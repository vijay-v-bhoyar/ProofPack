"""Verify one explicitly declared journal scope; never authorize erasure or restore."""
from dataclasses import dataclass
import hashlib
import json

from proofpack.evidence.erasure_journal import (
    DynamoErasureJournal, JournalEntry, JournalHeld, JournalConflict,
    JournalIntent, HASH, MAXIMUM, _body,
)


@dataclass(frozen=True)
class JournalScopeLimits:
    max_records: int
    max_manifest_bytes: int
    max_sdk_calls: int
    max_work: int

    def __post_init__(self):
        if any(type(getattr(self, key)) is not int or not 1 <= getattr(self, key) <= MAXIMUM
               for key in self.__dataclass_fields__):
            raise ValueError('explicit finite declared-scope limits required')


@dataclass(frozen=True)
class JournalScopeCoverage:
    sha256: str
    record_count: int
    manifest_bytes: int
    work: int
    sdk_calls_reserved: int
    declared_scope_complete: bool = True
    historical: bool = True
    read_only: bool = True
    can_erase: bool = False
    restore_authorized: bool = False
    request_fulfilled: bool = False
    global_history_complete: bool = False
    independent_iam_verified: bool = False


class _ScopeRead:
    def __init__(self, journal, intents, limits, deadline_ns, tick, checkpoint):
        if (type(journal) is not DynamoErasureJournal or type(limits) is not JournalScopeLimits
                or type(intents) is not tuple or not intents
                or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
                or not callable(tick) or not callable(checkpoint)):
            raise ValueError('exact journal, nonempty immutable scope, limits and original clock/checkpoint required')
        self.journal, self.intents, self.limits = journal, intents, limits
        self.initial = journal._initial
        self.limit_values = tuple(getattr(limits, name) for name in limits.__dataclass_fields__)
        JournalScopeLimits(*self.limit_values)
        self.deadline, self.tick, self.checkpoint = deadline_ns, tick, checkpoint
        self.last, self.work = -1, 0
        self.check()
        count = len(intents)
        if (count > limits.max_records or 5 * count > limits.max_sdk_calls
                or 3 * count + 2 > limits.max_work or journal.limits.max_sdk_calls < 5):
            raise JournalHeld('complete declared-scope read cannot fit original allowances')

    def _same(self):
        values = tuple(getattr(self.limits, name) for name in self.limits.__dataclass_fields__)
        if (self.journal._initial is not self.initial or values != self.limit_values
                or any(type(v) is not int for v in values)):
            raise JournalHeld('original declared-scope configuration changed')
        DynamoErasureJournal._check(self.journal)

    def time(self):
        value = self.tick()
        if type(value) is not int or not 0 <= value < self.deadline or value < self.last:
            raise JournalHeld('original declared-scope deadline or clock invalid')
        self.last = value
        return value

    def check(self, cost=0):
        self._same()
        self.work += cost
        if self.work > self.limit_values[3]:
            raise JournalHeld('original declared-scope work exhausted')
        self.checkpoint()
        self._same()
        self.time()
        self.checkpoint()
        self._same()
        self.time()

    def digest(self, *, capture=False):
        self.check(1)
        header = ['metadata-erasure-scope/v1', self.initial[2], self.initial[3],
                  self.initial[5], len(self.intents)]
        digest = hashlib.sha256()
        size = 0

        def add(value):
            nonlocal size
            encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
            size += 8 + len(encoded)
            if size > self.limit_values[1]:
                raise JournalHeld('declared manifest byte bound exhausted')
            digest.update(len(encoded).to_bytes(8, 'big'))
            digest.update(encoded)

        add(header)
        previous, common = None, None
        captured = []
        for intent in self.intents:
            self.check(1)
            body = _body(intent)
            current = (body['reference_sha256'], body['classification_sha256'],
                       body['confirmation_sha256'], body['created_at_ms'])
            resource = body['resource_sha256']
            if (previous is not None and resource <= previous
                    or common is not None and current != common):
                raise ValueError('one original scope with strictly ordered unique resources required')
            previous, common = resource, current
            add(body)
            if capture:
                captured.append(JournalIntent(**{name: body[name] for name in JournalIntent.__dataclass_fields__}))
        self.check()
        return digest.hexdigest(), size, tuple(captured)


def journal_scope_sha256(journal, intents, *, limits, deadline_ns, tick, checkpoint):
    """Bind an explicit manifest without I/O; this is not a presence receipt."""
    context = _ScopeRead(journal, intents, limits, deadline_ns, tick, checkpoint)
    return context.digest()[0]


def read_journal_scope(journal, intents, *, expected_sha256, limits, deadline_ns, tick, checkpoint):
    if type(expected_sha256) is not str or HASH.fullmatch(expected_sha256) is None:
        raise ValueError('exact original declared manifest digest required')
    context = _ScopeRead(journal, intents, limits, deadline_ns, tick, checkpoint)
    digest, size, captured = context.digest(capture=True)
    if digest != expected_sha256:
        raise JournalConflict('declared manifest differs from original expected scope')
    for intent in captured:
        context.check(1)
        entry = DynamoErasureJournal.read(journal, reference_sha256=intent.reference_sha256,
                                         resource_sha256=intent.resource_sha256,
                                         deadline_ns=deadline_ns, tick=context.time, checkpoint=context.check)
        if (type(entry) is not JournalEntry or type(entry.intent) is not JournalIntent
                or entry.intent != intent or entry.sha256 != DynamoErasureJournal._encoded(journal, intent)
                or entry.can_erase is not False or entry.restore_authorized is not False
                or entry.request_fulfilled is not False):
            raise JournalHeld('every original declared intent must have intact durable readback')
    try:
        final, final_size, _ = context.digest()
    except ValueError as exc:
        raise JournalHeld('original declared manifest changed before delivery') from exc
    if final != digest or final_size != size:
        raise JournalHeld('original declared manifest changed before delivery')
    context.check()
    return JournalScopeCoverage(digest, len(intents), size, context.work, 5 * len(intents))


@dataclass(frozen=True)
class JournalScopeCommit(JournalScopeCoverage):
    """Durable declared intent recording, never primary erasure or approval."""
    read_only: bool = False


def append_journal_scope(journal, intents, *, expected_sha256, limits, deadline_ns, tick, checkpoint):
    """Record immutable intents, then verify every original member before success.

    Failures preserve a durable partial prefix; explicit identical attempts reconcile
    it without overwriting or renewing any intent's original approval bindings.
    """
    if type(expected_sha256) is not str or HASH.fullmatch(expected_sha256) is None:
        raise ValueError('exact original declared manifest digest required')
    context = _ScopeRead(journal, intents, limits, deadline_ns, tick, checkpoint)
    count = len(intents)
    if (12 * count > context.limit_values[2] or 5 * count + 2 > context.limit_values[3]
            or journal.limits.max_sdk_calls < 7):
        raise JournalHeld('complete declared-scope recording cannot fit original allowances')
    digest, size, captured = context.digest(capture=True)
    if digest != expected_sha256:
        raise JournalConflict('declared manifest differs from original expected scope')
    # Do not discover a known item-size violation after writing earlier members.
    for intent in captured:
        context.check(1)
        DynamoErasureJournal._item(journal, intent)
    for intent in captured:
        context.check(1)
        entry = DynamoErasureJournal.append(journal, intent, deadline_ns=deadline_ns,
                                           tick=context.time, checkpoint=context.check)
        if (type(entry) is not JournalEntry or type(entry.intent) is not JournalIntent
                or entry.intent != intent or entry.sha256 != DynamoErasureJournal._encoded(journal, intent)
                or any(value is not False for value in
                       (entry.can_erase, entry.restore_authorized, entry.request_fulfilled))):
            raise JournalHeld('original immutable journal append readback required')
    for intent in captured:
        context.check(1)
        entry = DynamoErasureJournal.read(journal, reference_sha256=intent.reference_sha256,
                                         resource_sha256=intent.resource_sha256,
                                         deadline_ns=deadline_ns, tick=context.time, checkpoint=context.check)
        if (type(entry) is not JournalEntry or type(entry.intent) is not JournalIntent
                or entry.intent != intent or entry.sha256 != DynamoErasureJournal._encoded(journal, intent)
                or any(value is not False for value in
                       (entry.can_erase, entry.restore_authorized, entry.request_fulfilled))):
            raise JournalHeld('every original declared intent must remain durably readable')
    try:
        final, final_size, _ = context.digest()
    except ValueError as exc:
        raise JournalHeld('original declared manifest changed before recording receipt') from exc
    if final != digest or final_size != size:
        raise JournalHeld('original declared manifest changed before recording receipt')
    context.check()
    return JournalScopeCommit(digest, count, size, context.work, 12 * count)
