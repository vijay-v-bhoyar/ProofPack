"""Select exact replay peers and typed business copies; never renew authority."""
from dataclasses import asdict, dataclass
import re

from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.dataset_corpus import DatasetCorpus, DatasetCorpusLimits, DatasetCorpusHeld, derive as dataset_derive
from proofpack.evidence.label_corpus import _inspection_references, _snapshot
from proofpack.evidence.inspection_corpus import CorpusReference
from proofpack.evidence.inventory import _private_payload_size
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, MissingResourceBindings, InvalidResourceBindings
from proofpack.evidence.replay_lineage import ReplayOutputs, ReplayRecord, ReplayHistoryHeld, discover as replay_discover
from proofpack.runtime.control import uuid, sha, integer


class ReplayCorpusHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class ReplayCorpusLimits:
    dataset: DatasetCorpusLimits
    max_replays: int
    max_transaction_events: int

    def __post_init__(self):
        if (type(self.dataset) is not DatasetCorpusLimits or any(type(v) is not int
                or not 1 <= v <= 2**63-1 for v in (self.max_replays, self.max_transaction_events))):
            raise ValueError('explicit nested corpus and finite replay/peer limits required')


@dataclass(frozen=True)
class ReplayDependency:
    history: ReplayOutputs
    codec: str
    validation: str
    inspection_ids: tuple[str, ...]
    requested_inspection_ids: tuple[str, ...]
    unresolved_source_keys: tuple[Key, ...]


@dataclass(frozen=True)
class ReplayObligation:
    replay: ReplayRecord
    reason: str


@dataclass(frozen=True)
class ReplayCorpus:
    datasets: DatasetCorpus
    families: tuple[ReplayDependency, ...]
    obligations: tuple[ReplayObligation, ...]
    residual: tuple[CorpusReference, ...]
    work: int
    max_family_records_used: int
    max_family_payload_bytes_used: int


def _binding_key(binding):
    return digest(asdict(binding))


def _codec(operation):
    if operation == 'observation_admitted': return 'capture-admission/v1'
    if operation == 'label-create' or operation.startswith('label-revise:'): return 'label-revision/v1'
    if operation.startswith('action-ack:'): return 'action-ack/v1'
    if operation.startswith('inspection-disposition:'): return 'human-disposition/v1'
    if operation in {'improvement-preview', 'improvement-confirm'} or operation.startswith('improvement-withdraw:'):
        return 'optional-permission-id/v1'
    if operation == 'dataset-create' or operation.startswith(('dataset-step:', 'dataset-cancel:', 'dataset-retire:')):
        return 'dataset-id/v1'
    if operation.startswith('dataset-declassify:'): return 'shared-group-id/v1'
    return None


def _result(root, peers, binding, copied, codec):
    # Envelope/direct-result structure and typed timestamps are checked first by
    # the existing replay validator. Full expected-value comparisons use JSON
    # canonicalization so True cannot compare equal to an integer revision.
    if codec == 'capture-admission/v1': return 'EXACT_BUSINESS_VALUES'
    access = [row for row in peers if row.key.resource.startswith('access#')]
    if len(access) != 1: raise ValueError()
    event = access[0]; operation = binding.operation; result = root.data['result']
    details = event.data.get('details'); validation = 'EXACT_BUSINESS_VALUES'
    if codec == 'action-ack/v1':
        expected = {name: uuid(details[name]) for name in ('inspection_id', 'action_id')}
    elif codec == 'human-disposition/v1':
        ident = uuid(details['inspection_id']); decision = uuid(details['decision_id'])
        record = copied[Key('state', 'human-disposition#'+ident+'#'+decision)]
        written = [r for r in binding.writes if r.key == Key('state', 'inspection#'+ident)]
        if len(written) != 1 or type(record) is not Row: raise ValueError()
        expected = {'id': decision, 'inspection_id': ident,
            'inspection_state_version': written[0].revision, 'decision': record.data}
    elif codec == 'label-revision/v1':
        expected = {'id': uuid(details['label_id']), 'revision': integer(details['revision'])}
    elif codec == 'optional-permission-id/v1':
        expected = {'id': uuid(details['preview_id'] if operation == 'improvement-preview' else details['permission_id'])}
    elif codec == 'dataset-id/v1':
        ident = uuid(details['dataset_id']) if operation == 'dataset-create' else uuid(operation.split(':', 1)[1])
        expected = {'id': ident}
        if operation.startswith('dataset-step:'):
            validation = 'EXACT_ID_WRITER_VARIANT_SHAPE'
            if 'attempt' in result:
                expected['attempt'] = uuid(result['attempt'])
                validation = 'EXACT_ID_TYPED_HISTORICAL_ATTEMPT'
    elif codec == 'shared-group-id/v1':
        expected = {'id': sha(operation.split(':', 1)[1])}
    else: raise ValueError()
    if canonical(result) != canonical(expected): raise ValueError()
    return validation


def derive(rows, *, deployment, requested_inspections, limits, now_ms,
           deadline_ns, tick, checkpoint):
    if type(limits) is not ReplayCorpusLimits or not callable(tick) or not callable(checkpoint):
        raise ValueError('explicit replay corpus limits and trusted checkpoints required')
    last_tick = -1

    def checked_tick():
        nonlocal last_tick
        now = tick()
        if (type(now) is not int or type(deadline_ns) is not int
                or not 0 <= now < deadline_ns or now < last_tick):
            raise ReplayCorpusHeld('original replay-corpus clock/deadline invalid')
        last_tick = now
        return now

    try:
        upstream = dataset_derive(rows, deployment=deployment, requested_inspections=requested_inspections,
            limits=limits.dataset, now_ms=now_ms, deadline_ns=deadline_ns,
            tick=checked_tick, checkpoint=checkpoint)
        work = upstream.work; peak_records = upstream.max_family_records_used
        peak_bytes = upstream.max_family_payload_bytes_used

        def check(cost=0):
            nonlocal work
            work += cost
            if work > limits.dataset.corpus.max_work:
                raise ReplayCorpusHeld('shared replay-corpus work bound exhausted')
            checkpoint(); checked_tick(); checkpoint()

        copied = _snapshot(rows, _inspection_references(upstream.permissions.labels.inspections), check)
        scopes = {}

        def scope(records, owners, unresolved=()):
            owners = frozenset(owners); unresolved = frozenset(unresolved)
            check(len(owners)+len(unresolved))
            for record in records:
                check(1)
                if record.key.table != 'events': continue
                previous = scopes.get(record.key, (set(), set()))
                scopes[record.key] = (previous[0] | set(owners), previous[1] | set(unresolved))

        for family in upstream.permissions.labels.inspections.families:
            scope(family.capture.records, (family.inspection_id,))
            scope(family.human.records, (family.inspection_id,))
        for family in upstream.permissions.labels.families:
            scope(family.labels.records, (family.inspection_id,))
        for family in upstream.permissions.families:
            scope(family.history.records, family.inspection_ids, family.unresolved_reference_sources)
        for family in upstream.families:
            scope(family.history.records, family.inspection_ids, (r.target for r in family.unresolved_intents))
        for group in upstream.groups:
            scope(group.history.history, group.copied_inspection_ids, (group.history.group.key,))
        roots = []; transactions = {}
        for row in copied.values():
            check(1)
            if type(row) is not Row: continue
            if row.key.table == 'state' and row.key.resource.startswith('idempotency#'):
                if re.fullmatch('idempotency#[a-f0-9]{64}', row.key.resource) is None: raise ValueError()
                roots.append(row)
                if len(roots) > limits.max_replays:
                    raise ReplayCorpusHeld('replay root bound exhausted')
            elif row.key.table == 'events' and 'resource_bindings' in row.data:
                binding = decode(row, deployment=deployment)
                check(len(binding.writes)+len(binding.checks))
                token = _binding_key(binding)
                if token not in transactions: transactions[token] = (binding, [])
                original, peers = transactions[token]
                if binding != original: raise ValueError()
                peers.append(row)
                if len(peers) > limits.max_transaction_events:
                    raise ReplayCorpusHeld('transaction event bound exhausted')
        families = []; obligations = []; consumed = set()
        for root in sorted(roots, key=lambda r: r.key.resource):
            check(1)
            reference = ReplayRecord(root.key, root.revision, _payload_sha256(root.data))
            if 'resource_bindings' not in root.data:
                obligations.append(ReplayObligation(reference, 'LEGACY_PROVENANCE_UNRESOLVED')); continue
            binding = decode(root, deployment=deployment)
            check(len(binding.writes)+len(binding.checks))
            codec = _codec(binding.operation)
            if codec is None:
                obligations.append(ReplayObligation(reference, 'BUSINESS_CODEC_UNSUPPORTED')); continue
            token = _binding_key(binding); indexed = transactions.get(token)
            if indexed is None:
                obligations.append(ReplayObligation(reference, 'TRANSACTION_PEERS_UNRESOLVED')); continue
            if indexed[0] != binding: raise ValueError()
            peers = tuple(sorted(indexed[1], key=lambda r: (r.key.table, r.key.resource)))
            if any(peer.key not in scopes for peer in peers):
                obligations.append(ReplayObligation(reference, 'PEER_POLICY_UNRESOLVED')); continue
            size = sum(_private_payload_size(row.data) for row in (root, *peers)); count = 1+len(peers)
            check(count)
            if count > limits.dataset.family_max_records or size > limits.dataset.family_max_payload_bytes:
                raise ReplayCorpusHeld('explicit expanded replay-family bound exhausted')
            peak_records = max(peak_records, count); peak_bytes = max(peak_bytes, size)
            parsed = replay_discover(root, peers, deployment=deployment,
                max_records=limits.dataset.family_max_records, max_payload_bytes=limits.dataset.family_max_payload_bytes)
            check()
            validation = _result(root, peers, binding, copied, codec)
            owners = set().union(*(scopes[p.key][0] for p in peers))
            unresolved = set().union(*(scopes[p.key][1] for p in peers))
            families.append(ReplayDependency(parsed, codec, validation, tuple(sorted(owners)),
                tuple(sorted(owners.intersection(requested_inspections))), tuple(sorted(
                    unresolved, key=lambda k: (k.table, k.resource)))))
            if unresolved: obligations.append(ReplayObligation(reference, 'SOURCE_SCOPE_UNRESOLVED'))
            else: consumed.add(root.key)
        residual = tuple(r for r in upstream.residual if r.key not in consumed)
        if consumed - {r.key for r in upstream.residual}: raise ValueError()
        result = ReplayCorpus(upstream, tuple(families), tuple(obligations), residual, work,
            peak_records, peak_bytes)
        check()
        return result
    except ReplayCorpusHeld:
        raise
    except (DatasetCorpusHeld, ReplayHistoryHeld, MissingResourceBindings, InvalidResourceBindings,
            KeyError, TypeError, ValueError, AttributeError, ArithmeticError, RecursionError):
        raise ReplayCorpusHeld('intact complete replay/peer/result corpus required') from None
