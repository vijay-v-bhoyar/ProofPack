"""Derive inspection-family inputs from a complete corpus; never cleanup authority.

This is the inspection selection layer of privacy classification. Other families,
retained markers, context and unknown schemas remain explicit residual obligations.
The caller must obtain/revalidate the complete read set under its real admission.
"""
from copy import deepcopy
from dataclasses import dataclass
import re

from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.inventory import _private_payload_size
from proofpack.evidence.capture_lineage import CaptureFamily, CaptureDiscoveryHeld, discover as capture_discover
from proofpack.evidence.human_lineage import HumanHistory, HumanHistoryHeld, discover as human_discover
from proofpack.evidence.support_lineage import SupportFamily, SupportDiscoveryHeld, discover as support_discover
from proofpack.runtime.control import uuid


MAXIMUM = 2**63 - 1


class InspectionCorpusHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class InspectionCorpusLimits:
    max_records: int
    max_payload_bytes: int
    max_inspections: int
    max_work: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in
               (self.max_records, self.max_payload_bytes, self.max_inspections, self.max_work)):
            raise ValueError('explicit independent finite corpus limits required')


@dataclass(frozen=True)
class CorpusReference:
    key: Key
    revision: int
    kind: str
    sha256: str
    marker_resource_sha256: str | None = None


@dataclass(frozen=True)
class InspectionFamily:
    inspection_id: str
    requested: bool
    capture: CaptureFamily
    human: HumanHistory
    support: SupportFamily


@dataclass(frozen=True)
class InspectionCorpus:
    families: tuple[InspectionFamily, ...]
    residual: tuple[CorpusReference, ...]
    payload_bytes: int
    work: int


def derive(rows, *, deployment, requested_inspections, limits, now_ms,
           deadline_ns, tick, checkpoint):
    """Select and validate every supported inspection family, retaining all others.

    No result is an executable plan, even when residual is empty. In particular,
    requested flags select diagnostics; they do not establish ownership or roles.
    """
    if (type(rows) is not tuple or type(limits) is not InspectionCorpusLimits
            or type(deployment) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or type(requested_inspections) is not tuple or not requested_inspections
            or type(now_ms) is not int or not 0 <= now_ms <= MAXIMUM
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('complete private corpus, exact scope, bounds and checkpoints required')
    if len(requested_inspections) > limits.max_inspections:
        raise InspectionCorpusHeld('requested inspection bound exhausted')
    if any(type(v) is not str for v in requested_inspections):
        raise ValueError('ordered unique inspection UUIDs required')
    try:
        if tuple(sorted(set(requested_inspections))) != requested_inspections:
            raise ValueError()
        for ident in requested_inspections:
            uuid(ident)
    except (ValueError, TypeError):
        raise ValueError('ordered unique inspection UUIDs required') from None
    work = 0; last_tick = -1; payload_bytes = 0

    def check(cost=0):
        nonlocal work, last_tick
        work += cost
        if work > limits.max_work:
            raise InspectionCorpusHeld('corpus work bound exhausted')
        checkpoint()
        now = tick()
        if type(now) is not int or not last_tick <= now < deadline_ns or now < 0:
            raise InspectionCorpusHeld('original corpus deadline or monotonic clock invalid')
        last_tick = now
        checkpoint()

    try:
        check()
        if len(rows) > limits.max_records:
            raise InspectionCorpusHeld('corpus record bound exhausted')
        copied = {}; references = {}; roots = {}; observations = {}
        for original in rows:
            check(1)
            if (type(original) not in {Row, ErasureMarker} or type(original.key) is not Key
                    or original.key.table not in {'state', 'events'}
                    or type(original.key.resource) is not str or not 1 <= len(original.key.resource) <= 256
                    or type(original.revision) is not int or not 1 <= original.revision <= MAXIMUM
                    or original.key in copied):
                raise ValueError()
            row = deepcopy(original); copied[row.key] = row
            if type(row) is ErasureMarker:
                if (row.revision < 2 or any(type(v) is not str or re.fullmatch('[a-f0-9]{64}', v) is None
                        for v in (row.reference_sha256, row.resource_sha256))):
                    raise ValueError()
                references[row.key] = CorpusReference(row.key, row.revision, 'erased',
                    row.reference_sha256, row.resource_sha256)
                continue
            if type(row.data) is not dict:
                raise ValueError()
            digest = _payload_sha256(row.data)
            payload_bytes += _private_payload_size(row.data)
            if payload_bytes > limits.max_payload_bytes:
                raise InspectionCorpusHeld('corpus payload bound exhausted')
            references[row.key] = CorpusReference(row.key, row.revision, 'live', digest)
            prefix = row.key.resource.split('#', 1)[0]
            if prefix == 'inspection':
                ident = uuid(row.data['id'])
                if row.key != Key('state', 'inspection#' + ident) or ident in roots:
                    raise ValueError()
                roots[ident] = row
            elif prefix == 'observation':
                ident = uuid(row.data['id'])
                if row.key != Key('state', 'observation#' + ident) or ident in observations:
                    raise ValueError()
                observations[ident] = uuid(row.data['inspection_id'])
        if len(roots) > limits.max_inspections or not set(requested_inspections) <= roots.keys():
            raise InspectionCorpusHeld('inspection scope missing or bound exhausted')
        capture = {ident: [] for ident in roots}; human = {ident: [] for ident in roots}
        support = []; consumed = {r.key for r in roots.values()}
        for row in copied.values():
            check(1)
            if type(row) is not Row or row.key in consumed:
                continue
            prefix = row.key.resource.split('#', 1)[0]; data = row.data
            parent = None; destination = None
            if prefix in {'capture-permit', 'observation'}:
                if row.key.table != 'state': raise ValueError()
                parent = uuid(data['inspection_id']); destination = capture
            elif prefix in {'action', 'asset', 'object-intent'}:
                if row.key.table != 'state': raise ValueError()
                if prefix == 'asset' and (data.get('kind') == 'reference' or 'observation_id' not in data):
                    continue  # A separate policy must resolve this retained record.
                parent = observations.get(uuid(data['observation_id']))
                if parent is None: raise ValueError()
                destination = capture
            elif prefix == 'capture':
                if row.key.table != 'events': raise ValueError()
                parent = uuid(data['inspection_id']); destination = capture
            elif prefix == 'human-disposition':
                if row.key.table != 'state': raise ValueError()
                parent = uuid(data['inspection_id']); destination = human
            elif prefix in {'inspection-handoff', 'handoff-inbox'}:
                if row.key.table != 'state' or uuid(data['inspection_id']) not in roots:
                    raise ValueError()
                support.append(row); continue
            elif prefix == 'access' and row.key.table == 'events':
                kind = data.get('kind')
                if type(kind) is not str: raise ValueError()
                if kind.startswith('action-ack:'):
                    parent = uuid(data['details']['inspection_id']); destination = capture
                elif kind.startswith('inspection-disposition:'):
                    parent = uuid(data['details']['inspection_id']); destination = human
            if destination is not None:
                if parent not in roots: raise ValueError()
                destination[parent].append(row)
        families = []
        order = lambda row: (row.key.table, row.key.resource)
        support_rows = tuple(sorted(support, key=order))
        for ident, root in sorted(roots.items()):
            cr = tuple(sorted(capture[ident], key=order)); hr = tuple(sorted(human[ident], key=order))
            # Human validation independently revalidates the entire capture family.
            check(2 * (1 + len(cr)) + len(hr) + len(support_rows))
            options = dict(deployment=deployment, max_records=limits.max_records,
                           max_payload_bytes=limits.max_payload_bytes)
            cf = capture_discover(root, cr, **options); check()
            hf = human_discover(root, hr, capture_rows=cr, **options); check()
            sf = support_discover(root, support_rows, now_ms=now_ms, max_records=limits.max_records); check()
            expected_capture = {r.key for r in cr}
            expected_human = {r.key for r in hr}
            if ({r.key for r in cf.records} != expected_capture
                    or {r.key for r in hf.records} != expected_human):
                raise ValueError()
            consumed.update(expected_capture | expected_human | {r.key for r in sf.records})
            families.append(InspectionFamily(ident, ident in requested_inspections, cf, hf, sf))
        if not {r.key for r in support_rows} <= consumed:
            raise ValueError()
        result = InspectionCorpus(tuple(families), tuple(references[k] for k in sorted(
            references.keys() - consumed, key=lambda k: (k.table, k.resource))), payload_bytes, work)
        check()
        return result
    except InspectionCorpusHeld:
        raise
    except (CaptureDiscoveryHeld, HumanHistoryHeld, SupportDiscoveryHeld, KeyError,
            TypeError, ValueError, AttributeError, ArithmeticError, RecursionError):
        raise InspectionCorpusHeld('intact complete inspection-family inputs required') from None
