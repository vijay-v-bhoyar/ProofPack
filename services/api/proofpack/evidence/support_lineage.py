"""Validate one support family; never admit a full closure, read grant or removal."""
from copy import deepcopy
from dataclasses import dataclass

from proofpack.evidence.repository import Key, Row, ErasureMarker, StoreUnavailable
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.runtime.control import uuid, integer, sha
from proofpack.stations.handoffs import InspectionHandoffs, handoff_key, inbox_key
from proofpack.stations.service import inspection_key


class SupportDiscoveryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class SupportRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class SupportLink:
    source: Key
    target: Key
    kind: str


@dataclass(frozen=True)
class SupportFamily:
    inspection: SupportRecord
    records: tuple[SupportRecord, ...]
    links: tuple[SupportLink, ...]


MAIN_FIELDS = frozenset({'schema_version', 'id', 'inspection_id', 'request', 'request_sha256', 'status',
    'decision', 'decision_sha256', 'metadata_expires_at_ms', 'ttl_epoch_seconds'})
REQUEST_FIELDS = frozenset({'schema_version', 'id', 'inspection_id', 'station_id', 'station_epoch', 'station_name',
    'kit_reference', 'source_inspection_revision', 'post_request_inspection_revision', 'source_observation_id',
    'reason_code', 'stop_acknowledged', 'sender_user_id', 'sender_session_id', 'sender_cookie_resource', 'sender_role',
    'sender_access_version', 'recipient_user_id', 'recipient_access_version', 'previous_accepted_handoff_id',
    'runtime_epoch', 'runtime_instance_id', 'data_epoch', 'created_at_ms', 'expires_at_ms', 'metadata_expires_at_ms',
    'parent_metadata_expires_at_ms', 'configuration'})
INBOX_FIELDS = frozenset({'id', 'inspection_id', 'recipient_user_id', 'request_sha256', 'metadata_expires_at_ms', 'ttl_epoch_seconds'})


def _record(row):
    return SupportRecord(row.key, row.revision, _payload_sha256(row.data))


def discover(inspection, rows, *, now_ms, max_records):
    """Caller must supply the complete admitted support-family inventory/read set."""
    if (type(rows) is not tuple or type(max_records) is not int or not 1 <= max_records <= 2**63-1
            or type(now_ms) is not int or not 0 <= now_ms <= 2**63-1):
        raise ValueError('explicit bounded support input and reference time required')
    if len(rows) > max_records:
        raise SupportDiscoveryHeld('support family input bound exhausted')
    try:
        if (not isinstance(inspection, Row) or type(inspection.revision) is not int or not 1 <= inspection.revision <= 2**63-1
                or not isinstance(inspection.data, dict) or inspection.key != inspection_key(uuid(inspection.data['id']))):
            raise ValueError()
        root = deepcopy(inspection); copied = []; keys = set()
        uuid(root.data['station_id'])
        count = integer(root.data.get('handoff_count', 0)); latest = root.data.get('latest_handoff_id')
        if (count == 0) != (latest is None):
            raise ValueError()
        if latest is not None:uuid(latest)
        for row in rows:
            if isinstance(row, ErasureMarker):
                raise SupportDiscoveryHeld('support marker requires independent reconciliation')
            if (not isinstance(row, Row) or not isinstance(row.key, Key) or row.key.table != 'state'
                    or type(row.revision) is not int or not 1 <= row.revision <= 2**63-1
                    or type(row.data) is not dict or row.key in keys):
                raise ValueError()
            keys.add(row.key); copied.append(deepcopy(row))
        mains = {}; inboxes = {}; parents = {}; links = []
        for row in copied:
            parts = row.key.resource.split('#')
            if len(parts) != 3:
                raise ValueError()
            if parts[0] == 'inspection-handoff':
                owner, ident = uuid(parts[1]), uuid(parts[2])
                if set(row.data) != MAIN_FIELDS or type(row.data['request']) is not dict or set(row.data['request']) != REQUEST_FIELDS:
                    raise ValueError()
                InspectionHandoffs.retained(row, owner, ident, now=lambda: now_ms, include_expired=True)
                mains[(owner, ident)] = row; parents[row.key] = []
            elif parts[0] == 'handoff-inbox':
                recipient, ident = uuid(parts[1]), uuid(parts[2])
                if (set(row.data) != INBOX_FIELDS or row.data['id'] != ident or row.data['recipient_user_id'] != recipient
                        or row.revision != 1):
                    raise ValueError()
                uuid(row.data['inspection_id']); sha(row.data['request_sha256'])
                inboxes[(recipient, ident)] = row
            else:
                raise SupportDiscoveryHeld('explicit support family adapter required')
        used_inboxes = set()
        for (owner, ident), row in mains.items():
            request = row.data['request']; index = inboxes.get((request['recipient_user_id'], ident))
            if (index is None or index.key != inbox_key(request['recipient_user_id'], ident)
                    or index.data['inspection_id'] != owner or index.data['request_sha256'] != row.data['request_sha256']
                    or integer(index.data['metadata_expires_at_ms']) != integer(row.data['metadata_expires_at_ms'])
                    or integer(index.data['ttl_epoch_seconds']) != integer(row.data['ttl_epoch_seconds'])):
                raise ValueError()
            used_inboxes.add(index.key)
            previous = request['previous_accepted_handoff_id']
            if previous is not None:
                prior = mains.get((owner, previous))
                if (prior is None or prior.key == row.key or prior.data['status'] != 'accepted'
                        or integer(prior.data['decision']['at_ms']) > integer(request['created_at_ms'])):
                    raise ValueError()
                parents[row.key].append(prior.key); links.append(SupportLink(row.key, prior.key, 'previous_accepted'))
            if row.data['status'] == 'superseded':
                successor = mains.get((owner, row.data['decision']['successor_id']))
                if (successor is None or successor.key == row.key
                        or integer(successor.data['request']['created_at_ms']) < integer(request['created_at_ms'])
                        or integer(successor.data['request']['created_at_ms']) > integer(row.data['decision']['at_ms'])):
                    raise ValueError()
                parents[row.key].append(successor.key); links.append(SupportLink(row.key, successor.key, 'superseded_by'))
        if used_inboxes != {r.key for r in inboxes.values()}:
            raise ValueError()
        selected = [row for (owner, _), row in mains.items() if owner == root.data['id']]
        if (len(selected) != count or any(row.data['request']['station_id'] != root.data['station_id']
                or row.data['request']['kit_reference'] != root.data['kit_id'] for row in selected)):
            raise ValueError()
        if latest is not None:
            last = mains.get((root.data['id'], latest))
            if last is None or last.data['status'] == 'superseded':
                raise ValueError()
        # Iterative DFS avoids recursion depth becoming a bypass or crash on a long history.
        colors = {}
        for key in parents:
            stack = [(key, False)]
            while stack:
                item, leaving = stack.pop()
                if leaving:
                    colors[item] = 2
                elif colors.get(item) == 1:
                    raise ValueError()
                elif colors.get(item) != 2:
                    colors[item] = 1; stack.append((item, True))
                    stack.extend((parent, False) for parent in parents[item])
        owned = [row for row in copied if row.data['inspection_id'] == root.data['id']]
        owned_keys = {row.key for row in owned}
        return SupportFamily(_record(root), tuple(_record(row) for row in sorted(owned, key=lambda r: r.key.resource)),
            tuple(sorted((link for link in links if link.source in owned_keys), key=lambda link: (link.source.resource, link.kind, link.target.resource))))
    except SupportDiscoveryHeld:
        raise
    except (KeyError, TypeError, ValueError, ArithmeticError, AttributeError, StoreUnavailable) as exc:
        raise SupportDiscoveryHeld('intact complete support relationships required') from exc
