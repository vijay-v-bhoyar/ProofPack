"""Validate provided human-decision history; never certify truth or admit erasure."""
from copy import deepcopy
from dataclasses import dataclass
from bisect import bisect_right
import re

from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.capture_lineage import (
    CaptureFamily, CaptureRecord, CaptureLink, CaptureDiscoveryHeld,
    discover as capture_discover, _n, _record, _shape,
)
from proofpack.evidence.repository import Row, Key, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.runtime.control import uuid, sha
from proofpack.stations.service import DISPOSITIONS
from proofpack.verifier.core import State


class HumanHistoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class HumanHistory:
    capture: CaptureFamily
    records: tuple[CaptureRecord, ...]
    links: tuple[CaptureLink, ...]
    dependencies: tuple[CaptureRecord, ...]
    payload_bytes: int


RECORD_FIELDS = frozenset('id inspection_id station_id station_epoch source_inspection_revision source_state source_observation_id previous_id disposition reason human_check_confirmed actor_user_id actor_session_id at_ms machine_approval independent_truth_verified sha256'.split())
EVENT_FIELDS = frozenset('kind actor_scope at_ms session_id details resource_bindings'.split())
DETAIL_FIELDS = frozenset(('inspection_id', 'decision_id', 'disposition', 'sha256'))


def discover(inspection, rows, *, capture_rows, deployment, max_records, max_payload_bytes):
    """The caller must admit the complete inventory/read set under its real barrier."""
    if (type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}',deployment) is None
            or type(rows) is not tuple or type(capture_rows) is not tuple
            or any(type(v) is not int or not 1 <= v <= 2**63-1 for v in (max_records, max_payload_bytes))):
        raise ValueError('explicit independent bounded history and capture tuples required')
    if len(rows) + len(capture_rows) + 1 > max_records:
        raise HumanHistoryHeld('human-history record bound exhausted')
    try:
        copies = {}; payload_bytes = 0
        for row in (inspection, *capture_rows, *rows):
            if (isinstance(row, ErasureMarker) or not isinstance(row, Row) or not isinstance(row.key, Key)
                    or type(row.data) is not dict or type(row.revision) is not int
                    or not 1 <= row.revision <= 2**63-1 or row.key in copies):
                raise ValueError()
            _payload_sha256(row.data)
            payload_bytes += len(canonical(row.data).encode())
            if payload_bytes > max_payload_bytes:
                raise HumanHistoryHeld('human-history payload bound exhausted')
            copies[row.key] = deepcopy(row)
        root = copies[inspection.key]; head = root.data; ident = uuid(head['id']); station = uuid(head['station_id'])
        capture = capture_discover(root, tuple(copies[r.key] for r in capture_rows), deployment=deployment,
            max_records=max_records, max_payload_bytes=max_payload_bytes)
        if head.get('disposition') not in DISPOSITIONS | {None}:
            raise ValueError()
        capture_keys = {r.key for r in capture.records}
        transitions = set(); publications = []
        for source in capture_rows:
            if source.key.table != 'events':continue
            source = copies[source.key]
            binding = decode(source, deployment=deployment)
            root_writes = [w for w in binding.writes if w.key == root.key]
            for value in root_writes:
                if value.revision in transitions:raise ValueError()
                transitions.add(value.revision)
            if source.data.get('kind') == 'observation_completed':
                if len(root_writes) != 1:raise ValueError()
                publications.append((root_writes[0].revision, source.data['observation_id']))
        publications.sort(); publication_versions = [version for version, _ in publications]
        sequences = [copies[Key('state','observation#'+oid)].data['sequence'] for _, oid in publications]
        if sequences != sorted(set(sequences)):raise ValueError()
        records = {}; events = {}; links = set(); dependencies = set()
        for original in rows:
            row = copies[original.key]; data = row.data
            if row.key.table == 'state':
                _shape(data, RECORD_FIELDS)
                rid = uuid(data['id'])
                if (row.key != Key('state', 'human-disposition#' + ident + '#' + rid) or row.revision != 1
                        or rid in records or data['inspection_id'] != ident or data['station_id'] != station
                        or _n(data['station_epoch'], positive=True) != _n(head['station_epoch'], positive=True)
                        or not _n(data['source_inspection_revision'], positive=True) + 1 < root.revision
                        or State(data['source_state']) == State.CLOSED or data['disposition'] not in DISPOSITIONS
                        or data['machine_approval'] is not False or data['independent_truth_verified'] is not False
                        or type(data['human_check_confirmed']) is not bool
                        or (data['disposition'] == 'human_accepted' and data['human_check_confirmed'] is not True)
                        or data['actor_user_id'] != head['originating_user_id'] or data['actor_session_id'] != head['originating_session_id']
                        or not _n(head['created_at_ms']) <= _n(data['at_ms']) <= _n(head['closed_at_ms'])):
                    raise ValueError()
                if (type(data['reason']) is not str or not 1 <= len(data['reason']) <= 120
                        or not data['reason'].strip() or any(ord(c) < 32 for c in data['reason'])):
                    raise ValueError()
                if sha(data['sha256']) != digest({k: v for k, v in data.items() if k != 'sha256'}):
                    raise ValueError()
                uuid(data['actor_user_id']); uuid(data['actor_session_id'])
                if data['previous_id'] is not None:uuid(data['previous_id'])
                index = bisect_right(publication_versions, data['source_inspection_revision']) - 1
                expected_source = publications[index][1] if index >= 0 else None
                source = data['source_observation_id']
                if source != expected_source:raise ValueError()
                if source is not None:
                    source_key = Key('state', 'observation#' + uuid(source))
                    observed = copies.get(source_key)
                    if (observed is None or source_key not in capture_keys
                            or observed.data.get('status') != 'completed' or observed.data['inspection_id'] != ident
                            or _n(observed.data['completed_at_ms']) > data['at_ms']):
                        raise ValueError()
                    links.add(CaptureLink(row.key, source_key, 'historical_decision_source'))
                records[rid] = row
                links.add(CaptureLink(root.key, row.key, 'human_disposition'))
            elif row.key.table == 'events':
                _shape(data, EVENT_FIELDS); prefix, token = row.key.resource.split('#', 1); uuid(token)
                details = data['details']; _shape(details, DETAIL_FIELDS); rid = uuid(details['decision_id'])
                if (prefix != 'access' or row.revision != 1 or rid in events or details['inspection_id'] != ident
                        or data['kind'] != 'inspection-disposition:' + ident):
                    raise ValueError()
                sha(data['actor_scope']); uuid(data['session_id']); _n(data['at_ms'])
                events[rid] = row
            else:
                raise ValueError()
        latest = head.get('latest_disposition_id')
        if latest is None:
            if records or events:
                raise ValueError()
        else:
            uuid(latest)
            if not records or set(records) != set(events):
                raise ValueError()
        owned_keys = {root.key} | {r.key for r in records.values()}
        seen = set(); cursor = latest; newer = None
        while cursor is not None:
            if cursor in seen or cursor not in records:
                raise ValueError()
            seen.add(cursor); row = records[cursor]; data = row.data
            if newer is not None and (data['source_inspection_revision'] >= newer['source_inspection_revision'] or data['at_ms'] > newer['at_ms']):
                raise ValueError()
            previous = data['previous_id']
            if previous is not None:
                if previous not in records:
                    raise ValueError()
                links.add(CaptureLink(row.key, records[previous].key, 'previous_human_disposition'))
            event = events[cursor]; detail = event.data['details']; binding = decode(event, deployment=deployment)
            if (binding.operation != event.data['kind'] or detail['disposition'] != data['disposition']
                    or detail['sha256'] != data['sha256'] or event.data['session_id'] != data['actor_session_id']
                    or not data['at_ms'] <= event.data['at_ms'] <= head['closed_at_ms']):
                raise ValueError()
            written = {value.key: value for value in binding.writes}
            shared = Key('state', 'station-quota#' + station)
            if set(written) - {shared} != {root.key, row.key}:
                raise ValueError()
            root_write = written[root.key]; record_write = written[row.key]
            if (root_write.previous_revision != data['source_inspection_revision']
                    or root_write.revision != data['source_inspection_revision'] + 1
                    or record_write.previous_revision is not None or record_write.revision != 1
                    or record_write.sha256 != _payload_sha256(data) or root_write.revision >= root.revision
                    or root_write.revision in transitions):
                raise ValueError()
            transitions.add(root_write.revision)
            checked = {value.key: value for value in binding.checks}
            if (root.key not in checked or checked[root.key].revision != data['source_inspection_revision']
                    or Key('state', 'user#' + data['actor_user_id']) not in checked):
                raise ValueError()
            if previous is not None:
                prior = records[previous]; reference = checked.get(prior.key)
                if reference is None or reference.revision != 1 or reference.sha256 != _payload_sha256(prior.data):
                    raise ValueError()
            for reference in (*binding.writes, *binding.checks):
                if reference.key not in owned_keys:
                    dependencies.add(CaptureRecord(reference.key, reference.revision, reference.sha256))
            links.add(CaptureLink(row.key, event.key, 'human_disposition_audit'))
            newer = data; cursor = previous
        if seen != set(records):
            raise ValueError()
        return HumanHistory(capture,
            tuple(_record(copies[r.key]) for r in sorted(rows, key=lambda r: (r.key.table, r.key.resource))),
            tuple(sorted(links, key=lambda v: (v.source.table, v.source.resource, v.target.table, v.target.resource, v.kind))),
            tuple(sorted(dependencies, key=lambda v: (v.key.table, v.key.resource, v.revision, v.sha256))), payload_bytes)
    except HumanHistoryHeld:
        raise
    except (CaptureDiscoveryHeld, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise HumanHistoryHeld('intact complete supported human history required') from exc
