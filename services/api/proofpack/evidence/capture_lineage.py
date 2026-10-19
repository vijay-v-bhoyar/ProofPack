"""Parse a complete admitted capture family; never grant delivery or erasure."""
from copy import deepcopy
from dataclasses import dataclass, field
from decimal import Decimal
import json
import re
from pydantic import TypeAdapter

from proofpack.calibrations.dependencies import digest
from proofpack.capture.provenance import inspection_context, policy_provenance, POLICY_FIELDS, CONTEXT_FIELDS
from proofpack.capture.observations import FAILURES
from proofpack.evidence.repository import Key, Row, ErasureMarker, StoreUnavailable
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.evidence.originals import original_asset_id, validate_original_source, _metadata_media_record
from proofpack.planner.policy import ActionKind, TEMPLATES
from proofpack.recipes.models import Origin, Identifier
from proofpack.runtime.control import integer, uuid, sha
from proofpack.vision.correction import basis, verified_reference, geometry, target_indices
from proofpack.vision.worker_result import WorkerResult


class CaptureDiscoveryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class CaptureRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class CaptureLink:
    source: Key
    target: Key
    kind: str


@dataclass(frozen=True)
class MediaTarget:
    source: Key
    asset_id: str
    storage_binding_sha256: str
    object_key: str = field(repr=False)
    version_id: str | None = field(repr=False)
    status: str


@dataclass(frozen=True)
class CaptureFamily:
    inspection: CaptureRecord
    records: tuple[CaptureRecord, ...]
    links: tuple[CaptureLink, ...]
    media: tuple[MediaTarget, ...]
    dependencies: tuple[CaptureRecord, ...]
    payload_bytes: int


PERMIT = frozenset('id inspection_id station_id station_epoch runtime_instance_id runtime_epoch sequence nonce_sha256 status policy_provenance issued_tick_ns issued_at_ms expires_tick_ns observation_deadline_tick_ns'.split())
OBSERVATION = frozenset('id inspection_id permit_id sequence status station_id station_epoch runtime_epoch originating_session_id policy_provenance accepted_tick_ns permit_issued_tick_ns accepted_at_ms source_sha256 byte_length context_sha256 runtime_instance_id observation_deadline_tick_ns'.split())
RETAINED = frozenset(('retain_original_frame', 'original_capture_purpose_binding'))
COMPLETED = frozenset(('worker_id', 'result_json', 'asset_id', 'evidence_sha256', 'completed_at_ms'))
FAILED = frozenset(('failure_reason', 'failed_at_ms'))
ASSET = frozenset('storage_binding_sha256 id status read_denied sha256 input_sha256 context_sha256 object_key object_version byte_length content_type purpose_id expires_at_ms data_origin observation_id derivation'.split())
ORIGINAL = frozenset(('calibration_sha256', 'replay_profile_json'))
DELETION = frozenset(('deletion_job_id', 'denied_at_ms', 'live_versions_checked_at_ms'))
INTENT = frozenset('observation_id asset_id status key source_sha256 context_sha256 purpose_id user_id created_at_ms storage_binding_sha256'.split())
ACTION = frozenset('id kind observation_id scene_generation source_machine_version status message target_candidate_indices policy_state_version policy_provenance'.split())
ADMISSION = frozenset('kind inspection_id observation_id sequence source_sha256 at_ms resource_bindings'.split())
COMPLETE_EVENT = frozenset('kind inspection_id observation_id sequence asset_id input_sha256 crop_sha256 state action_id at_ms policy_state_version policy_provenance resource_bindings'.split())
FAIL_EVENT = frozenset('kind observation_id inspection_id status reason at_ms resource_bindings'.split())
ACK_EVENT = frozenset('kind actor_scope at_ms session_id details resource_bindings'.split())


def _n(value, *, positive=False):
    value = integer(value)
    if not int(positive) <= value <= 2**63-1:
        raise ValueError()
    return value


def _text(value, maximum, *, version=False):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ValueError()
    if version and (value == 'null' or not value.isascii() or any(ord(c) < 33 for c in value)):
        raise ValueError()
    return value


def _shape(data, required, optional=frozenset()):
    if type(data) is not dict or not required <= data.keys() or not data.keys() <= required | optional:
        raise ValueError()


def _policy(value, expected):
    _shape(value, frozenset(POLICY_FIELDS))
    if policy_provenance(value) != policy_provenance(expected):
        raise ValueError()


def _retention(data, *, original=False):
    selected = RETAINED & data.keys()
    if selected:
        if selected != RETAINED or data['retain_original_frame'] is not True:
            raise ValueError()
        sha(data['original_capture_purpose_binding'])
    if original and not selected:
        raise ValueError()
    return bool(selected)


def _json_number(value):
    if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
        return int(value)
    raise ValueError('canonical stored number required')


def _record(row):
    return CaptureRecord(row.key, row.revision, _payload_sha256(row.data))


def discover(inspection, rows, *, deployment, max_records, max_payload_bytes):
    """Caller proves complete inventory/read-set admission under its real barrier."""
    if (type(rows) is not tuple or any(type(v) is not int or not 1 <= v <= 2**63-1 for v in (max_records, max_payload_bytes))
            or type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None):
        raise ValueError('explicit bounded family input and deployment required')
    if len(rows) + 1 > max_records:
        raise CaptureDiscoveryHeld('capture family record bound exhausted')
    try:
        selected = {}; payload_bytes = 0
        for row in (inspection, *rows):
            if (isinstance(row, ErasureMarker) or not isinstance(row, Row) or not isinstance(row.key, Key)
                    or type(row.revision) is not int or not 1 <= row.revision <= 2**63-1 or row.key in selected
                    or row.key.table not in {'state', 'events'} or type(row.key.resource) is not str):
                raise ValueError()
            _payload_sha256(row.data)
            payload_bytes += len(json.dumps(row.data, sort_keys=True, separators=(',', ':'), allow_nan=False,
                default=_json_number).encode())
            if payload_bytes > max_payload_bytes:
                raise CaptureDiscoveryHeld('capture family payload bound exhausted')
            selected[row.key] = deepcopy(row)
        root = selected[inspection.key]; head = root.data
        ident = uuid(head['id']); station = uuid(head['station_id'])
        if (root.key != Key('state', 'inspection#' + ident) or head['state'] != 'CLOSED'
                or _n(head['deadline_tick_ns']) != 0 or head.get('pending_sequence') is not None):
            raise ValueError()
        created = _n(head['created_at_ms']); closed = _n(head['closed_at_ms'])
        if closed < created:
            raise ValueError()
        if 'schema_version' in head:raise ValueError()
        for name in ('runtime_instance_id','originating_session_id','originating_user_id'):uuid(head[name])
        for name in ('recipe_id','calibration_profile_id'):TypeAdapter(Identifier).validate_python(head[name], strict=True)
        for name in CONTEXT_FIELDS:
            if name.endswith(('_version','_epoch')):_n(head[name], positive=True)
        _n(head['recipe_revision'], positive=True); sha(head['artifact_sha256'])
        _policy(head['policy_provenance'], head['policy_provenance'])
        _n(head['station_epoch'], positive=True); _n(head['runtime_epoch'], positive=True)
        count = _n(head['latest_input_sequence']); _n(head['verified_sequence'])
        if head['verified_sequence'] > count:
            raise ValueError()
        groups = {name: {} for name in ('capture-permit', 'observation', 'action', 'asset', 'object-intent', 'capture', 'access')}
        for key, row in selected.items():
            if key == root.key:
                continue
            prefix, token = key.resource.split('#', 1); uuid(token)
            if prefix not in groups or key.table != ('events' if prefix in {'capture', 'access'} else 'state'):
                raise ValueError()
            if prefix not in {'capture', 'access'} and row.data.get('asset_id' if prefix == 'object-intent' else 'id') != token:
                raise ValueError()
            groups[prefix][token] = row
        permits = groups['capture-permit']; observations = groups['observation']; actions = groups['action']
        assets = groups['asset']; intents = groups['object-intent']; links = set(); targets = []
        dependencies = set(); events = {}; acks = {}
        for row in (*groups['capture'].values(), *groups['access'].values()):
            data = row.data; binding = decode(row, deployment=deployment)
            if binding.operation != data['kind']:
                raise ValueError()
            if row.key.resource.startswith('access#'):
                _shape(data, ACK_EVENT); details = data['details']
                _shape(details, frozenset(('inspection_id', 'action_id', 'observation_id')))
                aid = uuid(details['action_id']); uuid(details['observation_id']); uuid(data['session_id'])
                _text(data['actor_scope'], 512)
                if (details['inspection_id'] != ident or data['kind'] != 'action-ack:' + ident + ':' + aid or aid in acks):
                    raise ValueError()
                acks[aid] = row
            else:
                kind = data['kind']; oid = uuid(data['observation_id'])
                if data['inspection_id'] != ident or (oid, kind) in events:
                    raise ValueError()
                if kind == 'observation_admitted':
                    _shape(data, ADMISSION)
                elif kind == 'observation_completed':
                    _shape(data, COMPLETE_EVENT, frozenset(('original_asset_id', 'original_sha256', 'correction_basis_sha256', 'action_kind', 'target_candidate_indices')))
                elif kind == 'observation_failed':
                    _shape(data, FAIL_EVENT)
                else:
                    raise ValueError()
                events[oid, kind] = row
            _n(data['at_ms'])
            if 'sequence' in data:_n(data['sequence'], positive=True)
            if 'policy_state_version' in data:_n(data['policy_state_version'], positive=True)
            for reference in (*binding.writes, *binding.checks):
                if reference.key not in selected:
                    dependencies.add(CaptureRecord(reference.key, reference.revision, reference.sha256))
        if len(observations) != count or sorted(_n(o.data['sequence'], positive=True) for o in observations.values()) != list(range(1, count + 1)):
            raise ValueError()
        for row in permits.values():
            p = row.data; _shape(p, PERMIT, RETAINED | {'observation_id'})
            if (p['inspection_id'] != ident or p['station_id'] != station or p['station_epoch'] != head['station_epoch']
                    or p['runtime_instance_id'] != head['runtime_instance_id'] or p['runtime_epoch'] != head['runtime_epoch']
                    or p['status'] not in {'issued', 'expired', 'consumed'} or not 1 <= _n(p['sequence']) <= count + 1
                    or not created <= _n(p['issued_at_ms']) <= closed
                    or not _n(p['issued_tick_ns']) < _n(p['observation_deadline_tick_ns']) <= _n(p['expires_tick_ns'])):
                raise ValueError()
            for name in ('station_epoch','runtime_epoch'):_n(p[name], positive=True)
            _policy(p['policy_provenance'], head['policy_provenance']); sha(p['nonce_sha256']); _retention(p)
            if p['status'] == 'consumed':
                oid = uuid(p['observation_id'])
                if row.revision != 2 or oid not in observations or observations[oid].data['permit_id'] != p['id']:
                    raise ValueError()
            elif 'observation_id' in p or row.revision != (1 if p['status'] == 'issued' else 2):
                raise ValueError()
            links.add(CaptureLink(root.key, row.key, 'capture_permit'))
        retained_permits = sum(_retention(row.data) for row in permits.values())
        if not 0 <= _n(head.get('original_attempts_reserved', 0)) == retained_permits <= 3:
            raise ValueError()
        used_assets = set(); used_intents = set(); used_actions = set(); used_events = set(); completed = []

        def validate_binding(event, expected):
            binding = decode(event, deployment=deployment); owned = {}
            allowed_shared = {Key('state', 'station#' + station), Key('state', 'upload-quota#' + station), Key('state', 'station-quota#' + station)}
            for value in binding.writes:
                if value.key in allowed_shared:
                    continue
                if value.key not in selected or value.key not in expected:
                    raise ValueError()
                owned[value.key] = value
                current = selected[value.key]
                if current.revision < value.revision or (current.revision == value.revision and _payload_sha256(current.data) != value.sha256):
                    raise ValueError()
            if set(owned) != expected:
                raise ValueError()

        for observation in sorted(observations.values(), key=lambda value: _n(value.data['sequence'])):
            o = observation.data; oid = o['id']; status = o['status']; retained = _retention(o)
            if status not in {'completed', 'failed', 'discarded'}:
                raise CaptureDiscoveryHeld('capture worker must be drained')
            optional = (RETAINED | {'content_type'} if retained else frozenset())
            _shape(o, OBSERVATION | (COMPLETED if status == 'completed' else FAILED), optional | {'worker_id'} | ({'original_asset_id', 'original_evidence_sha256'} if retained and status == 'completed' else set()) | ({'correction_basis_sha256'} if status == 'completed' else set()))
            p = permits[uuid(o['permit_id'])].data; permit = permits[o['permit_id']]
            if (p['status'] != 'consumed' or p['observation_id'] != oid or o['inspection_id'] != ident
                    or any(o[name] != head[name] for name in ('station_id', 'station_epoch', 'runtime_epoch', 'runtime_instance_id', 'originating_session_id'))
                    or o['sequence'] != p['sequence'] or o['permit_issued_tick_ns'] != p['issued_tick_ns']
                    or o['observation_deadline_tick_ns'] != p['observation_deadline_tick_ns']
                    or not _n(p['issued_tick_ns']) <= _n(o['accepted_tick_ns']) < min(_n(p['expires_tick_ns']), _n(p['observation_deadline_tick_ns']))
                    or not _n(p['issued_at_ms']) <= _n(o['accepted_at_ms']) <= closed
                    or not 0 < _n(o['byte_length']) <= 2097152 or retained != _retention(p)
                    or (retained and (o['original_capture_purpose_binding'] != p['original_capture_purpose_binding'] or o['content_type'] not in {'image/jpeg', 'image/png'}))):
                raise ValueError()
            for name in ('station_epoch','runtime_epoch'):_n(o[name], positive=True)
            _n(o['permit_issued_tick_ns'])
            _policy(o['policy_provenance'], head['policy_provenance']); sha(o['source_sha256']); sha(o['context_sha256'])
            if digest(inspection_context(head, o['sequence'], o)) != o['context_sha256']:
                raise ValueError()
            admitted = events[oid, 'observation_admitted']; used_events.add(admitted.key)
            if (admitted.data['sequence'] != o['sequence'] or admitted.data['source_sha256'] != o['source_sha256']
                    or admitted.data['at_ms'] < o['accepted_at_ms']):
                raise ValueError()
            validate_binding(admitted, {root.key, observation.key, permit.key})
            links.update((CaptureLink(root.key, observation.key, 'observation'), CaptureLink(observation.key, permit.key, 'consumed_permit'), CaptureLink(observation.key, admitted.key, 'admission')))
            possible = {oid} | ({original_asset_id(oid)} if retained else set())
            current_intents = {i.data['asset_id']: i for i in intents.values() if i.data['observation_id'] == oid}
            expected_write = {observation.key}; terminal_kind = 'observation_completed' if status == 'completed' else 'observation_failed'
            terminal = events[oid, terminal_kind]; used_events.add(terminal.key); terminal_data = terminal.data
            terminal_time = _n(o['completed_at_ms' if status == 'completed' else 'failed_at_ms'])
            if (terminal_time < o['accepted_at_ms'] or terminal_data['at_ms'] < terminal_time
                    or admitted.data['at_ms'] > terminal_time
                    or (status != 'discarded' and terminal_data['at_ms'] > closed)):
                raise ValueError()
            if status == 'completed':
                completed.append(observation); uuid(o['worker_id'])
                if (observation.revision != 3 or terminal_time > closed or o['asset_id'] != oid
                        or terminal_data['asset_id'] != oid or terminal_data['sequence'] != o['sequence']
                        or terminal_data['input_sha256'] != o['source_sha256'] or terminal_data['crop_sha256'] != o['evidence_sha256']
                        or terminal_data['policy_state_version'] != head['policy_state_version']
                        or terminal_data['state'] not in {'OBSERVING', 'PASSED_CURRENT', 'ACTION_REQUIRED', 'REVIEW_REQUIRED', 'INVALIDATED'}):
                    raise ValueError()
                _policy(terminal_data['policy_provenance'], head['policy_provenance'])
                result = WorkerResult.model_validate_json(o['result_json'])
                if (result.evidence_jpeg_base64 is not None or result.evidence_sha256 is not None or result.source_sha256 != o['source_sha256']
                        or set(current_intents) != possible):
                    raise ValueError()
                crop = assets[oid]; _metadata_media_record(crop); verified_reference(crop.data, o)
                if crop.data['sha256'] != o['evidence_sha256']:
                    raise ValueError()
                if retained:
                    original = assets[original_asset_id(oid)]
                    if (o['original_asset_id'] != original.data['id'] or terminal_data['original_asset_id'] != original.data['id']
                            or terminal_data['original_sha256'] != o['original_evidence_sha256']):
                        raise ValueError()
                    validate_original_source(original, observation, crop, metadata_only=True)
                elif {'original_asset_id', 'original_sha256'} & terminal_data.keys():
                    raise ValueError()
                expected_write.add(root.key)
                action_id = terminal_data['action_id']
                if action_id is not None:
                    action = actions[uuid(action_id)]; a = action.data
                    _shape(a, ACTION, {'correction_basis_sha256'}); kind = ActionKind(a['kind'])
                    if (a['observation_id'] != oid or a['scene_generation'] != result.scene_generation
                            or a['policy_state_version'] != head['policy_state_version'] or a['message'] != TEMPLATES[kind]
                            or a['status'] not in ({'review'} if kind == ActionKind.REVIEW else {'pending', 'acknowledged'})
                            or a['target_candidate_indices'] != target_indices(geometry(result), kind.value)):
                        raise ValueError()
                    if (terminal_data['state'] != ('REVIEW_REQUIRED' if kind == ActionKind.REVIEW else 'ACTION_REQUIRED')
                            or (all(f.value == 'SATISFIED' for f in result.findings) and result.quality_ok and result.unknown_regions == 0)):
                        raise ValueError()
                    _n(a['scene_generation'], positive=True); _n(a['policy_state_version'], positive=True)
                    _n(a['source_machine_version'], positive=True); _policy(a['policy_provenance'], head['policy_provenance'])
                    if type(a['target_candidate_indices']) is not list or any(type(i) is not int for i in a['target_candidate_indices']):
                        raise ValueError()
                    if a.get('correction_basis_sha256') != o.get('correction_basis_sha256'):
                        raise ValueError()
                    used_actions.add(action.key); expected_write.add(action.key); links.add(CaptureLink(observation.key, action.key, 'issued_action'))
                    if a['status'] == 'acknowledged':
                        ack = acks[a['id']]
                        if (action.revision != 2 or ack.data['details']['observation_id'] != oid
                                or ack.data['session_id'] != head['originating_session_id']):
                            raise ValueError()
                        validate_binding(ack, {root.key, action.key}); used_events.add(ack.key)
                        links.add(CaptureLink(action.key, ack.key, 'acknowledgment'))
                    elif action.revision != 1 or a['id'] in acks:
                        raise ValueError()
                elif terminal_data['state'] in {'ACTION_REQUIRED', 'REVIEW_REQUIRED'}:
                    raise ValueError()
                _, correction = basis(o['result_json'], o['evidence_sha256'])
                if terminal_data.get('correction_basis_sha256') != correction:
                    raise ValueError()
                if correction is not None and action_id is not None:
                    if (terminal_data.get('action_kind') != actions[action_id].data['kind']
                            or terminal_data.get('target_candidate_indices') != actions[action_id].data['target_candidate_indices']):
                        raise ValueError()
                elif {'action_kind', 'target_candidate_indices'} & terminal_data.keys():
                    raise ValueError()
            else:
                if (observation.revision != (3 if 'worker_id' in o else 2) or terminal_data['status'] != status
                        or terminal_data['reason'] != o['failure_reason'] or o['failure_reason'] not in FAILURES
                        or any(asset.data['observation_id'] == oid for asset in assets.values())
                        or not set(current_intents) <= possible):
                    raise ValueError()
                if 'worker_id' in o:uuid(o['worker_id'])
                if status == 'failed':expected_write.add(root.key)
            for aid, intent in current_intents.items():
                i = intent.data; original = aid != oid
                _shape(i, INTENT | ({'derivation'} if original else {'crop_sha256'}), {'version_id'})
                if (aid not in possible or i['source_sha256'] != o['source_sha256'] or i['context_sha256'] != o['context_sha256']
                        or i['user_id'] != head['originating_user_id'] or _n(i['created_at_ms']) < o['accepted_at_ms']
                        or i['key'] != 'deployments/' + deployment + '/frames/' + aid
                        or i['status'] not in ({'linked'} if status == 'completed' else {'reserved', 'uploaded'})
                        or intent.revision != {'reserved': 1, 'uploaded': 2, 'linked': 3}[i['status']]
                        or (original and i['derivation'] != 'original_transmitted_frame')):
                    raise ValueError()
                sha(i['storage_binding_sha256']); uuid(i['purpose_id'])
                if Key('state','purpose#'+i['purpose_id']) not in {r.key for r in decode(admitted,deployment=deployment).checks}:
                    raise ValueError()
                if not original:sha(i['crop_sha256'])
                if i['status'] == 'reserved':
                    if 'version_id' in i:raise ValueError()
                else:_text(i['version_id'], 1024, version=True)
                targets.append(MediaTarget(intent.key, aid, i['storage_binding_sha256'], i['key'], i.get('version_id'), i['status']))
                used_intents.add(intent.key); links.add(CaptureLink(observation.key, intent.key, 'object_intent'))
                if status == 'completed':
                    asset = assets[aid]; a = asset.data
                    _shape(a, ASSET | (ORIGINAL if original else set()), DELETION | (set() if original else {'correction_basis_sha256'}))
                    _metadata_media_record(asset)
                    if (a['observation_id'] != oid or a['input_sha256'] != o['source_sha256'] or a['context_sha256'] != o['context_sha256']
                            or a['storage_binding_sha256'] != i['storage_binding_sha256'] or a['object_key'] != i['key']
                            or a['object_version'] != i['version_id'] or a['purpose_id'] != i['purpose_id']
                            or a['sha256'] != (i['source_sha256'] if original else i['crop_sha256'])
                            or a['derivation'] != ('original_transmitted_frame' if original else 'rectified_roi_jpeg')
                            or a['content_type'] not in ({'image/jpeg', 'image/png'} if original else {'image/jpeg'})
                            or not 0 < _n(a['byte_length']) <= 2097152
                            or not o['accepted_at_ms'] < _n(a['expires_at_ms']) <= o['accepted_at_ms'] + 7 * 86400000):
                        raise ValueError()
                    Origin(a['data_origin']); sha(a['sha256'])
                    targets.append(MediaTarget(asset.key, aid, a['storage_binding_sha256'], a['object_key'], a['object_version'], a['status']))
                    used_assets.add(asset.key); expected_write.update((asset.key, intent.key))
                    links.add(CaptureLink(intent.key, asset.key, 'published_asset'))
            if len({(i.data['purpose_id'], i.data['storage_binding_sha256']) for i in current_intents.values()}) > 1:
                raise ValueError()
            validate_binding(terminal, expected_write); links.add(CaptureLink(observation.key, terminal.key, 'terminal'))
        if (used_assets != {r.key for r in assets.values()} or used_intents != {r.key for r in intents.values()}
                or used_actions != {r.key for r in actions.values()}
                or used_events != {r.key for r in (*groups['capture'].values(), *groups['access'].values())}
                or _n(head['corrections']) != sum(a.data['kind'] != 'REVIEW' for a in actions.values())
                or not 0 <= _n(head['corrections']) <= 2):
            raise ValueError()
        originals = [o.data['original_asset_id'] for o in completed if o.data.get('retain_original_frame') is True]
        if type(head.get('original_asset_ids', [])) is not list or head.get('original_asset_ids', []) != originals:
            raise ValueError()
        if (head.get('latest_observation_id') != (completed[-1].data['id'] if completed else None)
                or _n(head['verified_sequence']) != max((o.data['sequence'] for o in completed if events[o.data['id'], 'observation_completed'].data['state'] != 'INVALIDATED'), default=0)):
            raise ValueError()
        for field_name, group in (('pending_observation_id', observations), ('pending_permit_id', permits), ('current_action_id', actions)):
            pointer = head.get(field_name)
            if pointer is not None and uuid(pointer) not in group:
                raise ValueError()
        if head.get('current_action_id') is not None:
            current_action = actions[head['current_action_id']].data
            if current_action['observation_id'] != head.get('latest_observation_id') or current_action['status'] == 'acknowledged':
                raise ValueError()
        return CaptureFamily(_record(root), tuple(_record(r) for k, r in sorted(selected.items(), key=lambda item: (item[0].table, item[0].resource)) if k != root.key),
            tuple(sorted(links, key=lambda link: (link.source.table, link.source.resource, link.target.table, link.target.resource, link.kind))),
            tuple(sorted(targets, key=lambda target: (target.source.table, target.source.resource))),
            tuple(sorted(dependencies, key=lambda value: (value.key.table, value.key.resource, value.revision, value.sha256))), payload_bytes)
    except CaptureDiscoveryHeld:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, StoreUnavailable) as exc:
        raise CaptureDiscoveryHeld('intact complete supported capture family required') from exc
