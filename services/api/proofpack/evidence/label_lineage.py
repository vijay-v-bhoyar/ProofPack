"""Validate provided historical labels; never grant reuse, truth or erasure."""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re

from proofpack.calibrations.dependencies import canonical, digest
from proofpack.capture.provenance import inspection_context
from proofpack.evidence.capture_lineage import (
    CaptureFamily, CaptureRecord, CaptureLink, CaptureDiscoveryHeld,
    discover as capture_discover, _n, _shape, _record,
)
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.evidence.originals import original_asset_id
from proofpack.recipes.models import Recipe
from proofpack.recipes.service import revision_key as recipe_key
from proofpack.review.labels import ReviewTuple, LabelRequest, head_key, label_revision_key
from proofpack.runtime.control import DATA, uuid, sha
from proofpack.vision.worker_result import WorkerResult


class LabelHistoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class LabelFamily:
    capture: CaptureFamily
    recipe: CaptureRecord
    purposes: tuple[CaptureRecord, ...]
    records: tuple[CaptureRecord, ...]
    links: tuple[CaptureLink, ...]
    dependencies: tuple[CaptureRecord, ...]
    payload_bytes: int


HEAD = frozenset(('id', 'latest_revision', 'sha256'))
REVISION = frozenset('id revision tuple source_context source_context_sha256 outcome ground_truth_counts method duration_ms note reviewer_id independence_declared independence_verified physical_truth_verified conflict_codes optional_improvement created_at_ms previous_sha256 data_epoch_before sha256'.split())
CONTEXT = frozenset('tuple inspection_id recipe_id recipe_revision recipe_sha256 data_origin artifact_sha256 runtime_instance_id inspection_bindings kit_group session_group operator_group sources observations expected_classes'.split())
SOURCE = frozenset('observation_id observation_version asset_id asset_version sha256 purpose_id purpose_version expires_at_ms'.split())
ORIGINAL_SOURCE = frozenset(('derivation', 'input_sha256', 'context_sha256', 'calibration_sha256'))
EVENT = frozenset('kind actor_scope at_ms session_id details resource_bindings'.split())
DETAIL = frozenset(('label_id', 'revision', 'source_context_sha256'))


def discover(inspection, rows, *, capture_rows, recipe, purpose_rows, deployment, max_records, max_payload_bytes):
    """Caller admits the complete inventory/read set; this is a pure family parser."""
    if (type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}',deployment) is None
            or type(rows) is not tuple or type(capture_rows) is not tuple or type(purpose_rows) is not tuple
            or any(type(v) is not int or not 1 <= v <= 2**63-1 for v in (max_records, max_payload_bytes))):
        raise ValueError('explicit independently bounded label/capture/purpose tuples required')
    if 2 + len(rows) + len(capture_rows) + len(purpose_rows) > max_records:
        raise LabelHistoryHeld('label-history record bound exhausted')
    try:
        copies = {}; payload_bytes = 0
        for row in (inspection, recipe, *capture_rows, *purpose_rows, *rows):
            if (isinstance(row, ErasureMarker) or not isinstance(row, Row) or not isinstance(row.key, Key)
                    or type(row.data) is not dict or type(row.revision) is not int
                    or not 1 <= row.revision <= 2**63-1 or row.key in copies):
                raise ValueError()
            _payload_sha256(row.data); payload_bytes += len(canonical(row.data).encode())
            if payload_bytes > max_payload_bytes:
                raise LabelHistoryHeld('label-history payload bound exhausted')
            copies[row.key] = deepcopy(row)
        root = copies[inspection.key]; head = root.data; source_recipe = copies[recipe.key]
        capture = capture_discover(root, tuple(copies[r.key] for r in capture_rows), deployment=deployment,
            max_records=max_records, max_payload_bytes=max_payload_bytes)
        _shape(source_recipe.data, frozenset(('recipe_json', 'sha256')))
        if (source_recipe.key != recipe_key(head['recipe_id'], _n(head['recipe_revision'], positive=True))
                or source_recipe.revision != 1 or type(source_recipe.data['recipe_json']) is not str
                or not 1 <= len(source_recipe.data['recipe_json'].encode()) <= 131072
                or sha(source_recipe.data['sha256']) != hashlib.sha256(source_recipe.data['recipe_json'].encode()).hexdigest()):
            raise ValueError()
        definition = Recipe.model_validate_json(source_recipe.data['recipe_json'])
        if definition.recipe_id != head['recipe_id'] or definition.revision != head['recipe_revision'] or definition.calibration_profile_id != head['calibration_profile_id']:
            raise ValueError()
        recipe_refs=[r for r in capture.dependencies if r.key==source_recipe.key]
        if not recipe_refs or any(r.revision!=1 or r.sha256!=_payload_sha256(source_recipe.data) for r in recipe_refs):raise ValueError()
        purposes = {}
        for original in purpose_rows:
            row = copies[original.key]; prefix, token = row.key.resource.split('#', 1); uuid(token)
            if (row.key.table != 'state' or prefix != 'purpose' or token in purposes
                    or type(row.data['withdrawn']) is not bool or type(row.data['allowed_uses']) is not list
                    or 'operation' not in row.data['allowed_uses']):
                raise ValueError()
            _n(row.data['expires_at_ms'], positive=True); purposes[token] = row
            for reference in capture.dependencies:
                if reference.key==row.key and (reference.revision>row.revision or (reference.revision==row.revision and reference.sha256!=_payload_sha256(row.data))):raise ValueError()
        heads = {}; revisions = {}; events = {}; links = set(); dependencies = set(); used_purposes = set()
        publications = {}
        for original in capture_rows:
            row = copies[original.key]
            if row.key.table == 'events' and row.data.get('kind') == 'observation_completed':
                values = [w for w in decode(row, deployment=deployment).writes if w.key == root.key]
                if len(values) != 1:raise ValueError()
                publications[row.data['observation_id']] = values[0].revision
        for original in rows:
            row = copies[original.key]; data = row.data
            if row.key.table == 'state' and row.key.resource.startswith('label#'):
                _shape(data, HEAD); ident = uuid(data['id']); number = _n(data['latest_revision'], positive=True)
                if row.key != head_key(ident) or row.revision != number or ident in heads:
                    raise ValueError()
                sha(data['sha256']); heads[ident] = row
            elif row.key.table == 'state' and row.key.resource.startswith('label-revision#'):
                _shape(data, REVISION); ident = uuid(data['id']); number = _n(data['revision'], positive=True)
                if row.key != label_revision_key(ident, number) or row.revision != 1 or (ident, number) in revisions:
                    raise ValueError()
                if sha(data['sha256']) != digest({k: v for k, v in data.items() if k != 'sha256'}):
                    raise ValueError()
                revisions[ident, number] = row
            elif row.key.table == 'events':
                _shape(data, EVENT); prefix, token = row.key.resource.split('#', 1); uuid(token)
                _shape(data['details'], DETAIL); ident = uuid(data['details']['label_id']); number = _n(data['details']['revision'], positive=True)
                if (prefix != 'access' or row.revision != 1 or (ident, number) in events
                        or data['kind'] != ('label-create' if number == 1 else 'label-revise:' + ident)):
                    raise ValueError()
                sha(data['actor_scope']); uuid(data['session_id']); _n(data['at_ms']); events[ident, number] = row
            else:
                raise ValueError()
        if set(revisions) != set(events) or {ident for ident, _ in revisions} != set(heads):
            raise ValueError()
        by_head = {ident: [] for ident in heads}
        for (ident, number), row in revisions.items():by_head[ident].append(number)
        all_owned = {r.key for r in (*heads.values(), *revisions.values())}; epochs = set()

        def reference(checked, row, version):
            version = _n(version, positive=True); ref = checked.get(row.key)
            if ref is None or ref.revision != version or row.revision < version:
                raise ValueError()
            if row.revision == version and ref.sha256 != _payload_sha256(row.data):
                raise ValueError()
            return ref

        for ident, label in heads.items():
            total = _n(label.data['latest_revision'], positive=True)
            if len(by_head[ident]) != total or sorted(by_head[ident]) != list(range(1, total + 1)):
                raise ValueError()
            previous = None; fixed_tuple = None
            for number in range(1, total + 1):
                row = revisions[ident, number]; data = row.data; event = events[ident, number]; binding = decode(event, deployment=deployment)
                checked = {v.key: v for v in binding.checks}; written = {v.key: v for v in binding.writes}
                if (binding.operation != event.data['kind'] or event.data['details']['source_context_sha256'] != data['source_context_sha256']
                        or data['independence_verified'] is not False or data['physical_truth_verified'] is not False
                        or data['optional_improvement'] is not False):
                    raise ValueError()
                _shape(data['tuple'], frozenset(ReviewTuple.model_fields))
                tuple_ = ReviewTuple.model_validate_json(canonical(data['tuple']))
                if fixed_tuple is None:fixed_tuple = data['tuple']
                if data['tuple'] != fixed_tuple or data['previous_sha256'] != (None if previous is None else previous.data['sha256']):
                    raise ValueError()
                request = LabelRequest.model_validate_json(canonical({**data['tuple'], 'source_context_sha256': data['source_context_sha256'],
                    'data_epoch': data['data_epoch_before'], **{name: data[name] for name in ('outcome', 'ground_truth_counts', 'method', 'duration_ms', 'independence_declared', 'note')}}))
                uuid(data['reviewer_id']); _n(data['created_at_ms']); epoch = _n(data['data_epoch_before'], positive=True)
                if epoch in epochs or epoch < _n(head['data_epoch'], positive=True):raise ValueError()
                epochs.add(epoch)
                if previous is not None and (data['created_at_ms'] < previous.data['created_at_ms'] or epoch <= previous.data['data_epoch_before']):
                    raise ValueError()
                conflicts = ([] if data['reviewer_id'] != head['originating_user_id'] else ['originating_operator'])
                if previous is not None and previous.data['reviewer_id'] != data['reviewer_id']:conflicts.append('different_revision_author')
                if type(data['conflict_codes']) is not list or data['conflict_codes'] != conflicts:
                    raise ValueError()
                context = data['source_context']; _shape(context, CONTEXT, {'action'})
                if sha(data['source_context_sha256']) != digest(context):raise ValueError()
                observations = [copies[Key('state', 'observation#' + uuid(tuple_.before_observation_id))]]
                if tuple_.action_id is not None:
                    action = copies[Key('state', 'action#' + uuid(tuple_.action_id))]
                    after = copies[Key('state', 'observation#' + uuid(tuple_.after_observation_id))]
                    if (action.data['observation_id'] != tuple_.before_observation_id or action.data['status'] != 'acknowledged'
                            or after.data['sequence'] <= observations[0].data['sequence']):raise ValueError()
                    observations.append(after); reference(checked, action, action.revision)
                    if context.get('action') != {'id': action.data['id'], 'kind': action.data['kind'], 'state_version': action.revision}:raise ValueError()
                    links.add(CaptureLink(row.key, action.key, 'label_action'))
                elif 'action' in context:raise ValueError()
                expected_results = []; expected_sources = []; window = []
                if type(context['sources']) is not list:raise ValueError()
                expected_source_count = sum(2 if o.data.get('retain_original_frame') is True else 1 for o in observations)
                if len(context['sources']) != expected_source_count:raise ValueError()
                offset = 0
                for observation in observations:
                    o = observation.data
                    if o['status'] != 'completed' or o['inspection_id'] != head['id'] or o['completed_at_ms'] > data['created_at_ms']:raise ValueError()
                    reference(checked, observation, observation.revision)
                    result = WorkerResult.model_validate_json(o['result_json'])
                    expected_results.append({'observation_id': o['id'], 'sequence': o['sequence'], 'findings': [v.value for v in result.findings],
                        'reason_codes': list(result.reason_codes), 'quality_ok': result.quality_ok, 'unknown_regions': result.unknown_regions, 'calibration_sha256': result.calibration_hash})
                    ids = [o['asset_id']] + ([original_asset_id(o['id'])] if o.get('retain_original_frame') is True else [])
                    for index, aid in enumerate(ids):
                        asset = copies[Key('state', 'asset#' + uuid(aid))]; a = asset.data; source = context['sources'][offset]; offset += 1
                        _shape(source, SOURCE | (ORIGINAL_SOURCE if index else set()))
                        purpose = purposes[uuid(a['purpose_id'])]; used_purposes.add(purpose.key)
                        reference(checked, asset, source['asset_version']); reference(checked, purpose, source['purpose_version'])
                        if source['observation_version'] != observation.revision:raise ValueError()
                        _n(source['observation_version'], positive=True); _n(source['expires_at_ms'], positive=True)
                        expiry = min(_n(a['expires_at_ms']), _n(purpose.data['expires_at_ms']))
                        expected = {'observation_id': o['id'], 'observation_version': observation.revision, 'asset_id': aid,
                            'asset_version': source['asset_version'], 'sha256': a['sha256'], 'purpose_id': a['purpose_id'],
                            'purpose_version': source['purpose_version'], 'expires_at_ms': expiry}
                        if index:expected.update(derivation='original_transmitted_frame', input_sha256=result.source_sha256,
                            context_sha256=o['context_sha256'], calibration_sha256=result.calibration_hash)
                        if source != expected or a['data_origin'] != definition.data_origin.value:raise ValueError()
                        expected_sources.append(expected); window.append(expiry)
                        links.add(CaptureLink(row.key, asset.key, 'label_media_source'))
                    links.add(CaptureLink(row.key, observation.key, 'label_observation'))
                if len({r['calibration_sha256'] for r in expected_results}) != 1:raise ValueError()
                expected_context = {'tuple': data['tuple'], 'inspection_id': head['id'], 'recipe_id': definition.recipe_id,
                    'recipe_revision': definition.revision, 'recipe_sha256': source_recipe.data['sha256'], 'data_origin': definition.data_origin.value,
                    'artifact_sha256': head['artifact_sha256'], 'runtime_instance_id': head['runtime_instance_id'],
                    'inspection_bindings': {k: v for k, v in inspection_context(head, observations[-1].data['sequence'], observations[-1].data).items() if k != 'sequence'},
                    'kit_group': head['kit_id'], 'session_group': head['originating_session_id'], 'operator_group': head['originating_user_id'],
                    'sources': expected_sources, 'observations': expected_results, 'expected_classes': [c.part_class_id.value for c in definition.constraints]}
                if tuple_.action_id is not None:expected_context['action'] = context['action']
                if canonical(context) != canonical(expected_context) or not data['created_at_ms'] <= event.data['at_ms'] < min(window):raise ValueError()
                if (not set(expected_context['expected_classes']) <= {c.part_class.value for c in request.ground_truth_counts}
                        or (request.method == 'physical_manual_check' and definition.data_origin.value != 'physical')
                        or (request.method == 'synthetic_fixture' and definition.data_origin.value != 'synthetic')):raise ValueError()
                reference(checked, source_recipe, 1)
                root_ref = checked.get(root.key)
                if (root_ref is None or not max(publications[o.data['id']] for o in observations) <= root_ref.revision <= root.revision
                        or (root_ref.revision == root.revision and root_ref.sha256 != _payload_sha256(head))
                        or Key('state', 'user#' + data['reviewer_id']) not in checked):raise ValueError()
                quota = Key('state', 'label-quota#' + event.data['actor_scope'])
                if set(written) != {label.key, row.key, DATA, quota} or DATA not in checked:raise ValueError()
                if (written[label.key].previous_revision != (None if number == 1 else number-1) or written[label.key].revision != number
                        or written[label.key].sha256 != _payload_sha256({'id': ident, 'latest_revision': number, 'sha256': data['sha256']})
                        or written[row.key].previous_revision is not None or written[row.key].revision != 1
                        or written[row.key].sha256 != _payload_sha256(data)):raise ValueError()
                if previous is None:
                    if label.key in checked:raise ValueError()
                else:
                    old_head = checked.get(label.key)
                    if (old_head is None or old_head.revision != number-1
                            or old_head.sha256 != _payload_sha256({'id': ident, 'latest_revision': number-1, 'sha256': previous.data['sha256']})):raise ValueError()
                    reference(checked, previous, 1); links.add(CaptureLink(row.key, previous.key, 'previous_label_revision'))
                for ref in (*binding.writes, *binding.checks):
                    if ref.key not in all_owned and ref.key != root.key:dependencies.add(CaptureRecord(ref.key, ref.revision, ref.sha256))
                links.update((CaptureLink(label.key, row.key, 'label_revision'), CaptureLink(row.key, event.key, 'label_audit'),
                    CaptureLink(row.key, source_recipe.key, 'shared_recipe')))
                previous = row
            if previous is None or previous.data['sha256'] != label.data['sha256']:raise ValueError()
        if used_purposes != {r.key for r in purposes.values()}:raise ValueError()
        return LabelFamily(capture, _record(source_recipe), tuple(_record(r) for r in sorted(purposes.values(), key=lambda r: r.key.resource)),
            tuple(_record(copies[r.key]) for r in sorted(rows, key=lambda r: (r.key.table, r.key.resource))),
            tuple(sorted(links, key=lambda v: (v.source.table, v.source.resource, v.target.table, v.target.resource, v.kind))),
            tuple(sorted(dependencies, key=lambda v: (v.key.table, v.key.resource, v.revision, v.sha256))), payload_bytes)
    except LabelHistoryHeld:
        raise
    except (CaptureDiscoveryHeld, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise LabelHistoryHeld('intact complete supported historical label family required') from exc
