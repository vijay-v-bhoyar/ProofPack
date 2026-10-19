"""Private dataset-family parsing; no current rights, execution or erasure grant."""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re

from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.capture_lineage import CaptureRecord, CaptureLink, _n, _shape, _record
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.evidence.job_authority import scope_sha256, _FIELDS
from proofpack.evidence.label_lineage import discover as label_discover, LabelHistoryHeld
from proofpack.evidence.improvement_lineage import discover as permission_discover, ImprovementHistoryHeld
from proofpack.review.labels import head_key, label_revision_key
from proofpack.review.manifests import ManifestRequest, job_key, entry_key, manifest_key, group_key
from proofpack.review.datasets import Split
from proofpack.runtime.control import DATA, RUNTIME, uuid, sha


class DatasetHistoryHeld(RuntimeError):pass


@dataclass(frozen=True)
class LabelInputs:
    inspection: Row
    rows: tuple
    capture_rows: tuple
    recipe: Row
    purpose_rows: tuple


@dataclass(frozen=True)
class PermissionInputs:
    preview: Row
    rows: tuple


@dataclass(frozen=True)
class DatasetIntent:
    source: Key
    target: Key
    revision: int
    kind: str


@dataclass(frozen=True)
class DatasetFamily:
    job: CaptureRecord
    records: tuple[CaptureRecord, ...]
    links: tuple[CaptureLink, ...]
    dependencies: tuple[CaptureRecord, ...]
    intents: tuple[DatasetIntent, ...]
    payload_bytes: int


JOB = frozenset('id kind requested_by configuration artifact_sha256 controls_sha256 environment data_epoch created_at_ms expires_at_ms request_json request_sha256 example_count status processed steps_reserved chain_sha256 seed_sha256 validation_runtime effective_deadline_ms splits manifest_sha256 failure_reason lease_token lease_until_ms lease_runtime processing_authority'.split())
ENTRY = frozenset('schema_version dataset_id index content content_sha256 previous_chain_sha256 chain_sha256'.split())
CONTENT = frozenset('label_id label_revision label_sha256 source_context_sha256 split data_origin sources permissions groups physical_truth_verified independence_verified outcome ground_truth_counts method duration_ms prior_exposure_unknown independent_benchmark_qualified'.split())
SEAL = frozenset('id request_sha256 example_count chain_sha256 seed_sha256 configuration artifact_sha256 controls_sha256 environment data_epoch created_at_ms validation_runtime splits schema_version expires_at_ms prior_exposure_unknown independent_benchmark_qualified sha256'.split())
EVENT = frozenset('kind actor_scope at_ms session_id resource_bindings'.split())
READ = frozenset('kind dataset_id manifest_sha256 user_id access_version first_index last_index at_ms prior_exposure_unknown resource_bindings'.split())
DIRECT = frozenset('kind dataset_id request_sha256 index prior_job_revision at_ms resource_bindings'.split())


def _runtime(value):
    _shape(value, frozenset('instance_id epoch artifact_sha256 controls_sha256 environment'.split()))
    uuid(value['instance_id']);_n(value['epoch'], positive=True)
    sha(value['artifact_sha256']);sha(value['controls_sha256'])
    if value['environment'] not in {'test', 'synthetic_demo', 'beta'}:raise ValueError()


def _same(reference, key, revision, data):
    if reference is None or reference.key != key or reference.revision != revision or reference.sha256 != _payload_sha256(data):raise ValueError()


def discover(job, rows, *, label_families, permission_families, group_rows, deployment, max_records, max_payload_bytes):
    """Complete inventory/drain, shared group history and action admission are external."""
    if (type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or any(type(v) is not tuple for v in (rows, label_families, permission_families, group_rows))
            or any(type(v) is not int or not 1 <= v <= 2**63-1 for v in (max_records, max_payload_bytes))):
        raise ValueError('explicit bounded dataset and source-family inputs required')
    try:
        total = 1 + len(rows) + len(group_rows)
        if total > max_records:raise DatasetHistoryHeld('dataset record bound exhausted')
        if any(type(v) is not LabelInputs for v in label_families) or any(type(v) is not PermissionInputs for v in permission_families):raise ValueError()
        for family in label_families:
            if any(type(v) is not tuple for v in (family.rows, family.capture_rows, family.purpose_rows)):raise ValueError()
            total += 2 + len(family.rows) + len(family.capture_rows) + len(family.purpose_rows)
            if total > max_records:raise DatasetHistoryHeld('dataset record bound exhausted')
        for family in permission_families:
            if type(family.rows) is not tuple:raise ValueError()
            total += 1 + len(family.rows)
            if total > max_records:raise DatasetHistoryHeld('dataset record bound exhausted')
        incoming = [job, *rows, *group_rows]
        for family in label_families:
            incoming.extend((family.inspection, family.recipe, *family.rows, *family.capture_rows, *family.purpose_rows))
        for family in permission_families:
            incoming.extend((family.preview, *family.rows))
        copies = {}; size = 0
        for row in incoming:
            if (isinstance(row, ErasureMarker) or not isinstance(row, Row) or not isinstance(row.key, Key)
                    or type(row.data) is not dict or type(row.revision) is not int or not 1 <= row.revision <= 2**63-1):raise ValueError()
            _payload_sha256(row.data);size += len(canonical(row.data).encode())
            if size > max_payload_bytes:raise DatasetHistoryHeld('dataset payload bound exhausted')
            if row.key in copies:
                old = copies[row.key]
                if old.revision != row.revision or canonical(old.data) != canonical(row.data):raise ValueError()
            else:copies[row.key] = deepcopy(row)
        if len({r.key for r in (job, *rows)}) != 1 + len(rows):raise ValueError()
        root = copies[job.key];d = root.data;_shape(d, JOB);ident = uuid(d['id'])
        if root.key != job_key(ident) or d['kind'] != 'dataset_manifest':raise ValueError()
        uuid(d['requested_by']);_n(d['data_epoch'], positive=True)
        for field in ('configuration', 'artifact_sha256', 'controls_sha256', 'request_sha256', 'chain_sha256', 'seed_sha256'):sha(d[field])
        if d['environment'] not in {'test', 'synthetic_demo', 'beta'}:raise ValueError()
        created = _n(d['created_at_ms']);expires = _n(d['expires_at_ms'], positive=True)
        if not created < _n(d['effective_deadline_ms'], positive=True) <= expires:raise ValueError()
        text = d['request_json']
        if type(text) is not str or not 1 <= len(text.encode()) <= 262144 or hashlib.sha256(text.encode()).hexdigest() != d['request_sha256']:raise ValueError()
        request = ManifestRequest.model_validate_json(text)
        if canonical(request.model_dump(mode='json')) != text or _n(d['example_count'], positive=True) != len(request.selections):raise ValueError()
        count = d['example_count'];processed = _n(d['processed']);steps = _n(d['steps_reserved'])
        if processed > count or steps < processed or d['seed_sha256'] != digest({'dataset_id': ident, 'request_sha256': d['request_sha256']}):raise ValueError()
        status = d['status']
        if status == 'processing':raise DatasetHistoryHeld('dataset worker drain required')
        if status not in {'queued', 'failed', 'cancelled', 'completed', 'retired'}:raise ValueError()
        failure = d['failure_reason']
        if failure is not None and failure not in {'SPLIT_CONFLICT', 'SOURCE_OR_PERMISSION_HELD', 'STEP_BUDGET_EXHAUSTED'}:raise ValueError()
        if ((status == 'failed' and failure is None)
                or (status not in {'failed', 'cancelled'} and failure is not None)):raise ValueError()
        if d['validation_runtime'] is None:
            if steps:raise ValueError()
        else:_runtime(d['validation_runtime'])
        residual = d['lease_token'] is not None
        if residual:
            uuid(d['lease_token']);_runtime(d['lease_runtime'])
            if (failure != 'STEP_BUDGET_EXHAUSTED' or status not in {'failed', 'cancelled'}
                    or not created <= _n(d['lease_until_ms'], positive=True) <= expires
                    or canonical(d['lease_runtime']) != canonical(d['validation_runtime'])):raise ValueError()
        elif d['lease_runtime'] is not None or _n(d['lease_until_ms']) != 0:raise ValueError()
        authority = d['processing_authority'];_shape(authority, frozenset(('body', 'signature')));body = authority['body'];_shape(body, _FIELDS)
        if (type(authority['signature']) is not str or re.fullmatch(r'[A-Za-z0-9_-]{43}', authority['signature']) is None
                or _n(body['schema_version'], positive=True) != 1 or body['job_id'] != ident or body['kind'] != d['kind']
                or body['scope_sha256'] != scope_sha256(d) or body['user_id'] != d['requested_by'] or body['role'] != 'reviewer'
                or type(body['cookie_ref']) is not str or re.fullmatch(r'cookie#[a-f0-9]{64}', body['cookie_ref']) is None):raise ValueError()
        uuid(body['session_id']);_n(body['access_version'], positive=True);_n(body['session_epoch'], positive=True)
        if not created <= _n(body['issued_at_ms']) < _n(body['expires_at_ms'], positive=True) <= expires:raise ValueError()
        catalog = None;seal = None;entries = {};events = []
        for original in rows:
            row = copies[original.key];data = row.data
            if row.key == Key('state', 'dataset-catalog#' + ident):
                _shape(data, frozenset(('id',)))
                if row.revision != 1 or data['id'] != ident:raise ValueError()
                catalog = row
            elif row.key == manifest_key(ident):
                if row.revision != 1:raise ValueError()
                _shape(data, SEAL);seal = row
            elif row.key.table == 'state' and row.key.resource.startswith('dataset-example#'):
                _shape(data, ENTRY);index = _n(data['index'])
                if row.key != entry_key(ident, index) or row.revision != 1 or data['dataset_id'] != ident or index >= count or index in entries:raise ValueError()
                if (_n(data['schema_version'], positive=True) != 1 or sha(data['content_sha256']) != digest(data['content'])
                        or sha(data['chain_sha256']) != digest({k: v for k, v in data.items() if k != 'chain_sha256'})):raise ValueError()
                sha(data['previous_chain_sha256']);_shape(data['content'], CONTENT);entries[index] = row
            elif row.key.table == 'events':
                if row.revision != 1:raise ValueError()
                events.append((row, decode(row, deployment=deployment)))
            else:raise ValueError()
        if catalog is None or sorted(entries) != list(range(len(entries))) or processed > len(entries):raise ValueError()
        previous = d['seed_sha256']
        for index in range(len(entries)):
            row = entries[index]
            if row.data['previous_chain_sha256'] != previous:raise ValueError()
            previous = row.data['chain_sha256']
        if d['chain_sha256'] != (d['seed_sha256'] if processed == 0 else entries[processed - 1].data['chain_sha256']):raise ValueError()
        splits = {split.value: 0 for split in Split};_shape(d['splits'], frozenset(splits))
        for index in range(processed):splits[entries[index].data['content']['split']] += 1
        if canonical(d['splits']) != canonical(splits):raise ValueError()
        if status in {'completed', 'retired'}:
            if processed != count or len(entries) != count or seal is None or failure is not None:raise ValueError()
            expected = {key: d[key] for key in ('id', 'request_sha256', 'example_count', 'chain_sha256', 'seed_sha256',
                'configuration', 'artifact_sha256', 'controls_sha256', 'environment', 'data_epoch', 'created_at_ms', 'validation_runtime', 'splits')}
            expected.update(schema_version=1, expires_at_ms=d['effective_deadline_ms'], prior_exposure_unknown=True, independent_benchmark_qualified=False)
            expected['sha256'] = digest(expected)
            if canonical(seal.data) != canonical(expected) or d['manifest_sha256'] != seal.data['sha256']:raise ValueError()
        elif seal is not None or d['manifest_sha256'] is not None or processed == count:raise ValueError()
        labels = {};heads = {};grants = {};permissions = {};links = set();dependencies = set()
        source_keys = set()
        for family in label_families:
            label_discover(copies[family.inspection.key], tuple(copies[r.key] for r in family.rows),
                capture_rows=tuple(copies[r.key] for r in family.capture_rows), recipe=copies[family.recipe.key],
                purpose_rows=tuple(copies[r.key] for r in family.purpose_rows), deployment=deployment,
                max_records=max_records, max_payload_bytes=max_payload_bytes)
            for original in family.rows:
                row = copies[original.key]
                if row.key.resource.startswith('label-revision#'):labels[(row.data['id'], row.data['revision'])] = row
                elif row.key.resource.startswith('label#'):heads[row.data['id']] = row
            source_keys.update(r.key for r in (family.inspection, family.recipe, *family.rows, *family.capture_rows, *family.purpose_rows))
        for family in permission_families:
            result = permission_discover(copies[family.preview.key], tuple(copies[r.key] for r in family.rows),
                deployment=deployment, max_records=max_records, max_payload_bytes=max_payload_bytes)
            if result.grant is None:raise ValueError()
            grant = copies[result.grant.key];grants[grant.data['id']] = grant;permissions[grant.data['id']] = copies[result.permission.key]
            source_keys.update(r.key for r in (family.preview, *family.rows))
        groups = {}
        for original in group_rows:
            row = copies[original.key];value = row.data
            _shape(value, frozenset('id category split generation original_split created_at_ms sha256'.split()), {'reason', 'changed_at_ms'})
            if row.key != group_key(sha(value['id'])) or row.revision != _n(value['generation'], positive=True):raise ValueError()
            if (value['category'] not in {'kit', 'session', 'operator'} or value['split'] not in splits
                    or value['original_split'] not in splits or digest({k: v for k, v in value.items() if k != 'sha256'}) != sha(value['sha256'])):raise ValueError()
            _n(value['created_at_ms'])
            if value['generation'] == 1:
                if set(value) & {'reason', 'changed_at_ms'} or value['split'] != value['original_split']:raise ValueError()
            elif value['generation'] == 2:
                if value['split'] != 'DEVELOPMENT' or value['original_split'] == 'DEVELOPMENT' or _n(value['changed_at_ms']) < value['created_at_ms']:raise ValueError()
                if type(value['reason']) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value['reason']) is None:raise ValueError()
            else:raise ValueError()
            if value['id'] in groups:raise ValueError()
            groups[value['id']] = row;source_keys.add(row.key)
        intents = [];copy_checks = {};copy_windows = {};used_groups = set()
        for selection in request.selections:
            intents.append(DatasetIntent(root.key, label_revision_key(selection.label_id, selection.label_revision), selection.label_revision, 'requested_label'))
            for permission in selection.permissions:
                intents.append(DatasetIntent(root.key, Key('state', 'improvement-permission#' + permission.id), permission.state_version, 'requested_permission'))
        for index, row in entries.items():
            selection = request.selections[index];label = labels.get((selection.label_id, selection.label_revision))
            if label is None or selection.label_id not in heads:raise DatasetHistoryHeld('complete source label family required')
            expected, checks, used, window = _copy(row, selection, label, grants, permissions, groups)
            if canonical(row.data['content']) != canonical(expected):raise ValueError()
            copy_checks[index] = checks;copy_windows[index] = window;used_groups.update(used)
            links.add(CaptureLink(row.key, label.key, 'copied_label'))
        if used_groups != set(groups):raise ValueError()
        if processed and d['effective_deadline_ms'] > min(copy_windows[index][1] for index in range(processed)):raise ValueError()
        owned = {root.key, *(r.key for r in rows)};versions = {};created_rows = {};step_events = [];first = 0
        for row, binding in events:
            e = row.data;kind = e['kind'];checked = {r.key: r for r in binding.checks};written = {r.key: r for r in binding.writes}
            if kind != binding.operation:raise ValueError()
            _n(e['at_ms'])
            for key, reference in checked.items():
                if key == root.key:
                    if reference.revision > root.revision:raise ValueError()
                    if reference.revision == root.revision:_same(reference, key, root.revision, d)
                elif key in owned:
                    _same(reference, key, copies[key].revision, copies[key].data)
            if root.key in written:
                ref = written[root.key]
                if ref.revision in versions:raise ValueError()
                versions[ref.revision] = (row, ref)
                if ref.revision == root.revision:_same(ref, root.key, root.revision, d)
                if ref.revision > root.revision:raise ValueError()
            for key, ref in written.items():
                if key in owned and key != root.key:
                    if key in created_rows or ref.previous_revision is not None:raise ValueError()
                    _same(ref, key, 1, copies[key].data);created_rows[key] = row
            if row.key.resource.startswith('access#'):
                if row.key.resource != 'access#' + uuid(row.key.resource[7:]):raise ValueError()
                _shape(e, EVENT, {'details'});sha(e['actor_scope']);uuid(e['session_id'])
                if RUNTIME not in checked or DATA not in checked or Key('state', 'session#' + e['session_id']) not in checked:raise ValueError()
                if not any(key.table == 'state' and key.resource.startswith('user#') for key in checked):raise ValueError()
                if kind in {'dataset-create', 'dataset-step:' + ident} and not created <= e['at_ms'] < expires:raise ValueError()
                if kind == 'dataset-create':
                    first += 1;_shape(e['details'], frozenset(('dataset_id', 'request_sha256', 'example_count')))
                    if canonical(e['details']) != canonical({'dataset_id': ident, 'request_sha256': d['request_sha256'], 'example_count': count}):raise ValueError()
                    quota = Key('state', 'dataset-create-quota#' + e['actor_scope'])
                    if set(written) != {root.key, catalog.key, quota} or written[root.key].previous_revision is not None or written[root.key].revision != 1:raise ValueError()
                    if Key('state', 'user#' + d['requested_by']) not in checked:raise ValueError()
                elif kind == 'dataset-step:' + ident:
                    if 'details' in e or set(written) != {root.key, Key('state', 'dataset-step-quota#' + e['actor_scope'])}:raise ValueError()
                    if Key('state', 'user#' + d['requested_by']) not in checked:raise ValueError()
                    step_events.append(row)
                elif kind in {'dataset-cancel:' + ident, 'dataset-retire:' + ident}:
                    _shape(e['details'], frozenset(('dataset_id', 'status', 'reason')))
                    target = 'cancelled' if kind.startswith('dataset-cancel:') else 'retired'
                    if e['details']['dataset_id'] != ident or e['details']['status'] != target:raise ValueError()
                    quota = Key('state', 'dataset-end-quota#' + e['actor_scope'])
                    allowed = {quota} | ({root.key} if root.key in written else set()) | ({DATA} if root.key in written and target == 'retired' else set())
                    if set(written) != allowed or root.key not in checked:raise ValueError()
                else:raise ValueError()
            elif row.key.resource.startswith('dataset-transition#'):
                if row.key.resource != 'dataset-transition#' + uuid(row.key.resource[len('dataset-transition#'):]):raise ValueError()
                _shape(e, DIRECT, {'failure_reason'})
                if not created <= e['at_ms'] < expires:raise ValueError()
                if e['dataset_id'] != ident or e['request_sha256'] != d['request_sha256'] or root.key not in written:raise ValueError()
                if (RUNTIME not in checked or not any(key.table == 'state' and key.resource.startswith('user#') for key in checked)
                        or not any(key.table == 'state' and key.resource.startswith('session#') for key in checked)):raise ValueError()
                if written[root.key].previous_revision != _n(e['prior_job_revision'], positive=True):raise ValueError()
                index = _n(e['index'])
                if index >= count:raise ValueError()
                if kind == 'dataset-source-failed':
                    if set(written) != {root.key} or e.get('failure_reason') not in {'SPLIT_CONFLICT', 'SOURCE_OR_PERMISSION_HELD'}:raise ValueError()
                elif kind == 'dataset-example-committed':
                    if 'failure_reason' in e or index not in entries:raise ValueError()
                    lower, expiry, cutoff = copy_windows[index]
                    if not max(created, lower) <= e['at_ms'] < expiry or e['at_ms'] > cutoff:raise ValueError()
                    allowed = {root.key} | {entries[index].key} | ({seal.key} if seal is not None and index == count - 1 else set()) | {r.key for r in groups.values()}
                    if not set(written) <= allowed:raise ValueError()
                    refs = {**checked, **written}
                    _same(refs.get(entries[index].key), entries[index].key, 1, entries[index].data)
                    for key, ref in copy_checks[index].items():
                        actual = refs.get(key)
                        if actual is None or (actual.revision, actual.sha256) != (ref.revision, ref.sha256):raise ValueError()
                else:raise ValueError()
            elif row.key.resource.startswith('dataset-access#'):
                if row.key.resource != 'dataset-access#' + uuid(row.key.resource[len('dataset-access#'):]):raise ValueError()
                _shape(e, READ, {'consumer_job_id'});uuid(e['user_id']);_n(e['access_version'], positive=True)
                if e['dataset_id'] != ident or e['prior_exposure_unknown'] is not True:raise ValueError()
                if (RUNTIME not in checked or DATA not in checked or Key('state', 'user#' + e['user_id']) not in checked
                        or not any(key.table == 'state' and key.resource.startswith('session#') for key in checked)):raise ValueError()
                lo = _n(e['first_index']);hi = _n(e['last_index'])
                if not lo <= hi < count or root.key not in checked:raise ValueError()
                if kind not in {'dataset_request_read', 'dataset_examples_read', 'evaluation_examples_read', 'vision_measurement_case_admitted'}:raise ValueError()
                if kind != 'dataset_request_read':
                    if seal is None or e['manifest_sha256'] != seal.data['sha256']:raise ValueError()
                    _same(checked.get(seal.key), seal.key, 1, seal.data)
                    completed_version = root.revision - int(status == 'retired')
                    _same(checked.get(root.key), root.key, completed_version, {**d, 'status': 'completed'})
                    if not created <= e['at_ms'] < seal.data['expires_at_ms']:raise ValueError()
                    if any(not copy_windows[index][0] <= e['at_ms'] < copy_windows[index][1]
                            or e['at_ms'] > copy_windows[index][2] for index in range(lo, hi + 1)):raise ValueError()
                elif lo != 0 or hi != count - 1 or e['manifest_sha256'] not in {None, d['manifest_sha256']}:raise ValueError()
                if 'consumer_job_id' in e:
                    consumer = job_key(uuid(e['consumer_job_id']))
                    if consumer not in checked:raise ValueError()
                if len(written) != 1 or any(key.table != 'state' or re.fullmatch(r'dataset-read-quota#[a-f0-9]{64}', key.resource) is None for key in written):raise ValueError()
            else:raise ValueError()
            for reference in (*binding.checks, *binding.writes):
                if reference.key not in owned:dependencies.add(CaptureRecord(reference.key, reference.revision, reference.sha256))
            links.add(CaptureLink(root.key, row.key, 'dataset_history'))
        if first != 1 or sorted(versions) != list(range(1, root.revision + 1)):raise ValueError()
        for number, (_, ref) in versions.items():
            if ref.previous_revision != (None if number == 1 else number - 1):raise ValueError()
        if set(created_rows) != {catalog.key, *(row.key for row in entries.values()), *(() if seal is None else (seal.key,))}:raise ValueError()
        budget = int(failure == 'STEP_BUDGET_EXHAUSTED')
        if budget and steps == 0:raise ValueError()
        if len(step_events) - budget != steps:raise ValueError()
        if residual and not any(row.data['kind'] == 'dataset-step:' + ident and row.data['at_ms'] >= d['lease_until_ms'] for row in step_events):raise ValueError()
        for key in source_keys:dependencies.add(_record(copies[key]))
        return DatasetFamily(_record(root), tuple(_record(copies[r.key]) for r in sorted(rows, key=lambda r: (r.key.table, r.key.resource))),
            tuple(sorted(links, key=lambda r: (r.source.table, r.source.resource, r.target.table, r.target.resource, r.kind))),
            tuple(sorted(dependencies, key=lambda r: (r.key.table, r.key.resource, r.revision, r.sha256))), tuple(intents), size)
    except DatasetHistoryHeld:raise
    except (KeyError, TypeError, ValueError, AttributeError, LabelHistoryHeld, ImprovementHistoryHeld) as exc:
        raise DatasetHistoryHeld('complete supported dataset family and copied-source inputs required') from exc


def _copy(row, selection, label, grants, permissions, groups):
    """Reconstruct the complete admitted copy from immutable validated sources."""
    value = label.data;context = value['source_context'];checks = {
        label.key: _record(label),
        head_key(value['id']): CaptureRecord(head_key(value['id']), value['revision'],
            digest({'id': value['id'], 'latest_revision': value['revision'], 'sha256': value['sha256']}))}
    needed = {source['asset_id']: source for source in context['sources']};covered = set();allowed = []
    # Historical version checks below prove the consumed state, even when a
    # later revocation shares its timestamp. Immutable expiry stays exclusive.
    lower = _n(value['created_at_ms']);expiry = min(_n(source['expires_at_ms'], positive=True) for source in context['sources']);cutoff = 2**63 - 1
    for permission in selection.permissions:
        grant = grants.get(permission.id);head = permissions.get(permission.id)
        if grant is None or head is None or permission.state_version != 1 or grant.data['derived_review_metadata_allowed'] is not True:raise ValueError()
        g = grant.data;subset = needed.keys() & {source['id'] for source in g['scope']['assets']}
        lower = max(lower, g['created_at_ms']);expiry = min(expiry, g['expires_at_ms'])
        if head.data['withdrawn']:cutoff = min(cutoff, head.data['withdrawn_at_ms'])
        if not subset:raise ValueError()
        for source in g['scope']['assets']:
            if source['id'] not in subset:continue
            original = needed[source['id']]
            if (source['sha256'] != original['sha256'] or source['data_origin'] != context['data_origin']
                    or source['purpose_id'] != original['purpose_id'] or source['asset_revision'] != original['asset_version']
                    or source['purpose_revision'] != original['purpose_version']):raise ValueError()
            checks[Key('state', 'asset#' + source['id'])] = CaptureRecord(Key('state', 'asset#' + source['id']), source['asset_revision'], source['asset_record_sha256'])
            checks[Key('state', 'purpose#' + source['purpose_id'])] = CaptureRecord(Key('state', 'purpose#' + source['purpose_id']), source['purpose_revision'], source['purpose_record_sha256'])
        covered.update(subset);allowed.append({'id': permission.id, 'state_version': 1, 'grant_sha256': g['sha256']})
        checks[grant.key] = _record(grant)
        checks[head.key] = CaptureRecord(head.key, 1, digest({'id': permission.id, 'grant_sha256': g['sha256'], 'withdrawn': False}))
    if covered != needed.keys():raise ValueError()
    assigned = [];used = set()
    for category, name in (('kit', 'kit_group'), ('session', 'session_group'), ('operator', 'operator_group')):
        ident = digest({'category': category, 'group': context[name]});group = groups.get(ident)
        if group is None:raise ValueError()
        entries = row.data['content']['groups']
        position = len(assigned)
        if type(entries) is not list or len(entries) != 3:raise ValueError()
        item = entries[position];_shape(item, frozenset(('id', 'category', 'generation')));generation = _n(item['generation'], positive=True)
        if generation > group.revision:raise ValueError()
        data = group.data
        if generation == 1:
            payload = {key: data[key] for key in ('id', 'category', 'original_split', 'created_at_ms')}
            payload.update(split=data['original_split'], generation=1);payload['sha256'] = digest(payload)
            if group.revision > generation:cutoff = min(cutoff, data['changed_at_ms'])
        elif generation == 2 and group.revision == 2:payload = data
        else:raise ValueError()
        if payload['category'] != category or payload['split'] != selection.split.value:raise ValueError()
        lower = max(lower, payload['created_at_ms'], payload.get('changed_at_ms', 0))
        assigned.append({'id': ident, 'category': category, 'generation': generation});used.add(ident)
        checks[group.key] = CaptureRecord(group.key, generation, _payload_sha256(payload))
    expected = {'label_id': value['id'], 'label_revision': selection.label_revision, 'label_sha256': value['sha256'],
        'source_context_sha256': value['source_context_sha256'], 'split': selection.split.value, 'data_origin': context['data_origin'],
        'sources': [{key: source[key] for key in ('asset_id', 'sha256')} for source in context['sources']],
        'permissions': allowed, 'groups': assigned, 'physical_truth_verified': False, 'independence_verified': False,
        'outcome': value['outcome'], 'ground_truth_counts': value['ground_truth_counts'], 'method': value['method'],
        'duration_ms': value['duration_ms'], 'prior_exposure_unknown': True, 'independent_benchmark_qualified': False}
    return expected, checks, used, (lower, expiry, cutoff)
