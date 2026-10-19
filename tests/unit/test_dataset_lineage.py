from copy import deepcopy
from uuid import UUID
import hashlib
import pytest
from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.repository import Key, Row, Write
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.evidence.job_authority import scope_sha256
from proofpack.review.manifests import job_key, ManifestRequest, Selection, PermissionBinding
from proofpack.review.datasets import Split
from proofpack.runtime.control import DATA, RUNTIME


def uid(value):return str(UUID(int=value))


def family(*, data_epoch=1, created=100, data_changed=100, deployment='beta', split=Split.DEVELOPMENT, extra_labels=()):
    ident = uid(1)
    request = ManifestRequest(selections=tuple(Selection(label_id=label_id, label_revision=1, split=split,
        permissions=(PermissionBinding(id=uid(11), state_version=1),)) for label_id in (uid(10), *extra_labels)),
        historical_diagnostic_acknowledged=True, frozen_holdout_acknowledged=True)
    text = canonical(request.model_dump(mode='json')); request_sha = hashlib.sha256(text.encode()).hexdigest()
    seed = digest({'dataset_id': ident, 'request_sha256': request_sha})
    data = {'id': ident, 'kind': 'dataset_manifest', 'requested_by': uid(2), 'configuration': 'a' * 64,
            'artifact_sha256': 'b' * 64, 'controls_sha256': 'c' * 64, 'environment': 'test', 'data_epoch': data_epoch,
            'created_at_ms': created, 'expires_at_ms': 1000, 'request_json': text, 'request_sha256': request_sha,
            'example_count': len(request.selections), 'status': 'queued', 'processed': 0, 'steps_reserved': 0,
            'chain_sha256': seed, 'seed_sha256': seed, 'validation_runtime': None, 'effective_deadline_ms': 1000,
            'splits': {split.value: 0 for split in Split}, 'manifest_sha256': None, 'failure_reason': None,
            'lease_token': None, 'lease_until_ms': 0, 'lease_runtime': None}
    body = {'schema_version': 1, 'job_id': ident, 'kind': 'dataset_manifest', 'scope_sha256': scope_sha256(data),
            'cookie_ref': 'cookie#' + 'd' * 64, 'user_id': uid(2), 'session_id': uid(3),
            'access_version': 1, 'session_epoch': 1, 'role': 'reviewer', 'issued_at_ms': created, 'expires_at_ms': 1000}
    # A structurally valid private signature fixture is not authenticated authority.
    data['processing_authority'] = {'body': body, 'signature': 'A' * 43}
    job = Row(job_key(ident), 1, data)
    catalog = Row(Key('state', 'dataset-catalog#' + ident), 1, {'id': ident})
    event_key = Key('events', 'access#' + uid(20))
    event = {'kind': 'dataset-create', 'actor_scope': 'e' * 64, 'at_ms': created, 'session_id': uid(3),
             'details': {'dataset_id': ident, 'request_sha256': request_sha, 'example_count': len(request.selections)}}
    checks = (Row(Key('state', 'user#' + uid(2)), 1, {'id': uid(2)}),
              Row(Key('state', 'session#' + uid(3)), 1, {'id': uid(3)}),
              Row(DATA, data_epoch, {'epoch': data_epoch, 'changed_at_ms': data_changed}), Row(RUNTIME, 1, {'epoch': 1}))
    writes, _ = prepare_linked(deployment, 'dataset-create', (Write(job.key, None, data),
        Write(catalog.key, None, catalog.data), Write(Key('state', 'dataset-create-quota#' + 'e' * 64),
        None, {'minute': 0, 'count': 1}), Write(event_key, None, event)), checks)
    audit = Row(event_key, 1, next(write.data for write in writes if write.key == event_key))
    return job, (catalog, audit)


def parse(job, rows, **changes):
    from proofpack.evidence.dataset_lineage import discover
    return discover(job, rows, **{'label_families': (), 'permission_families': (), 'group_rows': (),
        'deployment': 'beta', 'max_records': 200, 'max_payload_bytes': 200000, **changes})


def test_queued_job_retains_requested_intents_without_inventing_copies_or_grants():
    job, rows = family(); result = parse(job, rows)
    assert result.job.key == job.key
    assert {record.key for record in result.records} == {row.key for row in rows}
    assert any(intent.kind == 'requested_label' for intent in result.intents)
    assert not hasattr(result, 'usable')


def checks():
    return (Row(Key('state', 'user#' + uid(2)), 1, {'id': uid(2)}),
            Row(Key('state', 'session#' + uid(3)), 1, {'id': uid(3)}),
            Row(DATA, 1, {'epoch': 1, 'changed_at_ms': 100}), Row(RUNTIME, 1, {'epoch': 1}))


def access_event(kind, writes, dependencies, number, details=None, at=120, deployment='beta'):
    key = Key('events', 'access#' + uid(number))
    body = {'kind': kind, 'actor_scope': 'e' * 64, 'at_ms': at, 'session_id': uid(3)}
    if details is not None:body['details'] = details
    prepared, _ = prepare_linked(deployment, kind, (*writes, Write(key, None, body)), dependencies)
    return Row(key, 1, next(item.data for item in prepared if item.key == key))


def cancel(job, rows, number=30, repeat=False):
    data = {**job.data, 'status': 'cancelled', 'lease_token': None, 'lease_until_ms': 0, 'lease_runtime': None}
    latest = job if repeat else Row(job.key, job.revision + 1, data)
    quota = Write(Key('state', 'dataset-end-quota#' + 'e' * 64), 1 if repeat else None, {'minute': 0, 'count': 2 if repeat else 1})
    event = access_event('dataset-cancel:' + uid(1), (quota,) if repeat else (Write(job.key, job.revision, data), quota),
                         (*checks(), job), number, {'dataset_id': uid(1), 'status': 'cancelled', 'reason': 'cancelled-by-request'}, at=300)
    return latest, (*rows, event)


def reserved():
    job, rows = family()
    runtime = {'instance_id': uid(40), 'epoch': 1, 'artifact_sha256': 'b' * 64,
               'controls_sha256': 'c' * 64, 'environment': 'test'}
    latest = Row(job.key, 2, {**job.data, 'status': 'processing', 'steps_reserved': 1,
        'validation_runtime': runtime, 'lease_token': uid(41), 'lease_until_ms': 150, 'lease_runtime': runtime})
    event = access_event('dataset-step:' + uid(1), (Write(job.key, 1, latest.data),
        Write(Key('state', 'dataset-step-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
        (*checks(), job), 21)
    return latest, (*rows, event)


def failed(*, budget=False):
    job, rows = reserved();reason = 'STEP_BUDGET_EXHAUSTED' if budget else 'SOURCE_OR_PERMISSION_HELD'
    data = {**job.data, 'status': 'failed', 'failure_reason': reason}
    if not budget:data.update(lease_token=None, lease_until_ms=0, lease_runtime=None)
    latest = Row(job.key, 3, data)
    if budget:
        event = access_event('dataset-step:' + uid(1), (Write(job.key, 2, data),
            Write(Key('state', 'dataset-step-quota#' + 'e' * 64), 1, {'minute': 0, 'count': 2})),
            (*checks(), job), 22, at=200)
    else:
        key = Key('events', 'dataset-transition#' + uid(22))
        body = {'kind': 'dataset-source-failed', 'dataset_id': uid(1),
                'request_sha256': data['request_sha256'], 'index': 0, 'prior_job_revision': 2,
                'at_ms': 200, 'failure_reason': reason}
        prepared, _ = prepare_linked('beta', body['kind'], (Write(job.key, 2, data), Write(key, None, body)), checks())
        event = Row(key, 1, next(item.data for item in prepared if item.key == key))
    return latest, (*rows, event)


@pytest.mark.parametrize('state', ['cancelled', 'cancel-repeat', 'source-failed', 'budget-failed', 'cancelled-budget'])
def test_unmaterialized_terminal_history_keeps_all_transitions_and_intents(state):
    if state.startswith('cancel') and 'budget' not in state:
        job, rows = cancel(*family())
        if state == 'cancel-repeat':job, rows = cancel(job, rows, number=31, repeat=True)
    else:
        job, rows = failed(budget='budget' in state)
        if state == 'cancelled-budget':job, rows = cancel(job, rows)
    value = parse(job, rows)
    assert {r.key for r in value.records} == {r.key for r in rows}
    assert len(value.intents) == 2
    assert parse(job, tuple(reversed(rows))) == value


def test_processing_job_requires_drain_even_when_its_old_lease_looks_expired():
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    with pytest.raises(DatasetHistoryHeld):parse(*reserved())


@pytest.mark.parametrize('field,value', [
    ('kind', 'other'), ('status', 'done'), ('processed', True), ('processed', 1), ('steps_reserved', -1),
    ('configuration', 'bad'), ('data_epoch', 0), ('effective_deadline_ms', 1001),
    ('expires_at_ms', 100), ('seed_sha256', '0' * 64), ('chain_sha256', '0' * 64),
    ('request_sha256', '0' * 64), ('example_count', 2), ('failure_reason', 'SPLIT_CONFLICT'),
])
def test_invalid_queued_header_never_becomes_complete_family(field, value):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows = deepcopy(family());job.data[field] = value
    with pytest.raises(DatasetHistoryHeld):parse(job, rows)


@pytest.mark.parametrize('fault', ['catalog', 'create-event', 'duplicate', 'foreign', 'missing-binding', 'wrong-job-write'])
def test_missing_unknown_or_unlinked_queued_resources_hold(fault):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows = deepcopy(family())
    if fault == 'catalog':rows = rows[1:]
    elif fault == 'create-event':rows = rows[:1]
    elif fault == 'duplicate':rows += (rows[0],)
    elif fault == 'foreign':rows += (Row(Key('state', 'dataset-catalog#' + uid(99)), 1, {'id': uid(99)}),)
    elif fault == 'missing-binding':rows[1].data.pop('resource_bindings')
    else:next(ref for ref in rows[1].data['resource_bindings']['writes'] if ref['resource'] == job.key.resource)['sha256'] = '0' * 64
    with pytest.raises(DatasetHistoryHeld):parse(job, rows)


def test_queued_record_and_byte_bounds_include_the_job_and_are_independent():
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows = family();value = parse(job, rows)
    assert parse(job, rows, max_records=3, max_payload_bytes=value.payload_bytes) == value
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, max_records=2)
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, max_payload_bytes=value.payload_bytes - 1)


@pytest.mark.parametrize('bad', [True, 0, -1, 2**63, '100'])
@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes'])
def test_explicit_input_limits_reject_ambiguous_or_unbounded_values(field, bad):
    job, rows = family()
    with pytest.raises(ValueError):parse(job, rows, **{field: bad})


def completed(*, retired=False, derived=True, split=Split.DEVELOPMENT, declassified=False, withdrawn=False,
              count=1, restarted=False, withdrawn_at=950, declass_at=500):
    from test_label_lineage import labels
    from test_capture_lineage import DEPLOYMENT
    from proofpack.evidence.dataset_lineage import LabelInputs, PermissionInputs
    from proofpack.review.manifests import entry_key, manifest_key, group_key
    def permission_event(kind, details, writes, dependencies, number, at, actor_scope):
        assert actor_scope == 'e' * 64
        return access_event(kind, writes, dependencies, number, details, at, deployment=DEPLOYMENT)
    inspection, capture, recipe, purposes, label_rows = labels(count=1, ident=uid(10))
    label = next(row for row in label_rows if row.key.resource.startswith('label-revision#'))
    label_head = next(row for row in label_rows if row.key.resource.startswith('label#'))
    asset = next(row for row in capture if row.key.resource.startswith('asset#'))
    purpose = purposes[0];runtime = {'instance_id': uid(40), 'epoch': 1, 'artifact_sha256': 'b' * 64,
                                   'controls_sha256': 'c' * 64, 'environment': 'test'}
    notice = {'version': 'unit-v1', 'text': 'Unit optional notice',
              'sha256': hashlib.sha256(b'Unit optional notice').hexdigest()}
    scope = {'schema_version': 1, 'kind': 'selected_optional_improvement', 'configuration': 'f' * 64,
        'assets': [{'id': asset.data['id'], 'kind': 'frame', 'asset_revision': asset.revision,
            'asset_record_sha256': digest(asset.data), 'sha256': asset.data['sha256'], 'data_origin': 'synthetic',
            'purpose_id': purpose.key.resource.split('#')[1], 'purpose_revision': purpose.revision,
            'purpose_record_sha256': digest(purpose.data), 'source_permission_reference': 'synthetic-rights', 'expires_at_ms': 1000}]}
    p = {'id': uid(1000), 'status': 'preview', 'scope': scope, 'scope_sha256': digest(scope),
         'configuration': 'd' * 64, 'data_epoch': 2, 'notice': notice, 'runtime_binding': runtime,
         'owner_id': uid(2), 'session_id': uid(3), 'access_version': 1, 'created_at_ms': 100,
         'expires_at_ms': 200, 'source_expires_at_ms': 1000, 'permission_id': None}
    preview = Row(Key('state', 'improvement-preview#' + uid(1000)), 1, p)
    source_checks = (*checks()[:2], Row(DATA, 2, {'epoch': 2, 'changed_at_ms': 40}), checks()[3], asset, purpose)
    preview_event = permission_event('improvement-preview', {'preview_id': uid(1000), 'scope_sha256': digest(scope)},
        (Write(preview.key, None, p), Write(Key('state', 'improvement-preview-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
        source_checks, 1001, at=100, actor_scope='e' * 64)
    g = {'id': uid(11), 'schema_version': 1, 'scope': deepcopy(scope), 'scope_sha256': digest(scope), 'configuration': 'f' * 64,
         'documented_permission_reference': 'separate-rights', 'notice_version': notice['version'], 'notice_sha256': notice['sha256'],
         'owner_id': uid(2), 'created_at_ms': 150, 'notice_text': notice['text'], 'expires_at_ms': 900,
         'authority_basis': 'owner_attestation', 'rights_independently_verified': False, 'derived_review_metadata_allowed': derived,
         'optional_improvement': True, 'optional_publicity': False, 'physical_truth_verified': False, 'independence_verified': False}
    g['sha256'] = digest(g)
    grant = Row(Key('state', 'improvement-grant#' + uid(11)), 1, g)
    permission = Row(Key('state', 'improvement-permission#' + uid(11)), 1,
        {'id': uid(11), 'grant_sha256': g['sha256'], 'withdrawn': False})
    latest_preview = Row(preview.key, 2, {**p, 'status': 'committed', 'permission_id': uid(11)})
    confirmed = permission_event('improvement-confirm', {'permission_id': uid(11), 'scope_sha256': digest(scope), 'grant_sha256': g['sha256']},
        (Write(preview.key, 1, latest_preview.data), Write(grant.key, None, g), Write(permission.key, None, permission.data),
         Write(DATA, 2, {'epoch': 3, 'changed_at_ms': 150}), Write(Key('state', 'improvement-confirm-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
        (*source_checks, preview), 1002, at=150, actor_scope='e' * 64)
    upstream = {'deployment': DEPLOYMENT, 'label_families': (LabelInputs(inspection, label_rows, capture, recipe, purposes),),
                'permission_families': (PermissionInputs(latest_preview, (grant, permission, preview_event, confirmed)),)}
    assert count in (1, 2) and (not restarted or count == 2)
    initial, rows = family(data_epoch=3, created=200, data_changed=150, deployment=DEPLOYMENT, split=split,
                           extra_labels=() if count == 1 else (uid(20),))
    authority = deepcopy(initial.data['processing_authority']);authority['body']['issued_at_ms'] = 300
    lease = Row(initial.key, 2, {**initial.data, 'status': 'processing', 'steps_reserved': 1,
        'validation_runtime': runtime, 'lease_token': uid(41), 'lease_until_ms': 1000, 'lease_runtime': runtime,
        'processing_authority': authority})
    owner_checks = (*checks()[:2], Row(DATA, 3, {'epoch': 3, 'changed_at_ms': 150}), checks()[3])
    reserved_event = access_event('dataset-step:' + uid(1), (Write(lease.key, 1, lease.data),
        Write(Key('state', 'dataset-step-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})), owner_checks, 21, at=300, deployment=DEPLOYMENT)
    groups = [];assigned = []
    for category, name in (('kit', 'kit_group'), ('session', 'session_group'), ('operator', 'operator_group')):
        ident = digest({'category': category, 'group': label.data['source_context'][name]})
        value = {'id': ident, 'category': category, 'split': split.value, 'generation': 1,
                 'original_split': split.value, 'created_at_ms': 320};value['sha256'] = digest(value)
        groups.append(Row(group_key(ident), 1, value));assigned.append({'id': ident, 'category': category, 'generation': 1})
    content = {'label_id': uid(10), 'label_revision': 1, 'label_sha256': label.data['sha256'],
        'source_context_sha256': label.data['source_context_sha256'], 'split': split.value, 'data_origin': 'synthetic',
        'sources': [{'asset_id': asset.data['id'], 'sha256': asset.data['sha256']}],
        'permissions': [{'id': uid(11), 'state_version': 1, 'grant_sha256': g['sha256']}], 'groups': assigned,
        'physical_truth_verified': False, 'independence_verified': False,
        **{key: label.data[key] for key in ('outcome', 'ground_truth_counts', 'method', 'duration_ms')},
        'prior_exposure_unknown': True, 'independent_benchmark_qualified': False}
    entry = {'schema_version': 1, 'dataset_id': uid(1), 'index': 0, 'content': content,
             'content_sha256': digest(content), 'previous_chain_sha256': initial.data['seed_sha256']};entry['chain_sha256'] = digest(entry)
    example = Row(entry_key(uid(1), 0), 1, entry)
    data = {**lease.data, 'status': 'completed' if count == 1 else 'queued', 'processed': 1, 'chain_sha256': entry['chain_sha256'],
            'effective_deadline_ms': 900, 'splits': {part.value: int(part == split) for part in Split},
            'lease_token': None, 'lease_until_ms': 0, 'lease_runtime': None}
    sealed = {key: data[key] for key in ('id', 'request_sha256', 'example_count', 'chain_sha256', 'seed_sha256', 'configuration',
        'artifact_sha256', 'controls_sha256', 'environment', 'data_epoch', 'created_at_ms', 'validation_runtime', 'splits')}
    sealed.update(schema_version=1, expires_at_ms=900, prior_exposure_unknown=True, independent_benchmark_qualified=False);sealed['sha256'] = digest(sealed)
    seal = Row(manifest_key(uid(1)), 1, sealed) if count == 1 else None
    data['manifest_sha256'] = sealed['sha256'] if seal is not None else None;job = Row(initial.key, 3, data)
    key = Key('events', 'dataset-transition#' + uid(22));body = {'kind': 'dataset-example-committed', 'dataset_id': uid(1),
        'request_sha256': data['request_sha256'], 'index': 0, 'prior_job_revision': 2, 'at_ms': 320}
    writes, _ = prepare_linked(DEPLOYMENT, body['kind'], (Write(job.key, 2, data), Write(example.key, None, example.data),
        *((Write(seal.key, None, sealed),) if seal is not None else ()),
        *(Write(group.key, None, group.data) for group in groups), Write(key, None, body)),
        (*owner_checks, label, label_head, grant, permission, asset, purpose))
    committed_event = Row(key, 1, next(write.data for write in writes if write.key == key))
    rows = (*rows, reserved_event, example, *((seal,) if seal is not None else ()), committed_event)
    if restarted:
        new_runtime = {**runtime, 'instance_id': uid(42), 'epoch': 2}
        auth = deepcopy(job.data['processing_authority']);auth['body']['issued_at_ms'] = 400
        leased = Row(job.key, 4, {**job.data, 'status': 'processing', 'steps_reserved': 2,
            'processed': 0, 'chain_sha256': job.data['seed_sha256'], 'splits': {part.value: 0 for part in Split},
            'effective_deadline_ms': job.data['expires_at_ms'], 'validation_runtime': new_runtime,
            'lease_token': uid(43), 'lease_until_ms': 1000, 'lease_runtime': new_runtime, 'processing_authority': auth})
        new_checks = (*owner_checks[:3], Row(RUNTIME, 2, {'epoch': 2}))
        again = access_event('dataset-step:' + uid(1), (Write(job.key, 3, leased.data),
            Write(Key('state', 'dataset-step-quota#' + 'e' * 64), 1, {'minute': 0, 'count': 2})),
            (*new_checks, job), 23, at=400, deployment=DEPLOYMENT)
        terminal = Row(job.key, 5, {**leased.data, 'status': 'failed', 'failure_reason': 'SOURCE_OR_PERMISSION_HELD',
                                  'lease_token': None, 'lease_until_ms': 0, 'lease_runtime': None})
        key = Key('events', 'dataset-transition#' + uid(24));event = {'kind': 'dataset-source-failed',
            'dataset_id': uid(1), 'request_sha256': job.data['request_sha256'], 'index': 0,
            'prior_job_revision': 4, 'at_ms': 420, 'failure_reason': 'SOURCE_OR_PERMISSION_HELD'}
        writes, _ = prepare_linked(DEPLOYMENT, event['kind'], (Write(job.key, 4, terminal.data), Write(key, None, event)), new_checks)
        failed = Row(key, 1, next(write.data for write in writes if write.key == key))
        job = terminal;rows += (again, failed)
    if retired:
        assert count == 1 and not restarted
        latest = Row(job.key, 4, {**job.data, 'status': 'retired'})
        ended = access_event('dataset-retire:' + uid(1), (Write(job.key, 3, latest.data),
            Write(DATA, 3, {'epoch': 4, 'changed_at_ms': 500}),
            Write(Key('state', 'dataset-end-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
            (*owner_checks, job), 30, {'dataset_id': uid(1), 'status': 'retired', 'reason': 'benchmark-retired'}, at=500, deployment=DEPLOYMENT)
        job = latest;rows += (ended,)
    if declassified:
        assert split != Split.DEVELOPMENT
        revised = []
        for group in groups:
            value = {**group.data, 'split': 'DEVELOPMENT', 'generation': 2,
                     'reason': 'used-in-development', 'changed_at_ms': declass_at}
            value['sha256'] = digest({key: value for key, value in value.items() if key != 'sha256'})
            revised.append(Row(group.key, 2, value))
        groups = revised
    if withdrawn:
        assert not retired and not declassified
        latest = Row(permission.key, 2, {**permission.data, 'withdrawn': True, 'withdrawn_at_ms': withdrawn_at})
        event = permission_event('improvement-withdraw:' + uid(11), {'permission_id': uid(11), 'withdrawn': True},
            (Write(permission.key, 1, latest.data), Write(DATA, 3, {'epoch': 4, 'changed_at_ms': withdrawn_at}),
             Write(Key('state', 'improvement-withdraw-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
            (*owner_checks, grant, permission), 1003, at=withdrawn_at, actor_scope='e' * 64)
        upstream['permission_families'] = (PermissionInputs(latest_preview, (grant, latest, preview_event, confirmed, event)),)
    return job, rows, {**upstream, 'group_rows': tuple(groups)}


@pytest.mark.parametrize('retired', [False, True])
def test_complete_copied_family_revalidates_raw_label_and_permission_history(retired):
    job, rows, sources = completed(retired=retired)
    value = parse(job, rows, **sources)
    assert {record.key for record in value.records} == {row.key for row in rows}
    assert not ({record.key for record in value.records} & {record.key for record in value.dependencies})
    assert parse(job, tuple(reversed(rows)), **sources) == value


def resign_copies(job, rows):
    """Keep the forged copy's own hashes consistent; source families stay intact."""
    entries = sorted((r for r in rows if r.key.resource.startswith('dataset-example#')), key=lambda r: r.data['index'])
    previous = job.data['seed_sha256']
    for row in entries:
        row.data['content_sha256'] = digest(row.data['content'])
        row.data['previous_chain_sha256'] = previous
        row.data['chain_sha256'] = digest({key: value for key, value in row.data.items() if key != 'chain_sha256'})
        previous = row.data['chain_sha256']
    job.data['chain_sha256'] = previous
    seal = next(r for r in rows if r.key.resource.startswith('dataset-manifest#'))
    seal.data['chain_sha256'] = previous
    seal.data['sha256'] = digest({key: value for key, value in seal.data.items() if key != 'sha256'})
    job.data['manifest_sha256'] = seal.data['sha256']
    current = {row.key: row for row in (job, *rows)}
    for row in rows:
        if row.key.table != 'events':continue
        for ref in row.data['resource_bindings']['writes']:
            key = Key(ref['table'], ref['resource']);target = current.get(key)
            if target is not None and ref['revision'] == target.revision:
                ref['sha256'] = digest(target.data)


@pytest.mark.parametrize('field,value', [
    ('label_id', uid(99)), ('label_revision', 2), ('label_sha256', '0' * 64),
    ('source_context_sha256', '0' * 64), ('data_origin', 'physical'), ('outcome', 'unresolved'),
    ('ground_truth_counts', [{'part_class': 'washer', 'count': 2}]), ('method', 'reference_comparison'),
    ('duration_ms', 1001), ('physical_truth_verified', True), ('independence_verified', True),
    ('prior_exposure_unknown', False), ('independent_benchmark_qualified', True),
])
def test_self_consistent_changed_copy_cannot_override_its_immutable_source(field, value):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed()
    example = next(row for row in rows if row.key.resource.startswith('dataset-example#'))
    example.data['content'][field] = value;resign_copies(job, rows)
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


@pytest.mark.parametrize('which', ['label', 'capture', 'permission'])
def test_raw_source_families_are_revalidated_instead_of_trusting_a_supplied_wrapper(which):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed()
    if which == 'label':sources['label_families'][0].rows[0].data['note'] = 'altered source'
    elif which == 'capture':sources['label_families'][0].inspection.data['state'] = 'LIVE'
    else:sources['permission_families'][0].rows[0].data['derived_review_metadata_allowed'] = False
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


@pytest.mark.parametrize('missing', ['label_families', 'permission_families', 'group_rows'])
def test_materialized_copies_require_their_complete_provided_source_inputs(missing):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed();sources[missing] = ()
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


def test_operational_image_grant_without_derived_metadata_never_validates_a_copy():
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed(derived=False)
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


def test_withdrawn_expired_permission_can_describe_earlier_copy_without_restoring_a_grant():
    job, rows, sources = completed(withdrawn=True)
    value = parse(job, rows, **sources)
    permission = Key('state', 'improvement-permission#' + uid(11))
    assert {ref.revision for ref in value.dependencies if ref.key == permission} == {1, 2}
    assert not hasattr(value, 'usable')


def test_shared_declassification_preserves_original_frozen_copy_and_both_group_versions():
    job, rows, sources = completed(split=Split.FROZEN_TEST, declassified=True)
    value = parse(job, rows, **sources)
    assert job.data['splits']['FROZEN_TEST'] == 1
    for group in sources['group_rows']:
        assert group.key not in {ref.key for ref in value.records}
        assert {ref.revision for ref in value.dependencies if ref.key == group.key} == {1, 2}


@pytest.mark.parametrize('at', [199, 901])
def test_copy_commit_cannot_precede_job_or_outlive_its_optional_source_window(at):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed()
    next(row for row in rows if row.data.get('kind') == 'dataset-example-committed').data['at_ms'] = at
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


def test_budget_failure_cannot_be_invented_without_any_reserved_step():
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows = family();data = {**job.data, 'status': 'failed', 'failure_reason': 'STEP_BUDGET_EXHAUSTED'}
    latest = Row(job.key, 2, data)
    event = access_event('dataset-step:' + uid(1), (Write(job.key, 1, data),
        Write(Key('state', 'dataset-step-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})), checks(), 21)
    with pytest.raises(DatasetHistoryHeld):parse(latest, (*rows, event))


def accessed(kind='dataset_examples_read', *, retired=False, at=350, **history):
    job, rows, sources = completed(retired=retired, **history)
    historical = job if not retired else Row(job.key, job.revision - 1, {**job.data, 'status': 'completed'})
    seal = next(row for row in rows if row.key.resource.startswith('dataset-manifest#'))
    example = next(row for row in rows if row.key.resource.startswith('dataset-example#'))
    key = Key('events', 'dataset-access#' + uid(60))
    data = {'kind': kind, 'dataset_id': uid(1), 'manifest_sha256': seal.data['sha256'],
            'user_id': uid(2), 'access_version': 1, 'first_index': 0, 'last_index': 0,
            'at_ms': at, 'prior_exposure_unknown': True}
    dependencies = (*checks(), historical, seal, example)
    if at >= 1000:
        # A later authorized reader uses a new session; the job's original
        # processing authority remains expired and is never renewed here.
        dependencies = tuple(row for row in dependencies if not row.key.resource.startswith('session#'))
        dependencies += (Row(Key('state', 'session#' + uid(4)), 1, {'id': uid(4), 'user_id': uid(2), 'expires_at_ms': 2000}),)
    if kind in {'evaluation_examples_read', 'vision_measurement_case_admitted'}:
        data['consumer_job_id'] = uid(90)
        dependencies += (Row(job_key(uid(90)), 1, {'id': uid(90), 'kind': 'policy_evaluation'}),)
    prepared, _ = prepare_linked(sources['deployment'], kind, (Write(key, None, data),
        Write(Key('state', 'dataset-read-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})), dependencies)
    audit = Row(key, 1, next(write.data for write in prepared if write.key == key))
    return job, (*rows, audit), sources


@pytest.mark.parametrize('change', ['withdrawal', 'declassification'])
@pytest.mark.parametrize('cutoff', [319, 320])
def test_copy_change_time_is_inclusive_only_with_exact_historical_versions(change, cutoff):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    history = ({'withdrawn': True, 'withdrawn_at': cutoff} if change == 'withdrawal' else
               {'split': Split.FROZEN_TEST, 'declassified': True, 'declass_at': cutoff})
    job, rows, sources = completed(**history)
    if cutoff == 319:
        with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)
    else:
        assert parse(job, rows, **sources).job.key == job.key


@pytest.mark.parametrize('change', ['withdrawal', 'declassification'])
@pytest.mark.parametrize('at', [350, 351])
def test_prior_admission_same_millisecond_is_history_but_later_admission_is_held(change, at):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    history = ({'withdrawn': True, 'withdrawn_at': 350} if change == 'withdrawal' else
               {'split': Split.FROZEN_TEST, 'declassified': True, 'declass_at': 350})
    job, rows, sources = accessed(at=at, **history)
    if at == 351:
        with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)
    else:
        assert parse(job, rows, **sources).job.key == job.key


def thousand_copied_histories():
    """Synthetic metadata capacity, with every raw label revalidated; no I/O."""
    from dataclasses import replace
    from test_label_lineage import labels
    from proofpack.review.manifests import entry_key, manifest_key
    template_job, template_rows, sources = completed()
    source = sources['label_families'][0]
    all_labels = list(source.rows)
    for number in range(999):
        inspection, capture, recipe, purposes, rows = labels(count=1, ident=uid(10000 + number), epoch_start=2 + number)
        assert inspection == source.inspection and capture == source.capture_rows
        assert recipe == source.recipe and purposes == source.purpose_rows
        # Every preceding label writes DATA at time 111. Preserve that exact
        # historical payload instead of the small helper's initial time 100.
        for row in rows:
            if row.key.table == 'events':
                reference = next(ref for ref in row.data['resource_bindings']['checks'] if ref['resource'] == DATA.resource)
                reference['sha256'] = digest({'epoch': 2 + number, 'changed_at_ms': 111})
        all_labels.extend(rows)
    source = replace(source, rows=tuple(all_labels))
    sources = {**sources, 'label_families': (source,)}
    revisions = [row for row in all_labels if row.key.resource.startswith('label-revision#')]
    heads = {row.data['id']: row for row in all_labels if row.key.resource.startswith('label#')}
    job, initial_rows = family(data_epoch=1002, created=200, data_changed=150,
        deployment=sources['deployment'], extra_labels=tuple(row.data['id'] for row in revisions[1:]))
    rows = list(initial_rows)
    permission_rows = sources['permission_families'][0].rows
    grant = next(row for row in permission_rows if row.key.resource.startswith('improvement-grant#'))
    permission = next(row for row in permission_rows if row.key.resource.startswith('improvement-permission#'))
    asset = next(row for row in source.capture_rows if row.key.resource.startswith('asset#'))
    purpose = source.purpose_rows[0]
    previous_preview = sources['permission_families'][0].preview
    preview = Row(previous_preview.key, 1, {**previous_preview.data, 'status': 'preview', 'permission_id': None,
                  'created_at_ms': 120, 'data_epoch': 1001})
    committed_preview = Row(preview.key, 2, {**preview.data, 'status': 'committed', 'permission_id': permission.data['id']})
    preview_checks = (*checks()[:2], Row(DATA, 1001, {'epoch': 1001, 'changed_at_ms': 111}), checks()[3], asset, purpose)
    preview_event = access_event('improvement-preview', (Write(preview.key, None, preview.data),
        Write(Key('state', 'improvement-preview-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
        preview_checks, 1001, {'preview_id': preview.data['id'], 'scope_sha256': preview.data['scope_sha256']},
        at=120, deployment=sources['deployment'])
    confirmed_event = access_event('improvement-confirm', (Write(preview.key, 1, committed_preview.data),
        Write(grant.key, None, grant.data), Write(permission.key, None, permission.data),
        Write(DATA, 1001, {'epoch': 1002, 'changed_at_ms': 150}),
        Write(Key('state', 'improvement-confirm-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1})),
        (*preview_checks, preview), 1002, {'permission_id': permission.data['id'],
        'scope_sha256': grant.data['scope_sha256'], 'grant_sha256': grant.data['sha256']},
        at=150, deployment=sources['deployment'])
    sources = {**sources, 'permission_families': (replace(sources['permission_families'][0],
        preview=committed_preview, rows=(grant, permission, preview_event, confirmed_event)),)}
    owner_checks = (*checks()[:2], Row(DATA, 1002, {'epoch': 1002, 'changed_at_ms': 150}), checks()[3])
    content_template = next(row.data['content'] for row in template_rows if row.key.resource.startswith('dataset-example#'))
    seal = None
    for index, label in enumerate(revisions):
        authority = deepcopy(job.data['processing_authority']);authority['body']['issued_at_ms'] = 300
        lease = Row(job.key, job.revision + 1, {**job.data, 'status': 'processing', 'steps_reserved': index + 1,
            'validation_runtime': template_job.data['validation_runtime'], 'lease_token': uid(9000000 + index),
            'lease_until_ms': 1000, 'lease_runtime': template_job.data['validation_runtime'], 'processing_authority': authority})
        reserved = access_event('dataset-step:' + uid(1), (Write(job.key, job.revision, lease.data),
            Write(Key('state', 'dataset-step-quota#' + 'e' * 64), None if index == 0 else index,
                  {'minute': 0, 'count': index + 1})), (*owner_checks, job), 8000000 + index, at=300,
            deployment=sources['deployment'])
        content = {**deepcopy(content_template), 'label_id': label.data['id'], 'label_sha256': label.data['sha256']}
        entry = {'schema_version': 1, 'dataset_id': uid(1), 'index': index, 'content': content,
                 'content_sha256': digest(content), 'previous_chain_sha256': job.data['chain_sha256']}
        entry['chain_sha256'] = digest(entry)
        example = Row(entry_key(uid(1), index), 1, entry)
        data = {**lease.data, 'status': 'completed' if index == 999 else 'queued', 'processed': index + 1,
                'chain_sha256': entry['chain_sha256'], 'effective_deadline_ms': 900,
                'splits': {part.value: index + 1 if part == Split.DEVELOPMENT else 0 for part in Split},
                'lease_token': None, 'lease_until_ms': 0, 'lease_runtime': None}
        writes = [Write(example.key, None, example.data)]
        if index == 0:
            writes.extend(Write(group.key, None, group.data) for group in sources['group_rows'])
        if index == 999:
            sealed = {key: data[key] for key in ('id', 'request_sha256', 'example_count', 'chain_sha256', 'seed_sha256',
                'configuration', 'artifact_sha256', 'controls_sha256', 'environment', 'data_epoch',
                'created_at_ms', 'validation_runtime', 'splits')}
            sealed.update(schema_version=1, expires_at_ms=900, prior_exposure_unknown=True, independent_benchmark_qualified=False)
            sealed['sha256'] = digest(sealed);seal = Row(manifest_key(uid(1)), 1, sealed)
            data['manifest_sha256'] = sealed['sha256'];writes.append(Write(seal.key, None, sealed))
        latest = Row(job.key, lease.revision + 1, data)
        key = Key('events', 'dataset-transition#' + uid(7000000 + index))
        body = {'kind': 'dataset-example-committed', 'dataset_id': uid(1), 'request_sha256': data['request_sha256'],
                'index': index, 'prior_job_revision': lease.revision, 'at_ms': 320}
        prepared, _ = prepare_linked(sources['deployment'], body['kind'],
            (Write(job.key, lease.revision, latest.data), *writes, Write(key, None, body)),
            (*owner_checks, label, heads[label.data['id']], grant, permission, asset, purpose,
             *(sources['group_rows'] if index else ())))
        rows.extend((reserved, example, Row(key, 1, next(write.data for write in prepared if write.key == key))))
        job = latest
    rows.append(seal)
    return job, tuple(rows), sources


def test_thousand_complete_copied_histories_reach_last_entry_and_hold_missing_whole_peers():
    from dataclasses import replace
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = thousand_copied_histories()
    limits = {'max_records': 10000, 'max_payload_bytes': 64000000}
    value = parse(job, rows, **sources, **limits)
    examples = [ref for ref in value.records if ref.key.resource.startswith('dataset-example#')]
    assert len(examples) == 1000 and any(ref.key.resource.endswith('#0999') for ref in examples)
    assert value.job.revision == 2001
    for index in (500, 999):
        missing = tuple(row for row in rows if not row.key.resource.endswith('#' + str(index).zfill(4)))
        with pytest.raises(DatasetHistoryHeld):parse(job, missing, **sources, **limits)
    source = sources['label_families'][0]
    missing_label = uid(10499)
    retained = tuple(row for row in source.rows if row.data.get('id') != missing_label
                     and row.data.get('details', {}).get('label_id') != missing_label)
    with pytest.raises(DatasetHistoryHeld):
        parse(job, rows, **{**sources, 'label_families': (replace(source, rows=retained),)}, **limits)


def test_source_position_bounds_count_matching_duplicates_before_reconciliation():
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed()
    sources = {**sources, 'label_families': sources['label_families'] * 2}
    incoming = [job, *rows, *sources['group_rows']]
    for family in sources['label_families']:
        incoming.extend((family.inspection, family.recipe, *family.rows, *family.capture_rows, *family.purpose_rows))
    for family in sources['permission_families']:
        incoming.extend((family.preview, *family.rows))
    count = len(incoming);size = sum(len(canonical(row.data).encode()) for row in incoming)
    value = parse(job, rows, **sources, max_records=count, max_payload_bytes=size)
    assert value.payload_bytes == size
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources, max_records=count - 1, max_payload_bytes=size)
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources, max_records=count, max_payload_bytes=size - 1)


@pytest.mark.parametrize('operation', ['dataset-create', 'dataset-step', 'dataset-source-failed'])
@pytest.mark.parametrize('at', [99, 1000])
def test_admission_and_commit_audits_cannot_precede_job_or_reach_original_expiry(operation, at):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows = family() if operation == 'dataset-create' else failed()
    event = next(row for row in rows if row.data.get('kind', '').split(':')[0] == operation)
    event.data['at_ms'] = at
    with pytest.raises(DatasetHistoryHeld):parse(job, rows)


@pytest.mark.parametrize('kind', ['dataset_request_read', 'dataset_examples_read', 'evaluation_examples_read', 'vision_measurement_case_admitted'])
def test_admitted_access_and_consumer_links_retain_attempt_history(kind):
    job, rows, sources = accessed(kind)
    value = parse(job, rows, **sources)
    assert rows[-1].key in {ref.key for ref in value.records}
    assert not hasattr(value, 'delivered')


def test_old_completed_read_does_not_need_the_current_retired_job_payload_hash():
    job, rows, sources = accessed(retired=True)
    assert parse(job, rows, **sources).job.revision == 4


def test_expired_request_metadata_read_is_not_misclassified_as_new_example_delivery():
    job, rows, sources = accessed('dataset_request_read', at=1200)
    assert parse(job, rows, **sources).job.key == job.key


@pytest.mark.parametrize('fault', ['future-job-check', 'changed-current-job-hash', 'malformed-quota', 'missing-user', 'wrong-user-id'])
def test_access_audit_cannot_claim_unreconciled_job_or_actor_references(fault):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = accessed();data = rows[-1].data;binding = data['resource_bindings']
    if fault == 'future-job-check':
        next(ref for ref in binding['checks'] if ref['resource'] == job.key.resource)['revision'] += 1
    elif fault == 'changed-current-job-hash':
        next(ref for ref in binding['checks'] if ref['resource'] == job.key.resource)['sha256'] = '0' * 64
    elif fault == 'malformed-quota':binding['writes'][0]['resource'] = 'dataset-read-quota#not-a-scope'
    elif fault == 'missing-user':binding['checks'] = [ref for ref in binding['checks'] if not ref['resource'].startswith('user#')]
    else:data['user_id'] = uid(99)
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


@pytest.mark.parametrize('restarted', [False, True])
def test_retained_prefix_and_unmaterialized_intents_survive_runtime_revalidation(restarted):
    job, rows, sources = completed(count=2, restarted=restarted)
    value = parse(job, rows, **sources)
    retained = [record for record in value.records if record.key.resource.startswith('dataset-example#')]
    assert len(retained) == 1
    assert job.data['processed'] == (0 if restarted else 1)
    assert job.data['steps_reserved'] == (2 if restarted else 1)
    assert any(intent.target == Key('state', 'label-revision#' + uid(20) + '#1') for intent in value.intents)


def test_runtime_restart_cannot_hide_an_earlier_materialized_prefix():
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = completed(count=2, restarted=True)
    rows = tuple(row for row in rows if not row.key.resource.startswith('dataset-example#'))
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


@pytest.mark.parametrize('fault', ['before-job', 'expired-seal', 'processing-root-reference'])
def test_example_access_needs_its_actual_completed_version_and_original_window(fault):
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    job, rows, sources = accessed();data = rows[-1].data
    if fault == 'before-job':data['at_ms'] = 199
    elif fault == 'expired-seal':data['at_ms'] = 900
    else:
        ref = next(ref for ref in data['resource_bindings']['checks'] if ref['resource'] == job.key.resource)
        ref['revision'] = 2;ref['sha256'] = '0' * 64
    with pytest.raises(DatasetHistoryHeld):parse(job, rows, **sources)


@pytest.mark.parametrize('materialized', [False, True])
def test_stored_integral_decimal_metadata_has_the_same_family_as_python_integer_fixtures(materialized):
    from decimal import Decimal
    from dataclasses import fields, is_dataclass
    if materialized:job, rows, sources = completed()
    else:job, rows = family();sources = {}
    expected = parse(job, rows, **sources)
    def stored(value):
        if type(value) is int:return Decimal(value)
        if type(value) is dict:return {key: stored(item) for key, item in value.items()}
        if type(value) is list:return [stored(item) for item in value]
        if type(value) is tuple:return tuple(stored(item) for item in value)
        if isinstance(value, Row):return Row(value.key, value.revision, stored(value.data))
        if is_dataclass(value):return type(value)(**{field.name: stored(getattr(value, field.name)) for field in fields(value)})
        return value
    assert parse(stored(job), stored(rows), **stored(sources)) == expected
