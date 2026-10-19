"""Supplied shared metadata histories, not ownership, permissions or truth."""
from copy import deepcopy
from dataclasses import replace
import pytest
from test_dataset_lineage import completed, checks, access_event, uid
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Row, Key, Write
from proofpack.review.datasets import Split
from proofpack.runtime.control import DATA


def family(*, split=Split.DEVELOPMENT, changed=False, repeats=0, retired=False, changed_at=500, category='kit'):
    from proofpack.evidence.dataset_group_lineage import DatasetInputs
    job, rows, sources = completed(split=split, declassified=changed, retired=retired, declass_at=changed_at)
    group = next(row for row in sources['group_rows'] if row.data['category'] == category)
    inputs = (DatasetInputs(job, rows, sources['label_families'], sources['permission_families'], sources['group_rows']),)
    history = []
    base_checks = (*checks()[:2], checks()[3])
    if changed:
        first = {key: group.data[key] for key in ('id', 'category', 'original_split', 'created_at_ms')}
        first.update(split=group.data['original_split'], generation=1);first['sha256'] = digest(first)
        old = Row(group.key, 1, first)
        key = Key('events', 'dataset-declassification#' + uid(2000))
        detail = {'group_id': group.data['id'], 'from_split': split.value, 'to_split': 'DEVELOPMENT',
                  'at_ms': changed_at, 'reason': group.data['reason']}
        outer = access_event('dataset-declassify:' + group.data['id'], (
            Write(group.key, 1, group.data), Write(DATA, 3, {'epoch': 4, 'changed_at_ms': changed_at}),
            Write(Key('state', 'dataset-end-quota#' + 'e' * 64), None, {'minute': 0, 'count': 1}),
            Write(key, None, detail)), (*base_checks, Row(DATA, 3, {'epoch': 3, 'changed_at_ms': 150}), old),
            2001, {'group_id': group.data['id'], 'to_split': 'DEVELOPMENT', 'reason': group.data['reason']},
            at=changed_at, deployment=sources['deployment'])
        history.extend((outer, Row(key, 1, {**detail, 'resource_bindings': deepcopy(outer.data['resource_bindings'])})))
    for index in range(repeats):
        count = index + int(changed)
        event = access_event('dataset-declassify:' + group.data['id'], (
            Write(Key('state', 'dataset-end-quota#' + 'e' * 64), count or None, {'minute': 0, 'count': count + 1}),),
            (*base_checks, Row(DATA, 4 if changed else 3,
             {'epoch': 4 if changed else 3, 'changed_at_ms': changed_at if changed else 150}), group),
            2100 + index, {'group_id': group.data['id'], 'to_split': 'DEVELOPMENT', 'reason': 'repeat-private-reason'},
            at=max(600, changed_at) + index, deployment=sources['deployment'])
        history.append(event)
    return group, tuple(history), inputs, sources['deployment']


def parse(group, rows, datasets, deployment, **limits):
    from proofpack.evidence.dataset_group_lineage import discover
    return discover(group, rows, datasets=datasets, deployment=deployment,
                    **({'max_records': 10000, 'max_payload_bytes': 16000000} | limits))


def test_original_group_creation_is_shared_history_not_removal_authority():
    group, rows, datasets, deployment = family()
    result = parse(group, rows, datasets, deployment)
    assert result.group.key == group.key
    assert datasets[0].job.key in {ref.key for ref in result.dependencies}
    assert len(result.history) == 1
    assert not hasattr(result, 'owned') and not hasattr(result, 'usable')


@pytest.mark.parametrize('split,changed,repeats', [
    (Split.DEVELOPMENT, False, 2), (Split.FROZEN_TEST, False, 0),
    (Split.FROZEN_TEST, True, 0), (Split.FROZEN_TEST, True, 2),
    (Split.VALIDATION, True, 1),
])
def test_known_generations_and_repeated_acknowledgments_retain_shared_history(split, changed, repeats):
    group, rows, datasets, deployment = family(split=split, changed=changed, repeats=repeats)
    value = parse(group, rows, datasets, deployment)
    assert len(value.versions) == 1 + int(changed)
    assert len(value.history) == 1 + 2 * int(changed) + repeats
    assert value.versions[0].revision == 1 and value.versions[-1].revision == group.revision
    assert parse(group, tuple(reversed(rows)), datasets, deployment) == value
    assert 'repeat-private-reason' not in repr(value)


def test_retired_dataset_and_later_expired_source_history_do_not_reset_group():
    group, rows, datasets, deployment = family(retired=True)
    assert parse(group, rows, datasets, deployment).group.revision == 1
    group, rows, datasets, deployment = family(split=Split.FROZEN_TEST, changed=True, changed_at=1200, repeats=1)
    assert parse(group, rows, datasets, deployment).group.revision == 2


@pytest.mark.parametrize('missing', ['datasets', 'detail', 'access', 'creator'])
def test_missing_whole_creator_or_transition_peers_hold(missing):
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    group, rows, datasets, deployment = family(split=Split.FROZEN_TEST, changed=True)
    if missing == 'datasets':datasets = ()
    elif missing == 'detail':rows = tuple(row for row in rows if not row.key.resource.startswith('dataset-declassification#'))
    elif missing == 'access':rows = tuple(row for row in rows if not row.key.resource.startswith('access#'))
    else:datasets = (replace(datasets[0], rows=tuple(row for row in datasets[0].rows if row.data.get('kind') != 'dataset-example-committed')),)
    with pytest.raises(GroupHistoryHeld):parse(group, rows, datasets, deployment)


@pytest.mark.parametrize('fault', ['old-hash', 'pair-hash', 'extra-write', 'missing-data-write', 'quota-scope',
                                 'missing-session', 'detail-reason', 'detail-before-change', 'access-before-change',
                                 'detail-after-access', 'foreign-operation', 'unknown-schema', 'duplicate-peer'])
def test_corrupt_or_unreconciled_declassification_never_becomes_complete(fault):
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    group, rows, datasets, deployment = family(split=Split.FROZEN_TEST, changed=True)
    access, detail = rows
    if fault == 'detail-reason':detail.data['reason'] = 'different-reason'
    elif fault == 'detail-before-change':detail.data['at_ms'] = 499
    elif fault == 'access-before-change':access.data['at_ms'] = 499
    elif fault == 'detail-after-access':detail.data['at_ms'] = 501
    elif fault == 'unknown-schema':access.data['unexpected'] = 'not-supported'
    elif fault == 'duplicate-peer':rows += (replace(access, key=Key('events', 'access#' + uid(5000))),)
    else:
        for row in rows:
            binding = row.data['resource_bindings']
            if fault == 'old-hash':next(ref for ref in binding['checks'] if ref['resource'] == group.key.resource)['sha256'] = '0' * 64
            elif fault == 'pair-hash' and row is detail:binding['checks'][0]['sha256'] = '0' * 64
            elif fault == 'extra-write':
                binding['writes'].append({'table': 'state', 'resource': 'recipe#' + uid(99), 'revision': 1, 'previous_revision': None, 'sha256': '0' * 64})
                binding['writes'].sort(key=lambda ref: (ref['table'], ref['resource']))
            elif fault == 'missing-data-write':binding['writes'] = [ref for ref in binding['writes'] if ref['resource'] != DATA.resource]
            elif fault == 'quota-scope':next(ref for ref in binding['writes'] if ref['resource'].startswith('dataset-end-quota#'))['resource'] = 'dataset-end-quota#' + 'f' * 64
            elif fault == 'missing-session':binding['checks'] = [ref for ref in binding['checks'] if not ref['resource'].startswith('session#')]
            elif fault == 'foreign-operation':binding['operation'] = 'dataset-declassify:' + 'f' * 64
    with pytest.raises(GroupHistoryHeld):parse(group, rows, datasets, deployment)


@pytest.mark.parametrize('fault', ['source-label', 'source-capture', 'source-permission', 'processing', 'foreign-group', 'erased-group'])
def test_raw_inputs_are_revalidated_and_erased_or_active_sources_hold(fault):
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    from proofpack.evidence.repository import ErasureMarker
    group, rows, datasets, deployment = family()
    if fault == 'source-label':datasets[0].label_families[0].rows[0].data['note'] = 'tampered source'
    elif fault == 'source-capture':datasets[0].label_families[0].inspection.data['state'] = 'LIVE'
    elif fault == 'source-permission':datasets[0].permission_families[0].rows[0].data['derived_review_metadata_allowed'] = False
    elif fault == 'processing':datasets[0].job.data['status'] = 'processing'
    elif fault == 'foreign-group':datasets = (replace(datasets[0], group_rows=datasets[0].group_rows[1:]),)
    else:group = ErasureMarker(group.key, group.revision, 'a' * 64, 'b' * 64)
    with pytest.raises(GroupHistoryHeld):parse(group, rows, datasets, deployment)


def test_all_supplied_positions_count_before_matching_shared_duplicates_reconcile():
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    from proofpack.calibrations.dependencies import canonical
    group, rows, datasets, deployment = family();datasets *= 2
    incoming = [group, *rows]
    for dataset in datasets:
        incoming.extend((dataset.job, *dataset.rows, *dataset.group_rows))
        for source in dataset.label_families:
            incoming.extend((source.inspection, source.recipe, *source.rows, *source.capture_rows, *source.purpose_rows))
        for source in dataset.permission_families:incoming.extend((source.preview, *source.rows))
    count = len(incoming);size = sum(len(canonical(row.data).encode()) for row in incoming)
    result = parse(group, rows, datasets, deployment, max_records=count, max_payload_bytes=size)
    assert len(result.history) == 1 and result.payload_bytes == size
    with pytest.raises(GroupHistoryHeld):parse(group, rows, datasets, deployment, max_records=count - 1, max_payload_bytes=size)
    with pytest.raises(GroupHistoryHeld):parse(group, rows, datasets, deployment, max_records=count, max_payload_bytes=size - 1)


@pytest.mark.parametrize('name,bad', [('max_records', True), ('max_records', 0), ('max_records', 2**63),
                                  ('max_payload_bytes', False), ('max_payload_bytes', 1.0)])
def test_explicit_limits_reject_ambiguous_or_unbounded_values(name, bad):
    with pytest.raises(ValueError):parse(*family(), **{name: bad})


@pytest.mark.parametrize('fault', ['malformed-user', 'multiple-users'])
def test_declassification_actor_requires_one_canonical_user_reference(fault):
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    group, rows, datasets, deployment = family(split=Split.FROZEN_TEST, changed=True)
    for row in rows:
        refs = row.data['resource_bindings']['checks']
        if fault == 'malformed-user':next(ref for ref in refs if ref['resource'].startswith('user#'))['resource'] = 'user#not-a-uuid'
        else:refs.append({'table': 'state', 'resource': 'user#' + uid(99), 'revision': 1, 'sha256': 'f' * 64})
        refs.sort(key=lambda ref: (ref['table'], ref['resource']))
    with pytest.raises(GroupHistoryHeld):parse(group, rows, datasets, deployment)


def referring_dataset(first, deployment, *, queued=False, extra_labels=()):
    """A later supplied job reuses existing groups; it never creates them."""
    from proofpack.evidence.job_authority import scope_sha256
    from proofpack.review.manifests import job_key, entry_key, manifest_key
    from proofpack.calibrations.dependencies import canonical
    import hashlib, json
    ident = uid(99)
    data = {**deepcopy(first.job.data), 'id': ident, 'created_at_ms': 350, 'status': 'queued', 'processed': 0,
            'steps_reserved': 0, 'validation_runtime': None, 'effective_deadline_ms': 1000,
            'splits': {part.value: 0 for part in Split}, 'manifest_sha256': None}
    if extra_labels:
        assert queued
        request = json.loads(data['request_json'])
        request['selections'].extend({**deepcopy(request['selections'][0]), 'label_id': ident} for ident in extra_labels)
        data['request_json'] = canonical(request)
        data['request_sha256'] = hashlib.sha256(data['request_json'].encode()).hexdigest()
        data['example_count'] = len(request['selections'])
    data['seed_sha256'] = digest({'dataset_id': ident, 'request_sha256': data['request_sha256']})
    data['chain_sha256'] = data['seed_sha256']
    authority = data['processing_authority']['body'];authority.update(job_id=ident, issued_at_ms=350, scope_sha256=scope_sha256(data))
    job = Row(job_key(ident), 1, data)
    catalog = Row(Key('state', 'dataset-catalog#' + ident), 1, {'id': ident})
    owner = (*checks()[:2], Row(DATA, 3, {'epoch': 3, 'changed_at_ms': 150}), checks()[3])
    create = access_event('dataset-create', (Write(job.key, None, data), Write(catalog.key, None, catalog.data),
        Write(Key('state', 'dataset-create-quota#' + 'e' * 64), 1, {'minute': 0, 'count': 2})), owner, 3000,
        {'dataset_id': ident, 'request_sha256': data['request_sha256'], 'example_count': data['example_count']}, at=350, deployment=deployment)
    if queued:return replace(first, job=job, rows=(catalog, create), group_rows=())
    issued = deepcopy(data['processing_authority']);issued['body']['issued_at_ms'] = 360
    lease = Row(job.key, 2, {**data, 'status': 'processing', 'steps_reserved': 1,
        'validation_runtime': first.job.data['validation_runtime'], 'lease_token': uid(3001), 'lease_until_ms': 1000,
        'lease_runtime': first.job.data['validation_runtime'], 'processing_authority': issued})
    reserve = access_event('dataset-step:' + ident, (Write(job.key, 1, lease.data),
        Write(Key('state', 'dataset-step-quota#' + 'e' * 64), 1, {'minute': 0, 'count': 2})),
        (*owner, job), 3001, at=360, deployment=deployment)
    content = deepcopy(next(row.data['content'] for row in first.rows if row.key.resource.startswith('dataset-example#')))
    entry = {'schema_version': 1, 'dataset_id': ident, 'index': 0, 'content': content,
             'content_sha256': digest(content), 'previous_chain_sha256': data['seed_sha256']}
    entry['chain_sha256'] = digest(entry);example = Row(entry_key(ident, 0), 1, entry)
    final = {**lease.data, 'status': 'completed', 'processed': 1, 'chain_sha256': entry['chain_sha256'],
             'effective_deadline_ms': 900, 'splits': {part.value: int(part == Split.DEVELOPMENT) for part in Split},
             'lease_token': None, 'lease_until_ms': 0, 'lease_runtime': None}
    sealed = {key: final[key] for key in ('id', 'request_sha256', 'example_count', 'chain_sha256', 'seed_sha256',
        'configuration', 'artifact_sha256', 'controls_sha256', 'environment', 'data_epoch', 'created_at_ms', 'validation_runtime', 'splits')}
    sealed.update(schema_version=1, expires_at_ms=900, prior_exposure_unknown=True, independent_benchmark_qualified=False)
    sealed['sha256'] = digest(sealed);seal = Row(manifest_key(ident), 1, sealed);final['manifest_sha256'] = sealed['sha256']
    latest = Row(job.key, 3, final);key = Key('events', 'dataset-transition#' + uid(3002))
    event = {'kind': 'dataset-example-committed', 'dataset_id': ident, 'request_sha256': data['request_sha256'],
             'index': 0, 'prior_job_revision': 2, 'at_ms': 380}
    label = next(row for row in first.label_families[0].rows if row.key.resource.startswith('label-revision#'))
    head = next(row for row in first.label_families[0].rows if row.key.resource.startswith('label#'))
    permission = next(row for row in first.permission_families[0].rows if row.key.resource.startswith('improvement-permission#'))
    grant = next(row for row in first.permission_families[0].rows if row.key.resource.startswith('improvement-grant#'))
    asset = next(row for row in first.label_families[0].capture_rows if row.key.resource.startswith('asset#'))
    from proofpack.evidence.resource_bindings import prepare_linked
    prepared, _ = prepare_linked(deployment, event['kind'], (Write(job.key, 2, final), Write(example.key, None, example.data),
        Write(seal.key, None, seal.data), Write(key, None, event)),
        (*owner, lease, label, head, permission, grant, asset, *first.label_families[0].purpose_rows, *first.group_rows))
    committed = Row(key, 1, next(write.data for write in prepared if write.key == key))
    return replace(first, job=latest, rows=(catalog, create, reserve, example, seal, committed))


def test_multiple_referring_datasets_need_the_one_original_creator():
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    group, rows, datasets, deployment = family()
    second = referring_dataset(datasets[0], deployment)
    result = parse(group, rows, (*datasets, second), deployment)
    assert len(result.history) == 1
    assert {datasets[0].job.key, second.job.key} <= {ref.key for ref in result.dependencies}
    with pytest.raises(GroupHistoryHeld):parse(group, rows, (second,), deployment)


def test_two_distinct_claimed_creators_cannot_reset_shared_split_history():
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    group, rows, datasets, deployment = family();second = referring_dataset(datasets[0], deployment)
    original = next(row for row in datasets[0].rows if row.data.get('kind') == 'dataset-example-committed')
    created = deepcopy(next(ref for ref in original.data['resource_bindings']['writes'] if ref['resource'] == group.key.resource))
    event = next(row for row in second.rows if row.data.get('kind') == 'dataset-example-committed')
    binding = event.data['resource_bindings'];binding['checks'] = [ref for ref in binding['checks'] if ref['resource'] != group.key.resource]
    binding['writes'].append(created);binding['writes'].sort(key=lambda ref: (ref['table'], ref['resource']))
    with pytest.raises(GroupHistoryHeld):parse(group, rows, (*datasets, second), deployment)


def test_result_is_frozen_detached_references_without_private_payloads():
    from dataclasses import FrozenInstanceError
    group, rows, datasets, deployment = family(split=Split.FROZEN_TEST, changed=True, repeats=1)
    result = parse(group, rows, datasets, deployment);saved = result.group.sha256
    group.data['reason'] = 'later-caller-mutation'
    assert result.group.sha256 == saved and 'later-caller-mutation' not in repr(result)
    with pytest.raises(FrozenInstanceError):result.payload_bytes = 0


def test_unmaterialized_label_request_retains_its_group_link_and_unresolved_intents():
    group, rows, datasets, deployment = family()
    queued = referring_dataset(datasets[0], deployment, queued=True)
    result = parse(group, rows, (*datasets, queued), deployment)
    assert queued.job.key in {ref.key for ref in result.dependencies}
    assert any(link.kind == 'group_requested_label' for link in result.links)
    assert {intent.source for intent in result.intents} == {datasets[0].job.key, queued.job.key}
    assert len(result.history) == 1 and result.group.revision == 1


@pytest.mark.parametrize('category', ['kit', 'session', 'operator'])
def test_each_group_category_retains_its_known_original_and_transition(category):
    group, rows, datasets, deployment = family(split=Split.FROZEN_TEST, changed=True, category=category)
    assert parse(group, rows, datasets, deployment).group.key == group.key


def test_unknown_additional_request_target_is_forwarded_without_a_fabricated_digest():
    group, rows, datasets, deployment = family()
    queued = referring_dataset(datasets[0], deployment, queued=True, extra_labels=(uid(88),))
    result = parse(group, rows, (*datasets, queued), deployment)
    target = Key('state', 'label-revision#' + uid(88) + '#1')
    assert any(intent.source == queued.job.key and intent.target == target for intent in result.intents)
    assert target not in {ref.key for ref in result.dependencies}


def test_request_without_an_admitted_source_cannot_invent_group_association():
    from proofpack.evidence.dataset_group_lineage import GroupHistoryHeld
    # Keep the original valid group creator. Supply a queued request whose
    # only selected label is unknown, without inventing its source metadata.
    group, rows, datasets, deployment = family()
    queued = referring_dataset(datasets[0], deployment, queued=True)
    from proofpack.evidence.job_authority import scope_sha256
    from proofpack.calibrations.dependencies import canonical
    import hashlib, json
    request = json.loads(queued.job.data['request_json']);request['selections'][0]['label_id'] = uid(88)
    data = deepcopy(queued.job.data);data['request_json'] = canonical(request)
    data['request_sha256'] = hashlib.sha256(data['request_json'].encode()).hexdigest()
    data['seed_sha256'] = digest({'dataset_id': data['id'], 'request_sha256': data['request_sha256']})
    data['chain_sha256'] = data['seed_sha256'];data['processing_authority']['body']['scope_sha256'] = scope_sha256(data)
    root = Row(queued.job.key, 1, data);catalog = queued.rows[0]
    owner = (*checks()[:2], Row(DATA, 3, {'epoch': 3, 'changed_at_ms': 150}), checks()[3])
    created = access_event('dataset-create', (Write(root.key, None, data), Write(catalog.key, None, catalog.data),
        Write(Key('state', 'dataset-create-quota#' + 'e' * 64), 1, {'minute': 0, 'count': 2})), owner, 3000,
        {'dataset_id': data['id'], 'request_sha256': data['request_sha256'], 'example_count': 1}, at=350, deployment=deployment)
    queued = replace(queued, job=root, rows=(catalog, created), label_families=())
    with pytest.raises(GroupHistoryHeld):parse(group, rows, (*datasets, queued), deployment)
