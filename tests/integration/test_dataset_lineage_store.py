from dataclasses import replace
import pytest
from test_access_lifecycle import world, repository_factory, publication_case
from test_labels import review_case
from test_manifests import manifest_case, create, finish, request, selection
from test_labels import request_for
from test_capture_family_store import inventory, closed
from test_label_lineage_store import arguments as label_arguments
from test_improvement_lineage_store import arguments as permission_arguments
from test_original_frames import original_case
from test_evaluations import evaluations, submit
from test_vision_replay import vision_case
from proofpack.evidence.dataset_lineage import discover, LabelInputs, PermissionInputs
from proofpack.review.manifests import DatasetManifests, Consequence, job_key, group_key
from proofpack.review.datasets import Split


def arguments(repo, ident):
    # Fixture selector only: production requires complete classification/barrier
    # admission, including unknown writers and unresolved requested targets.
    all_rows = inventory(repo);key = job_key(ident);job = repo.snapshot((key,))[key]
    rows = []
    operations = {'dataset-step:' + ident, 'dataset-cancel:' + ident, 'dataset-retire:' + ident}
    for row in all_rows:
        name = row.key.resource;data = row.data
        if row.key.table == 'state' and (name == 'dataset-catalog#' + ident or name == 'dataset-manifest#' + ident
                or name.startswith('dataset-example#' + ident + '#')):
            rows.append(row)
        elif row.key.table == 'events' and (data.get('dataset_id') == ident
                or data.get('details', {}).get('dataset_id') == ident or data.get('kind') in operations):
            rows.append(row)
    examples = [row for row in rows if row.key.resource.startswith('dataset-example#')]
    inspection_ids = set();permission_ids = set();group_ids = set()
    for row in examples:
        content = row.data['content']
        label_key = next(r.key for r in all_rows if r.key.resource.startswith('label-revision#')
            and r.data.get('id') == content['label_id'] and r.data.get('revision') == content['label_revision'])
        label = repo.snapshot((label_key,))[label_key]
        inspection_ids.add(label.data['source_context']['inspection_id'])
        permission_ids.update(item['id'] for item in content['permissions'])
        group_ids.update(item['id'] for item in content['groups'])
    sources = []
    for inspection_id in sorted(inspection_ids):
        root = next(row for row in all_rows if row.key.resource == 'inspection#' + inspection_id)
        labels, capture, recipe, purposes = label_arguments(repo, root)
        sources.append(LabelInputs(root, labels, capture, recipe, purposes))
    grants = []
    for permission_id in sorted(permission_ids):
        previews = [row for row in all_rows if row.key.resource.startswith('improvement-preview#')
                    and row.data.get('permission_id') == permission_id]
        assert len(previews) == 1, 'fixture must resolve one actual original permission preview'
        preview, history = permission_arguments(repo, previews[0].data['id'])
        grants.append(PermissionInputs(preview, history))
    groups = tuple(repo.snapshot((group_key(ident),))[group_key(ident)] for ident in sorted(group_ids))
    return job, tuple(rows), {'label_families': tuple(sources), 'permission_families': tuple(grants), 'group_rows': groups}


def parse(repo, ident):
    job, rows, sources = arguments(repo, ident)
    result = discover(job, rows, **sources, deployment=repo.deployment, max_records=3000, max_payload_bytes=8000000)
    assert {record.key for record in result.records} == {row.key for row in rows}
    assert not ({record.key for record in result.records} & {record.key for record in result.dependencies})
    return result


def test_actual_queued_and_cancelled_jobs_preserve_unmaterialized_intents(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = create(manifest_case)
    first = parse(world[1], job['id'])
    ended = service.cancel(actor, job['id'], expected_version=job['state_version'], idempotency_key='lineage-cancel')
    assert ended['status'] == 'cancelled'
    assert parse(world[1], job['id']).intents == first.intents


@pytest.mark.parametrize('retired', [False, True])
def test_actual_completed_and_retired_copy_family_preserves_original_sources(world, manifest_case, publication_case, retired):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case))
    assert job['status'] == 'completed'
    if retired:
        job = service.retire(actor, job['id'], request=Consequence(acknowledged=True, reason='historical-lineage'),
            expected_version=job['state_version'], idempotency_key='lineage-retire')
        assert job['status'] == 'retired'
    result = parse(world[1], job['id'])
    assert any(record.key.resource.startswith('dataset-example#') for record in result.records)
    assert not hasattr(result, 'usable')


def test_actual_request_and_example_admission_records_are_part_of_the_family(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case))
    service.selections(actor, job['id']);service.examples(actor, job['id'])
    result = parse(world[1], job['id'])
    assert sum(record.key.resource.startswith('dataset-access#') for record in result.records) == 2


def test_actual_split_conflict_failure_has_no_invented_copy(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST))
    job = finish(service, actor, create(manifest_case, split=Split.DEVELOPMENT, key='lineage-conflict'))
    assert job['status'] == 'failed' and job['failure_reason'] == 'SPLIT_CONFLICT'
    assert not any(record.key.resource.startswith('dataset-example#') for record in parse(world[1], job['id']).records)


def test_actual_expired_budget_failure_retains_old_lease_without_renewing_it(world, manifest_case, publication_case):
    base, actor, *_ = manifest_case;closed(world, publication_case)
    service = DatasetManifests(base.labels, base.improvement, replace(base.config, max_steps=1))
    job = create((service, *manifest_case[1:]));fired = False
    def stop_after_admission():
        nonlocal fired
        if service._row(job['id']).data['status'] == 'processing':
            fired = True
            raise RuntimeError('deliberate worker interruption after reservation')
    with pytest.raises(RuntimeError, match='deliberate worker interruption'):
        service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='lineage-reserve',
                        execution_gate=stop_after_admission)
    lease = service._row(job['id']);assert fired and lease.data['steps_reserved'] == 1
    world[2].value = int(lease.data['lease_until_ms'])
    failed = service.advance(actor, job['id'], expected_version=lease.revision, idempotency_key='lineage-exhausted')
    assert failed['status'] == 'failed' and failed['failure_reason'] == 'STEP_BUDGET_EXHAUSTED'
    assert service._row(job['id']).data['steps_reserved'] == 1
    assert parse(world[1], job['id']).job.revision == failed['state_version']


def test_same_millisecond_withdrawal_preserves_the_causally_prior_copy(world, manifest_case, publication_case):
    service, actor, _, _, grant, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case))
    revoked = service.improvement.withdraw(world[5], grant['id'], expected_version=grant['state_version'],
                                           idempotency_key='lineage-same-time-withdraw')
    assert revoked['withdrawn'] and not service.job(actor, job['id'])['receipt_usable']
    assert parse(world[1], job['id']).job.key == job_key(job['id'])


def test_same_millisecond_declassification_preserves_frozen_history(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST))
    group = service.examples(actor, job['id'])['examples'][0]['groups'][0]['id']
    service.declassify(world[5], group, request=Consequence(acknowledged=True, reason='development-use'),
                       expected_version=1, idempotency_key='lineage-same-time-declassify')
    assert not service.job(actor, job['id'])['receipt_usable']
    assert parse(world[1], job['id']).job.key == job_key(job['id'])


def test_source_purpose_withdrawal_does_not_erase_historical_copy_metadata(world, manifest_case, publication_case):
    service, actor, _, _, _, original = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case))
    purpose = original[-1];row = world[1].snapshot((purpose,))[purpose]
    service.purposes.withdraw(world[5], ident=purpose.resource.split('#')[1], expected_version=row.revision,
                              idempotency_key='lineage-source-purpose-withdraw')
    assert not service.job(actor, job['id'])['receipt_usable']
    assert parse(world[1], job['id']).job.key == job_key(job['id'])


def two_selection_job(manifest_case):
    service, actor, _, first, grant, original = manifest_case
    second = service.labels.write(actor, request=request_for(original), idempotency_key='lineage-second-label')
    return service.create(actor, request=request((first, selection(second['id'], grant['id']))),
                          idempotency_key='lineage-two-selection-job')


@pytest.mark.parametrize('cancelled', [False, True])
def test_actual_partial_prefix_retains_all_request_intents_after_optional_cancellation(world, manifest_case, publication_case, cancelled):
    service, actor, *_ = manifest_case
    job = two_selection_job(manifest_case);closed(world, publication_case)
    job = service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='lineage-first-copy')
    assert job['status'] == 'queued' and job['prepared_count'] == 1
    if cancelled:
        job = service.cancel(actor, job['id'], expected_version=job['state_version'], idempotency_key='lineage-partial-cancel')
    result = parse(world[1], job['id'])
    assert len([ref for ref in result.records if ref.key.resource.startswith('dataset-example#')]) == 1
    assert len([intent for intent in result.intents if intent.kind == 'requested_label']) == 2


def test_actual_runtime_restart_revalidates_retained_prefix_without_new_copy_or_budget_refund(world, manifest_case, publication_case):
    from uuid import uuid4
    from proofpack.runtime.control import RuntimeControl
    service, actor, *_ = manifest_case
    job = two_selection_job(manifest_case);closed(world, publication_case)
    job = service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='lineage-before-restart')
    before = parse(world[1], job['id'])
    original = service._row(job['id']).data
    newer = RuntimeControl(world[0], instance_id=str(uuid4()), artifact_sha256=service.runtime.artifact_sha256,
                           controls_sha256=service.runtime.controls_sha256, environment=service.runtime.environment)
    newer.start()
    # Recompose every actual service sharing this process identity. Leaving
    # the read service on the old incarnation correctly denies source access.
    for component in (service, service.labels, service.improvement, service.purposes, service.improvement.assets):
        component.runtime = newer
    job = service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='lineage-revalidate-prefix')
    assert job['prepared_count'] == 1 and job['steps_reserved'] == 2
    during = parse(world[1], job['id'])
    copies = lambda family: {ref for ref in family.records if ref.key.resource.startswith('dataset-example#')}
    assert copies(before) == copies(during)
    job = finish(service, actor, job)
    assert job['status'] == 'completed' and job['steps_reserved'] == 3
    assert service._row(job['id']).data['expires_at_ms'] == original['expires_at_ms']
    assert len(copies(parse(world[1], job['id']))) == 2


def test_actual_retained_original_and_crop_are_distinct_complete_copied_sources(world, original_case, publication_case):
    from test_access_lifecycle import invite_and_join
    from proofpack.auth.policy import Role
    from proofpack.evidence.purposes import DataPurposes
    from proofpack.evidence.improvement import ImprovementPermissions, ImprovementConfig, ImprovementPreview, ImprovementConfirmation
    from proofpack.review.labels import OutcomeLabels, ReviewTuple
    from test_manifests import config
    reads, observe, operator, objects, purpose, started, capture = original_case
    observation, _, _ = observe()
    _, credentials, reviewer, *_ = invite_and_join(world, 'dataset-original-reviewer', roles=(Role.REVIEWER,))
    labels = OutcomeLabels(DataPurposes(world[0], capture.stations.runtime, max_lifetime_ms=60000),
                           writes_per_minute=8, max_duration_ms=60000, review_validity_ms=30000)
    review = (labels, reviewer, credentials, ReviewTuple(before_observation_id=observation.data['id']), started, purpose)
    # Keep the original captured purpose unchanged: the abbreviated crop-only
    # builder rewrites its permission fields and correctly invalidates originals.
    label = labels.write(reviewer, request=request_for(review, outcome='incorrect_finding'), idempotency_key='dataset-original-label')
    permissions = ImprovementPermissions(reads, ImprovementConfig('synthetic-dataset-v1', 'Separate synthetic optional notice.', 60000, 8, 30000))
    preview = permissions.preview(world[5], request=ImprovementPreview(asset_ids=tuple(
        value['asset_id'] for value in label['source_context']['sources'])), idempotency_key='dataset-original-preview')
    grant = permissions.confirm(world[5], request=ImprovementConfirmation(preview_id=preview['id'],
        confirmed_scope_sha256=preview['scope_sha256'], documented_permission_reference='synthetic-original-copy-rights',
        notice_version=preview['notice']['version'], notice_sha256=preview['notice']['sha256'],
        optional_improvement_acknowledged=True, limitations_acknowledged=True,
        derived_review_metadata_acknowledged=True, expires_at_ms=world[2]() + 40000),
        expected_version=preview['state_version'], idempotency_key='dataset-original-confirm')
    case = (DatasetManifests(labels, permissions, config()), reviewer, credentials,
            selection(label['id'], grant['id']), grant, review)
    service, actor, *_ = case;closed(world, publication_case)
    job = finish(service, actor, create(case))
    assert job['status'] == 'completed'
    result = parse(world[1], job['id'])
    _, rows, sources = arguments(world[1], job['id'])
    content = next(row.data['content'] for row in rows if row.key.resource.startswith('dataset-example#'))
    assert len(content['sources']) == 2 and len({value['asset_id'] for value in content['sources']}) == 2
    assert len(sources['label_families'][0].purpose_rows) == 1
    assert {value['asset_id'] for value in content['sources']} <= {
        ref.key.resource.split('#')[1] for ref in result.dependencies if ref.key.resource.startswith('asset#')}
    assert not hasattr(result, 'usable')


def test_actual_two_closed_inspections_require_both_complete_source_families(world, review_case, publication_case):
    import cv2
    from proofpack.vision.fixtures import make_fixture
    from proofpack.evidence.dataset_lineage import DatasetHistoryHeld
    from proofpack.evidence.improvement import ImprovementPreview, ImprovementConfirmation
    from proofpack.review.labels import ReviewTuple
    from proofpack.stations.service import inspection_key
    prior = closed(world, publication_case)
    observations, capture, started, operator, _, _, _, _, _, observe = publication_case
    # Capture both inspections before label/grant writes advance DATA. The
    # fixture correctly requires new qualification after those later writes.
    station = capture.stations.view(operator, prior.data['station_id'])
    second = capture.stations.start(operator, station_id=station['id'], expected_version=station['state_version'],
        expected_epoch=station['epoch'], recipe_id=prior.data['recipe_id'], kit_id='lineage-second-kit',
        idempotency_key='lineage-second-inspection')
    started.clear();started.update(second)
    observations.prepare(operator, inspection_id=started['inspection_id'], expected_version=started['state_version'],
                         idempotency_key='lineage-warm-second-inspection')
    current = world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    permit = capture.issue(operator, inspection_id=started['inspection_id'], expected_version=current.revision,
        expected_epoch=int(current.data['station_epoch']), idempotency_key='lineage-second-capture-permit')
    frame, _ = make_fixture(0, 'complete', seed=1)
    encoded_ok, encoded = cv2.imencode('.png', frame);assert encoded_ok
    payload = encoded.tobytes()
    admission = capture.admit(operator, inspection_id=started['inspection_id'],
        expected_version=permit['inspection_state_version'], permit_id=permit['permit_id'],
        nonce=permit['nonce'], sequence=permit['sequence'], payload=payload, content_type='image/png')
    observations.process(operator, observation_id=admission['id'], payload=payload)
    root = world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    station = capture.stations.view(operator, prior.data['station_id'])
    capture.stations.close(operator, inspection_id=started['inspection_id'], expected_version=root.revision,
        expected_epoch=station['epoch'], reason='second-source-closed', disposition='cancelled',
        idempotency_key='lineage-second-inspection-close')
    case = manifest_case.__wrapped__(world, review_case, publication_case)
    service, actor, _, first, *_ = case
    label = service.labels.write(actor, request=request_for(review_case,
        tuple_=ReviewTuple(before_observation_id=admission['id']), outcome='incorrect_finding'),
        idempotency_key='lineage-second-inspection-label')
    preview = service.improvement.preview(world[5], request=ImprovementPreview(asset_ids=tuple(
        value['asset_id'] for value in label['source_context']['sources'])), idempotency_key='lineage-second-source-preview')
    grant = service.improvement.confirm(world[5], request=ImprovementConfirmation(preview_id=preview['id'],
        confirmed_scope_sha256=preview['scope_sha256'], documented_permission_reference='synthetic-second-inspection-rights',
        notice_version=preview['notice']['version'], notice_sha256=preview['notice']['sha256'],
        optional_improvement_acknowledged=True, limitations_acknowledged=True,
        derived_review_metadata_acknowledged=True, expires_at_ms=world[2]() + 40000),
        expected_version=preview['state_version'], idempotency_key='lineage-second-source-confirm')
    job = service.create(actor, request=request((first, selection(label['id'], grant['id']))),
                         idempotency_key='lineage-two-inspection-dataset')
    job = finish(service, actor, job)
    assert job['status'] == 'completed' and job['prepared_count'] == 2
    result = parse(world[1], job['id'])
    root, rows, sources = arguments(world[1], job['id'])
    assert len(sources['label_families']) == len(sources['permission_families']) == 2
    assert len({family.inspection.key for family in sources['label_families']}) == 2
    assert sum(ref.key.resource.startswith('dataset-example#') for ref in result.records) == 2
    with pytest.raises(DatasetHistoryHeld):
        discover(root, rows, **{**sources, 'label_families': sources['label_families'][:1]},
                 deployment=world[1].deployment, max_records=3000, max_payload_bytes=8000000)


def test_actual_evaluation_consumer_admission_is_historical_not_delivery_authority(world, evaluations, publication_case):
    service, actor, _, request, *_ = evaluations;closed(world, publication_case)
    job = finish(service, actor, submit(evaluations))
    assert job['status'] == 'completed'
    assert len(service.examples(actor, job['id'])['examples']) == 1
    result = parse(world[1], request.manifest_id)
    _, rows, _ = arguments(world[1], request.manifest_id)
    admissions = [row for row in rows if row.data.get('kind') == 'evaluation_examples_read']
    assert len(admissions) == 1 and admissions[0].data['consumer_job_id'] == job['id']
    assert job_key(job['id']) in {ref.key for ref in result.dependencies}
    assert not hasattr(result, 'delivered')


@pytest.mark.parametrize('vision_case', ['two_frames'], indirect=True)
def test_actual_pixel_replay_admission_keeps_both_original_frame_sources(world, vision_case, publication_case):
    engine, actor, request, *_ = vision_case;closed(world, publication_case)
    measured, _, _ = engine.measure(actor, request=request, index=0)
    assert measured['pixel_measurement_performed'] and measured['original_frames'] == 2
    result = parse(world[1], request.manifest_id)
    _, rows, _ = arguments(world[1], request.manifest_id)
    assert sum(row.data.get('kind') == 'vision_measurement_case_admitted' for row in rows) == 1
    content = next(row.data['content'] for row in rows if row.key.resource.startswith('dataset-example#'))
    assert len(content['sources']) == 4
    assert not hasattr(result, 'usable')
