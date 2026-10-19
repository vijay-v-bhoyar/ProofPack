"""Local real-writer fixtures; not provider, physical or aggregate erasure proof."""
import json
from uuid import uuid4
import pytest
from test_access_lifecycle import world, repository_factory, publication_case
from test_labels import review_case
from test_manifests import manifest_case, create, finish, request, selection
from test_capture_family_store import inventory, closed
from test_dataset_lineage_store import arguments as dataset_arguments
from test_label_lineage_store import arguments as label_arguments
from test_improvement_lineage_store import arguments as permission_arguments
from proofpack.evidence.dataset_group_lineage import discover, DatasetInputs, GroupHistoryHeld
from proofpack.evidence.dataset_lineage import LabelInputs, PermissionInputs
from proofpack.evidence.repository import Key
from proofpack.review.labels import label_revision_key
from proofpack.review.manifests import group_key, Consequence
from proofpack.review.datasets import Split
from proofpack.stations.service import inspection_key


def group_id(repo, dataset_id, category='kit'):
    _, rows, _ = dataset_arguments(repo, dataset_id)
    example = next(row for row in rows if row.key.resource.startswith('dataset-example#'))
    return next(value['id'] for value in example.data['content']['groups'] if value['category'] == category)


def arguments(repo, ident, dataset_ids):
    # Fixture selector only. Production still needs complete classification,
    # a real maintenance barrier, read-set admission and absence resolution.
    all_rows = inventory(repo);key = group_key(ident);group = repo.snapshot((key,))[key]
    own = tuple(row for row in all_rows if row.key.table == 'events' and (
        row.key.resource.startswith('dataset-declassification#') and row.data.get('group_id') == ident
        or row.key.resource.startswith('access#') and row.data.get('kind') == 'dataset-declassify:' + ident
    ))
    datasets = []
    for dataset_id in dataset_ids:
        job, rows, source = dataset_arguments(repo, dataset_id)
        labels = {family.inspection.key: family for family in source['label_families']}
        permissions = {family.preview.key: family for family in source['permission_families']}
        for selected in json.loads(job.data['request_json'])['selections']:
            selected_key = label_revision_key(selected['label_id'], selected['label_revision'])
            label = repo.snapshot((selected_key,))[selected_key]
            if label is not None:
                root_key = inspection_key(label.data['source_context']['inspection_id'])
                root = repo.snapshot((root_key,))[root_key]
                label_rows, capture, recipe, purposes = label_arguments(repo, root)
                labels[root.key] = LabelInputs(root, label_rows, capture, recipe, purposes)
            for binding in selected['permissions']:
                previews = [row for row in all_rows if row.key.resource.startswith('improvement-preview#')
                            and row.data.get('permission_id') == binding['id']]
                if not previews:continue  # Keep the unresolved request; never invent its grant.
                assert len(previews) == 1
                preview, history = permission_arguments(repo, previews[0].data['id'])
                permissions[preview.key] = PermissionInputs(preview, history)
        datasets.append(DatasetInputs(job, rows, tuple(labels.values()), tuple(permissions.values()), source['group_rows']))
    return group, own, tuple(datasets)


def parse(repo, ident, dataset_ids):
    group, rows, datasets = arguments(repo, ident, dataset_ids)
    return discover(group, rows, datasets=datasets, deployment=repo.deployment,
                    max_records=12000, max_payload_bytes=16000000)


@pytest.mark.parametrize('split', [Split.DEVELOPMENT, Split.VALIDATION, Split.FROZEN_TEST])
def test_actual_creation_preserves_each_shared_group_category(world, manifest_case, publication_case, split):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case, split=split))
    for category in ('kit', 'session', 'operator'):
        ident = group_id(world[1], job['id'], category)
        result = parse(world[1], ident, (job['id'],))
        assert result.group.revision == 1 and len(result.history) == 1
        assert service._row(job['id']).key in {ref.key for ref in result.dependencies}
        assert not hasattr(result, 'owned') and not hasattr(result, 'usable')


@pytest.mark.parametrize('repeats', [0, 2])
def test_actual_declassification_pairs_both_outputs_and_quota_only_repeats(world, manifest_case, publication_case, repeats):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST))
    ident = group_id(world[1], job['id'])
    service.declassify(world[5], ident, request=Consequence(acknowledged=True, reason='used-in-development'),
                       expected_version=1, idempotency_key='group-first-declassification')
    for index in range(repeats):
        service.declassify(world[5], ident, request=Consequence(acknowledged=True, reason='later-private-reason'),
                           expected_version=2, idempotency_key='group-repeat-' + str(index))
    result = parse(world[1], ident, (job['id'],))
    assert {ref.revision for ref in result.versions} == {1, 2}
    assert len(result.history) == 3 + repeats
    assert not service.job(actor, job['id'])['receipt_usable']
    assert 'later-private-reason' not in repr(result)


def test_actual_development_origin_acknowledgment_never_invents_a_transition(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case));ident = group_id(world[1], job['id'])
    service.declassify(world[5], ident, request=Consequence(acknowledged=True, reason='already-development'),
                       expected_version=1, idempotency_key='group-origin-ack')
    result = parse(world[1], ident, (job['id'],))
    assert result.group.revision == 1 and len(result.history) == 2


def test_actual_retirement_keeps_the_original_shared_denial_record(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case));ident = group_id(world[1], job['id'])
    before = parse(world[1], ident, (job['id'],)).group
    service.retire(actor, job['id'], request=Consequence(acknowledged=True, reason='source-retired'),
                   expected_version=job['state_version'], idempotency_key='group-source-retire')
    assert parse(world[1], ident, (job['id'],)).group == before


def test_actual_two_datasets_have_one_original_group_creator(world, manifest_case, publication_case):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    first = finish(service, actor, create(manifest_case));ident = group_id(world[1], first['id'])
    second = finish(service, actor, create(manifest_case, key='group-second-dataset'))
    result = parse(world[1], ident, (first['id'], second['id']))
    assert len(result.history) == 1
    assert {service._row(first['id']).key, service._row(second['id']).key} <= {ref.key for ref in result.dependencies}
    with pytest.raises(GroupHistoryHeld):parse(world[1], ident, (second['id'],))


def test_actual_queued_request_preserves_unknown_targets_without_fabricated_records(world, manifest_case, publication_case):
    service, actor, _, item, grant, *_ = manifest_case;closed(world, publication_case)
    first = finish(service, actor, create(manifest_case));ident = group_id(world[1], first['id'])
    unknown = str(uuid4())
    queued = service.create(actor, request=request((item, selection(unknown, grant['id']))),
                            idempotency_key='group-queued-request')
    result = parse(world[1], ident, (first['id'], queued['id']))
    target = label_revision_key(unknown, 1)
    assert any(intent.source == service._row(queued['id']).key and intent.target == target for intent in result.intents)
    assert target not in {ref.key for ref in result.dependencies}
    assert len(result.history) == 1


@pytest.mark.parametrize('missing', ['access', 'detail'])
def test_actual_missing_whole_transition_output_holds(world, manifest_case, publication_case, missing):
    service, actor, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST));ident = group_id(world[1], job['id'])
    service.declassify(world[5], ident, request=Consequence(acknowledged=True, reason='development-use'),
                       expected_version=1, idempotency_key='group-missing-peer')
    group, rows, datasets = arguments(world[1], ident, (job['id'],))
    prefix = 'access#' if missing == 'access' else 'dataset-declassification#'
    rows = tuple(row for row in rows if not row.key.resource.startswith(prefix))
    with pytest.raises(GroupHistoryHeld):
        discover(group, rows, datasets=datasets, deployment=world[1].deployment, max_records=12000, max_payload_bytes=16000000)


def test_actual_expired_withdrawn_source_does_not_erase_later_group_history(world, manifest_case, publication_case):
    service, actor, _, _, grant, *_ = manifest_case;closed(world, publication_case)
    job = finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST));ident = group_id(world[1], job['id'])
    key = Key('state', 'improvement-grant#' + grant['id'])
    world[2].value = int(world[1].snapshot((key,))[key].data['expires_at_ms']) + 1
    service.improvement.withdraw(world[5], grant['id'], expected_version=1, idempotency_key='group-old-source-withdraw')
    service.declassify(world[5], ident, request=Consequence(acknowledged=True, reason='late-development-use'),
                       expected_version=1, idempotency_key='group-late-declassification')
    assert not service.job(actor, job['id'])['receipt_usable']
    assert parse(world[1], ident, (job['id'],)).group.revision == 2
