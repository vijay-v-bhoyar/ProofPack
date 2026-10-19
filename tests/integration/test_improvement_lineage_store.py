from copy import deepcopy
import pytest
from test_access_lifecycle import world, repository_factory, publication_case
from test_references import reference_case
from test_asset_reads import frame_read_case
from test_improvement import improvement_case, review, request
from proofpack.evidence.improvement import ImprovementPermissions, ImprovementConfig, ImprovementPreview, preview_key, grant_key, permission_key
from proofpack.evidence.improvement_lineage import discover, ImprovementHistoryHeld
from proofpack.evidence.repository import Key, Write


def arguments(repo, ident):
    root = repo.snapshot((preview_key(ident),))[preview_key(ident)]
    permission = root.data['permission_id']; rows = []
    if permission is not None:
        keys = (grant_key(permission), permission_key(permission))
        stored = repo.snapshot(keys)
        rows.extend(stored[key] for key in keys)
    cursor = None
    for _ in range(20):
        page, cursor = repo.partition_page(table='events', limit=100, start_resource=cursor)
        for row in page:
            data = row.data; kind = data.get('kind'); detail = data.get('details', {})
            if ((kind == 'improvement-preview' and detail.get('preview_id') == ident)
                    or (permission is not None and detail.get('permission_id') == permission
                        and kind in {'improvement-confirm', 'improvement-withdraw:' + permission})):
                rows.append(row)
        if cursor is None:
            return root, tuple(rows)
    raise AssertionError('bounded fixture history scan exhausted')


def parse(repo, ident, values=None):
    root, rows = values or arguments(repo, ident)
    result = discover(root, rows, deployment=repo.deployment, max_records=200, max_payload_bytes=1000000)
    assert {ref.key for ref in result.records} == {row.key for row in rows}
    assert not ({ref.key for ref in result.records} & {ref.key for ref in result.dependencies})
    return result


def test_actual_reference_preview_retains_no_invented_grant(world, improvement_case):
    preview = review(world, improvement_case)
    value = parse(world[1], preview['id'])
    assert value.grant is None and value.permission is None


@pytest.mark.parametrize('derived', [False, True])
def test_actual_reference_grant_preserves_explicit_derived_metadata_choice(world, improvement_case, derived):
    service = improvement_case[0]; preview = review(world, improvement_case)
    grant = service.confirm(world[5], request=request(world, preview, derived_review_metadata_acknowledged=derived),
                            expected_version=preview['state_version'], idempotency_key='lineage-confirm')
    value = parse(world[1], preview['id'])
    assert value.grant.key == grant_key(grant['id']) and value.permission.revision == 1
    assert grant['derived_review_metadata_allowed'] is derived
    assert not hasattr(value, 'usable')


def test_actual_expired_grant_and_repeated_withdrawal_remain_historical(world, improvement_case):
    service = improvement_case[0]; preview = review(world, improvement_case)
    grant = service.confirm(world[5], request=request(world, preview), expected_version=preview['state_version'],
                            idempotency_key='withdraw-confirm')
    world[2].value = world[2]() + 20001
    first = service.withdraw(world[5], grant['id'], expected_version=grant['state_version'], idempotency_key='withdraw-first')
    second = service.withdraw(world[5], grant['id'], expected_version=first['state_version'], idempotency_key='withdraw-repeat')
    assert first['withdrawn'] and not first['usable'] and second['state_version'] == first['state_version'] == 2
    value = parse(world[1], preview['id'])
    assert value.permission.revision == 2


def test_actual_frame_source_is_a_shared_dependency_not_owned_permission_payload(world, frame_read_case):
    reads, asset, *_ = frame_read_case
    key = Key('state', 'purpose#' + asset.data['purpose_id']); row = world[1].snapshot((key,))[key]
    world[1].transact((Write(key, row.revision, {**row.data, 'id': asset.data['purpose_id'],
        'source_permission_reference': 'synthetic-original-frame-record'}), reads.purposes.advance(reads.purposes.head())))
    service = ImprovementPermissions(reads, ImprovementConfig('frame-lineage-v1', 'Synthetic optional notice.', 60000, 8, 30000))
    preview = service.preview(world[5], request=ImprovementPreview(asset_ids=(asset.data['id'],)), idempotency_key='frame-preview')
    grant = service.confirm(world[5], request=request(world, preview, derived_review_metadata_acknowledged=True),
                            expected_version=preview['state_version'], idempotency_key='frame-confirm')
    value = parse(world[1], preview['id'])
    assert asset.key in {ref.key for ref in value.dependencies}
    assert asset.key not in {ref.key for ref in value.records}
    assert grant['assets'][0]['kind'] == 'frame'


@pytest.mark.parametrize('fault', ['missing-grant', 'missing-head', 'missing-confirmation', 'legacy-derived-field'])
def test_actual_history_missing_or_legacy_peers_hold(world, improvement_case, fault):
    service = improvement_case[0]; preview = review(world, improvement_case)
    grant = service.confirm(world[5], request=request(world, preview), expected_version=preview['state_version'],
                            idempotency_key='corruption-confirm')
    root, rows = deepcopy(arguments(world[1], preview['id']))
    if fault == 'missing-grant':rows = tuple(row for row in rows if row.key != grant_key(grant['id']))
    elif fault == 'missing-head':rows = tuple(row for row in rows if row.key != permission_key(grant['id']))
    elif fault == 'missing-confirmation':rows = tuple(row for row in rows if row.data.get('kind') != 'improvement-confirm')
    else:next(row for row in rows if row.key == grant_key(grant['id'])).data.pop('derived_review_metadata_allowed')
    with pytest.raises(ImprovementHistoryHeld):parse(world[1], preview['id'], (root, rows))
