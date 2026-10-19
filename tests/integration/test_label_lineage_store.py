import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_labels import review_case,request_for
from proofpack.evidence.repository import StoreUnavailable,StoreConflict
from proofpack.auth.policy import Denied
from proofpack.runtime.control import DATA
from dataclasses import replace
from proofpack.evidence.repository import Key
from proofpack.evidence.label_lineage import discover,LabelHistoryHeld
from proofpack.capture.service import observation_key
from proofpack.recipes.service import revision_key as recipe_key
from proofpack.stations.service import inspection_key
from proofpack.auth.policy import Role
from proofpack.auth.service import user_key
from test_access_lifecycle import invite_and_join,proof
from test_capture_family_store import capture_rows,closed
from test_original_frames import original_case
from proofpack.evidence.purposes import DataPurposes
from proofpack.review.labels import OutcomeLabels,ReviewTuple,LabelRequest,GroundCount
from proofpack.recipes.models import PartClass
from proofpack.evidence.erasure import AssetErasure
from proofpack.evidence.erasure_models import ErasurePreview,ErasureConfirmation


def all_rows(repo):
    result=[]
    for table in ('state','events'):
        cursor=None
        for _ in range(100):
            rows,cursor=repo.partition_page(table=table,limit=100,start_resource=cursor);result.extend(rows)
            if cursor is None:break
        else:raise AssertionError('bounded label fixture inventory exhausted')
    return result


def arguments(repo,root):
    inventory=all_rows(repo)
    ids={r.data['id'] for r in inventory if r.key.resource.startswith('label-revision#') and r.data.get('source_context',{}).get('inspection_id')==root.data['id']}
    selected=[];purposes=set()
    for row in inventory:
        if row.key.table=='state' and row.key.resource.startswith(('label#','label-revision#')) and row.data.get('id') in ids:
            selected.append(row)
            if 'source_context' in row.data:purposes.update(s['purpose_id'] for s in row.data['source_context']['sources'])
        elif row.key.table=='events' and row.data.get('details',{}).get('label_id') in ids and (row.data['kind']=='label-create' or row.data['kind'].startswith('label-revise:')):selected.append(row)
    keys=tuple(Key('state','purpose#'+p) for p in sorted(purposes));values=repo.snapshot(keys) if keys else {}
    recipe_id=recipe_key(root.data['recipe_id'],int(root.data['recipe_revision']))
    return (tuple(selected),capture_rows(repo,root.data['id']),repo.snapshot((recipe_id,))[recipe_id],tuple(values[k] for k in keys))


def parse(repo,root,values=None):
    rows,capture,recipe,purposes=values or arguments(repo,root)
    result=discover(root,rows,capture_rows=capture,recipe=recipe,purpose_rows=purposes,deployment=repo.deployment,max_records=2000,max_payload_bytes=4000000)
    assert {r.key for r in result.records}=={r.key for r in rows}
    assert not any(r.key.resource.startswith(('purpose#','user#','data-','recipe-','label-quota#')) for r in result.records)
    return result


def test_source_expiry_during_label_preparation_cannot_leave_a_committed_label(world,review_case,monkeypatch):
    service,reviewer,credentials,tuple_,started,purpose=review_case
    request=request_for(review_case);repo=world[1];before=repo.snapshot((DATA,))[DATA]
    deadline=int(repo.snapshot((purpose,))[purpose].data['expires_at_ms'])
    prepare=service.access._prepare_linked;seen=False
    def expire(operation,writes,checks=()):
        nonlocal seen
        result=prepare(operation,writes,checks)
        if operation=='label-create':seen=True;world[2].value=deadline
        return result
    monkeypatch.setattr(service.access,'_prepare_linked',expire)
    with pytest.raises((StoreUnavailable,StoreConflict,Denied)):
        service.write(reviewer,request=request,idempotency_key='label-final-expiry')
    assert seen
    assert repo.query(prefix='label#',limit=20)[0]==[], 'expired source must not persist a label before withholding its reply'
    assert repo.query(prefix='label-revision#',limit=20)[0]==[]
    assert repo.snapshot((DATA,))[DATA]==before


def test_source_expiry_during_label_revision_preserves_original_head_and_data(world,review_case,monkeypatch):
    service,reviewer,credentials,tuple_,started,purpose=review_case;repo=world[1]
    first=service.write(reviewer,request=request_for(review_case),idempotency_key='first-before-expiry')
    request=request_for(review_case,note='Revised synthetic judgment');before=repo.snapshot((DATA,))[DATA]
    labels=repo.query(prefix='label#',limit=20)[0];revisions=repo.query(prefix='label-revision#',limit=20)[0]
    quotas=repo.query(prefix='label-quota#',limit=20)[0]
    deadline=int(repo.snapshot((purpose,))[purpose].data['expires_at_ms']);prepare=service.access._prepare_linked;seen=False
    def expire(operation,writes,checks=()):
        nonlocal seen
        result=prepare(operation,writes,checks)
        if operation=='label-revise:'+first['id']:seen=True;world[2].value=deadline
        return result
    monkeypatch.setattr(service.access,'_prepare_linked',expire)
    with pytest.raises((StoreUnavailable,StoreConflict,Denied)):
        service.write(reviewer,request=request,ident=first['id'],expected_version=1,idempotency_key='revision-final-expiry')
    assert seen and repo.query(prefix='label#',limit=20)[0]==labels
    assert repo.query(prefix='label-revision#',limit=20)[0]==revisions
    assert repo.query(prefix='label-quota#',limit=20)[0]==quotas and repo.snapshot((DATA,))[DATA]==before


def test_actual_revision_chain_remains_metadata_after_closed_capture(world,review_case,publication_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case
    first=service.write(reviewer,request=request_for(review_case),idempotency_key='lineage-first')
    service.write(reviewer,request=request_for(review_case,note='Corrected synthetic note'),ident=first['id'],expected_version=1,idempotency_key='lineage-second')
    root=closed(world,publication_case);result=parse(world[1],root)
    assert len(result.records)==5 and any(link.kind=='previous_label_revision' for link in result.links)


@pytest.mark.parametrize('missing',['head','previous','event'])
def test_actual_missing_head_revision_or_audit_is_held(world,review_case,publication_case,missing):
    service,reviewer,*_=review_case
    first=service.write(reviewer,request=request_for(review_case),idempotency_key='missing-first')
    service.write(reviewer,request=request_for(review_case,note='Second actual fixture revision'),ident=first['id'],expected_version=1,idempotency_key='missing-second')
    root=closed(world,publication_case);rows,capture,recipe,purposes=arguments(world[1],root)
    if missing=='head':rows=tuple(r for r in rows if not r.key.resource.startswith('label#'))
    elif missing=='previous':rows=tuple(r for r in rows if not(r.key.resource.startswith('label-revision#') and r.data['revision']==1))
    else:rows=tuple(r for r in rows if not(r.key.table=='events' and r.data['details']['revision']==1))
    with pytest.raises(LabelHistoryHeld):parse(world[1],root,(rows,capture,recipe,purposes))


def test_two_independent_label_heads_and_different_revision_author_keep_conflict_flags(world,review_case,publication_case):
    service,reviewer,*_=review_case
    first=service.write(reviewer,request=request_for(review_case),idempotency_key='author-first')
    _,_,other,*_=invite_and_join(world,'other-label-reviewer',roles=(Role.REVIEWER,))
    revised=service.write(other,request=request_for(review_case,note='Different reviewer revision'),ident=first['id'],expected_version=1,idempotency_key='author-revise')
    assert revised['conflict_codes']==['different_revision_author']
    service.write(reviewer,request=request_for(review_case,note='Second label head'),idempotency_key='second-head')
    result=parse(world[1],closed(world,publication_case))
    assert sum(r.key.resource.startswith('label#') for r in result.records)==2


def test_originating_operator_can_declare_but_not_verify_independence(world,review_case,publication_case):
    service,reviewer,*_=review_case;root=closed(world,publication_case);old_operator=publication_case[3]
    member=world[1].snapshot((user_key(old_operator.member.data['id']),))[user_key(old_operator.member.data['id'])]
    world[0].change_access(world[5],user_id=member.data['id'],roles=(Role.OPERATOR,Role.REVIEWER),enabled=True,
        expected_version=int(member.data['access_version']),idempotency_key='operator-reviewer-grant')
    actor=world[0].resolve(world[0].login(proof(world[2],'operator')).cookie)
    label=service.write(actor,request=request_for(review_case),idempotency_key='self-review')
    assert label['conflict_codes']==['originating_operator'] and label['independence_verified'] is False
    assert parse(world[1],root).records


def test_actual_withdrawal_keeps_historical_labels_but_does_not_restore_get_permission(world,review_case,publication_case,original_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case
    # The existing original_case fixture completes the abbreviated purpose
    # attestation so this exercises the public withdrawal service normally.
    label=service.write(reviewer,request=request_for(review_case),idempotency_key='before-withdrawal')
    root=closed(world,publication_case);row=world[1].snapshot((purpose,))[purpose]
    service.purposes.withdraw(world[5],ident=purpose.resource.split('#',1)[1],expected_version=row.revision,idempotency_key='withdraw-label-purpose')
    assert parse(world[1],root).records
    with pytest.raises(StoreUnavailable):service.get(reviewer,label['id'])


def test_actual_asset_denial_preserves_label_lineage_without_byte_delivery(world,review_case,publication_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case
    label=service.write(reviewer,request=request_for(review_case),idempotency_key='before-denial')
    root=closed(world,publication_case)
    ob=world[1].snapshot((observation_key(tuple_.before_observation_id),))[observation_key(tuple_.before_observation_id)]
    objects=publication_case[7]
    from proofpack.evidence.objects import ReferenceObjects
    erasure=AssetErasure(service.purposes,objects,ReferenceObjects(objects.client,objects.config),review_ms=30000,jobs_per_minute=8,lease_ms=15000,version_page_size=3)
    preview=erasure.preview(world[5],request=ErasurePreview(asset_ids=(ob.data['asset_id'],)),idempotency_key='label-asset-preview')
    erasure.confirm(world[5],request=ErasureConfirmation(preview_id=preview['id'],confirmed_digest=preview['scope_sha256'],
        erase_asset_versions_acknowledged=True,understands_remaining_metadata_and_backups=True),expected_version=preview['state_version'],idempotency_key='label-asset-deny')
    assert parse(world[1],root).records
    with pytest.raises(StoreUnavailable):service.get(reviewer,label['id'])


def test_actual_selected_original_manifest_is_validated_as_a_distinct_historical_source(world,original_case,publication_case):
    reads,observe,operator,objects,purpose,started,capture=original_case;ob,_,_=observe()
    _,_,reviewer,*_=invite_and_join(world,'original-label-reviewer',roles=(Role.REVIEWER,))
    labels=OutcomeLabels(DataPurposes(world[0],capture.stations.runtime,max_lifetime_ms=60000),writes_per_minute=8,max_duration_ms=60000,review_validity_ms=30000)
    tuple_=ReviewTuple(before_observation_id=ob.data['id']);context=labels.context(reviewer,tuple_)
    request=LabelRequest(**tuple_.model_dump(),source_context_sha256=context['source_context_sha256'],data_epoch=context['data_epoch'],
        outcome='incorrect_finding',ground_truth_counts=tuple(GroundCount(part_class=part,count=1) for part in PartClass),
        method='synthetic_fixture',duration_ms=1000,independence_declared=True,note='Selected-original synthetic review')
    label=labels.write(reviewer,request=request,idempotency_key='original-label')
    assert len(label['source_context']['sources'])==2
    result=parse(world[1],closed(world,publication_case))
    assert sum(link.kind=='label_media_source' for link in result.links)==2


def test_closed_capture_without_labels_does_not_invent_a_label_or_purpose_grant(world,review_case,publication_case):
    result=parse(world[1],closed(world,publication_case))
    assert result.records==() and result.purposes==()
