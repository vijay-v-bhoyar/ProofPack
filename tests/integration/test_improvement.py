"""Separate synthetic owner attestations; no actual consent, AWS or learning proof."""
from dataclasses import replace
from uuid import uuid4
import json
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world, repository_factory, invite_and_join, proof
from test_access_lifecycle import publication_case
from test_asset_reads import frame_read_case
from test_references import reference_case, upload
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied, Role
from proofpack.evidence.improvement import (ImprovementConfig, ImprovementPermissions, ImprovementPreview,
    ImprovementConfirmation, ImprovementLimited, permission_key, grant_key, preview_key)
from proofpack.evidence.objects import EvidenceObjects
from proofpack.evidence.reads import AssetReads
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable
from proofpack.runtime.control import DATA, RuntimeControl


@pytest.fixture
def improvement_case(world, reference_case):
    purposes, references, objects, *_ = reference_case
    asset = upload(world, reference_case)
    reads = AssetReads(purposes, EvidenceObjects(objects.client, objects.config), objects,
        reads_per_minute=16, max_concurrent=1, read_window_ms=5000)
    service = ImprovementPermissions(reads, ImprovementConfig('optional-synthetic-v1',
        'Synthetic separate optional-use notice; no real consent.', 60000, 8, 30000))
    return service, asset['id'], references


def review(world, case, key='review'):
    return case[0].preview(world[5], request=ImprovementPreview(asset_ids=(case[1],)), idempotency_key=key)


def request(world, preview, **changes):
    fields = dict(preview_id=preview['id'], confirmed_scope_sha256=preview['scope_sha256'],
        documented_permission_reference='synthetic-separate-authorization', notice_version=preview['notice']['version'],
        notice_sha256=preview['notice']['sha256'], optional_improvement_acknowledged=True, limitations_acknowledged=True,
        expires_at_ms=world[2]()+20000)
    fields.update(changes);return ImprovementConfirmation(**fields)


def confirm(world, case):
    preview = review(world, case)
    return case[0].confirm(world[5], request=request(world, preview), expected_version=preview['state_version'], idempotency_key='confirm')


def test_separate_grant_preserves_operational_flags_and_never_copies_media(world, improvement_case):
    service, asset, _ = improvement_case;epoch = service.purposes.head();preview = review(world, improvement_case)
    result = service.confirm(world[5], request=request(world, preview), expected_version=preview['state_version'], idempotency_key='confirm')
    assert result['usable'] and result['optional_improvement'] and not result['optional_publicity']
    assert not result['physical_truth_verified'] and not result['independence_verified'] and not result['rights_independently_verified']
    assert service.purposes.head().data['epoch'] == epoch.data['epoch']+1
    original = service.purposes.permitted(preview['assets'][0]['purpose_id'])
    assert original.data['allowed_uses'] == ['operation'] and original.data['optional_improvement'] is False
    for secret in ('object_key', 'object_version', 'session_id', 'cookie', 'owner_access', 'runtime_binding'):
        assert secret not in json.dumps(result)
    assert service.preview_read(world[5], preview['id'])['permission_id'] == result['id']
    assert len(service.list(world[5])['permissions']) == 1


def test_reviewer_authorization_requires_current_exact_scope_and_version(world, improvement_case):
    service, asset, _ = improvement_case;result = confirm(world, improvement_case)
    _, _, reviewer, *_ = invite_and_join(world, 'data-reviewer', roles=(Role.REVIEWER,))
    actor, rows, deadline = service.authorize(reviewer, result['id'], asset_ids=(asset,), expected_version=result['state_version'])
    assert actor.member.data['id'] == reviewer.member.data['id'] and DATA in rows and deadline == result['expires_at_ms']
    with pytest.raises(Denied): service.authorize(world[5], result['id'], asset_ids=(asset,), expected_version=result['state_version'])
    with pytest.raises(Denied): service.authorize(reviewer, result['id'], asset_ids=(str(uuid4()),), expected_version=result['state_version'])
    with pytest.raises(StoreConflict): service.authorize(reviewer, result['id'], asset_ids=(asset,), expected_version=99)
    assert service.get(reviewer, result['id'])['usable']
    with pytest.raises(Denied): service.preview(reviewer, request=ImprovementPreview(asset_ids=(asset,)), idempotency_key='bad-role')


@pytest.mark.parametrize('change', ['epoch', 'source', 'notice', 'expiry', 'runtime', 'session'])
def test_changed_review_context_cannot_confirm(world, improvement_case, change):
    service, asset, _ = improvement_case;preview = review(world, improvement_case);body = request(world, preview);actor = world[5]
    if change == 'epoch':
        epoch = service.purposes.head();world[1].transact((service.purposes.advance(epoch),))
    elif change == 'source':
        key = Key('state', 'asset#'+asset);row = world[1].snapshot((key,))[key]
        world[1].transact((Write(key, row.revision, {**row.data, 'read_denied': True}),))
    elif change == 'notice':
        service = ImprovementPermissions(service.assets, replace(service.config, notice_version='changed'))
    elif change == 'expiry': world[2].value += 30000
    elif change == 'runtime':
        RuntimeControl(world[0], instance_id=str(uuid4()), artifact_sha256='a'*64, controls_sha256='b'*64, environment='synthetic_demo').start()
    else: actor = world[0].resolve(world[0].login(proof(world[2])).cookie)
    with pytest.raises((Denied, StoreConflict, StoreUnavailable)):
        service.confirm(actor, request=body, expected_version=preview['state_version'], idempotency_key='changed')
    assert world[1].query(prefix='improvement-grant#', limit=20)[0] == []


@pytest.mark.parametrize('field,value', [('optional_improvement_acknowledged', False), ('limitations_acknowledged', False),
    ('notice_sha256', '0'*64), ('confirmed_scope_sha256', '0'*64), ('expires_at_ms', 999999999)])
def test_wrong_acknowledgment_notice_scope_or_lifetime_denied(world, improvement_case, field, value):
    preview = review(world, improvement_case)
    with pytest.raises((Denied, StoreConflict, ValueError)):
        improvement_case[0].confirm(world[5], request=request(world, preview, **{field:value}), expected_version=preview['state_version'], idempotency_key='bad')


def test_unknown_confirmation_and_withdrawal_retry_preserve_original_result(world, improvement_case):
    service = improvement_case[0];preview = review(world, improvement_case);body = request(world, preview)
    first = service.confirm(world[5], request=body, expected_version=preview['state_version'], idempotency_key='lost-confirm')
    world[2].value += 1
    second = service.confirm(world[5], request=body, expected_version=preview['state_version'], idempotency_key='lost-confirm')
    assert second == first and service.preview_read(world[5], preview['id'])['permission_id'] == first['id']
    before = service.purposes.head()
    withdrawn = service.withdraw(world[5], first['id'], expected_version=first['state_version'], idempotency_key='withdraw')
    again = service.withdraw(world[5], first['id'], expected_version=first['state_version'], idempotency_key='withdraw')
    assert withdrawn == again and withdrawn['withdrawn'] and not withdrawn['usable']
    assert service.purposes.head().data['epoch'] == before.data['epoch']+1
    assert service.get(world[5], first['id'])['grant_sha256'] == first['grant_sha256']


@pytest.mark.parametrize('cause', ['denied', 'expired', 'withdrawn_source', 'config'])
def test_held_sources_never_fall_back_to_operation_and_withdrawal_still_works(world, improvement_case, cause):
    service, asset, _ = improvement_case;result = confirm(world, improvement_case)
    if cause == 'denied':
        key = Key('state', 'asset#'+asset);row = world[1].snapshot((key,))[key]
        world[1].transact((Write(key, row.revision, {**row.data, 'read_denied': True, 'status': 'deleted'}),))
    elif cause == 'expired': world[2].value = result['expires_at_ms']
    elif cause == 'withdrawn_source':
        purpose = service.purposes.get(world[5], result['assets'][0]['purpose_id'])
        service.purposes.withdraw(world[5], ident=purpose['id'], expected_version=purpose['state_version'], idempotency_key='source-withdraw')
    else: service = ImprovementPermissions(service.assets, replace(service.config, notice_text='Changed optional notice'))
    assert not service.get(world[5], result['id'])['usable']
    _, _, reviewer, *_ = invite_and_join(world, 'reuse-reviewer', roles=(Role.REVIEWER,))
    with pytest.raises((StoreUnavailable, StoreConflict, Denied)):
        service.authorize(reviewer, result['id'], asset_ids=(asset,), expected_version=result['state_version'])
    assert service.withdraw(world[5], result['id'], expected_version=result['state_version'], idempotency_key='stop-reuse')['withdrawn']


def test_final_source_race_prevents_grant_and_does_not_advance_epoch(world, improvement_case, monkeypatch):
    service, asset, _ = improvement_case;preview = review(world, improvement_case);epoch = service.purposes.head();original = world[1].transact
    def transact(writes, checks=()):
        if any(w.key.resource.startswith('improvement-grant#') for w in writes):
            key = Key('state', 'asset#'+asset);row = world[1].snapshot((key,))[key]
            original((Write(key, row.revision, {**row.data, 'read_denied': True}),))
        return original(writes, checks)
    monkeypatch.setattr(world[1], 'transact', transact)
    with pytest.raises(StoreConflict): service.confirm(world[5], request=request(world, preview), expected_version=preview['state_version'], idempotency_key='race')
    assert service.purposes.head() == epoch and world[1].query(prefix='improvement-grant#', limit=20)[0] == []


def test_write_allowance_and_expired_owner_mfa_fail_closed(world, improvement_case):
    service = ImprovementPermissions(improvement_case[0].assets, replace(improvement_case[0].config, writes_per_minute=1))
    service.preview(world[5], request=ImprovementPreview(asset_ids=(improvement_case[1],)), idempotency_key='one')
    with pytest.raises(ImprovementLimited): service.preview(world[5], request=ImprovementPreview(asset_ids=(improvement_case[1],)), idempotency_key='two')
    world[2].value += 600001
    with pytest.raises(Denied): service.options(world[5])


@pytest.mark.parametrize('fault,status', [('origin',403),('csrf',403),('body',413),('extra',400)])
def test_http_guard_and_body_bound_before_optional_grant(world, improvement_case, fault, status):
    service, asset, _ = improvement_case
    app = create_app(access_service=world[0], app_origin='https://proofpack.test', runtime_control=service.runtime,
        purpose_service=service.purposes, asset_service=service.assets, improvement_service=service)
    headers = {'Origin':'https://proofpack.test','X-CSRF-Token':world[4].csrf,'Idempotency-Key':'http-preview'}
    body = {'asset_ids':[asset]}
    if fault == 'origin': headers['Origin']='https://foreign.invalid'
    elif fault == 'csrf': headers['X-CSRF-Token']='wrong'
    elif fault == 'body': body['extra']='x'*9000
    else: body['optional_publicity']=True
    with TestClient(app, base_url='https://proofpack.test', cookies={COOKIE:world[4].cookie}) as client:
        response = client.post('/api/v1/privacy/improvement-previews', json=body, headers=headers)
        assert response.status_code == status, response.text
    assert world[1].query(prefix='improvement-grant#',limit=20)[0] == []


def test_corrupt_immutable_grant_is_never_usable(world, improvement_case):
    service = improvement_case[0];result=confirm(world,improvement_case)
    key=grant_key(result['id']);row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{**row.data,'optional_publicity':True}),))
    with pytest.raises(StoreUnavailable): service.get(world[5],result['id'])


def test_frame_requires_documented_original_permission_and_keeps_recorded_origin(world, frame_read_case):
    reads,asset,*_=frame_read_case
    service=ImprovementPermissions(reads,ImprovementConfig('optional-frame-v1','Synthetic optional notice.',60000,8,30000))
    with pytest.raises(StoreUnavailable):service.preview(world[5],request=ImprovementPreview(asset_ids=(asset.data['id'],)),idempotency_key='missing-reference')
    key=Key('state','purpose#'+asset.data['purpose_id']);row=world[1].snapshot((key,))[key];epoch=reads.purposes.head()
    # Complete this abbreviated synthetic fixture; never real rights or consent proof.
    world[1].transact((Write(key,row.revision,{**row.data,'id':asset.data['purpose_id'],'source_permission_reference':'synthetic-original-frame-record'}),reads.purposes.advance(epoch)))
    preview=service.preview(world[5],request=ImprovementPreview(asset_ids=(asset.data['id'],)),idempotency_key='frame-preview')
    value=service.confirm(world[5],request=request(world,preview),expected_version=preview['state_version'],idempotency_key='frame-confirm')
    assert value['usable'] and value['assets'][0]['kind']=='frame' and value['assets'][0]['data_origin']=='synthetic'


def test_notice_history_and_tighter_policy_do_not_silently_renew_old_grants(world, improvement_case):
    service=improvement_case[0];value=confirm(world,improvement_case)
    changed=ImprovementPermissions(service.assets,replace(service.config,notice_text='New terms'))
    old=changed.get(world[5],value['id']);assert not old['usable'] and old['notice']['text']==service.config.notice_text
    tighter=ImprovementPermissions(service.assets,replace(service.config,max_lifetime_ms=10000))
    assert not tighter.get(world[5],value['id'])['usable']
    preview=review(world,improvement_case,key='old-limits')
    altered=ImprovementPermissions(service.assets,replace(service.config,review_ms=1000))
    with pytest.raises(StoreConflict):altered.confirm(world[5],request=request(world,preview),expected_version=preview['state_version'],idempotency_key='changed-limits')


def test_requested_expiry_is_rechecked_at_final_commit(world, improvement_case, monkeypatch):
    service=improvement_case[0];preview=review(world,improvement_case);body=request(world,preview);original=world[0]._record
    def record(*args,**kwargs):
        if args[1]=='improvement-confirm':
            before=kwargs['before_commit']
            def expires():world[2].value=body.expires_at_ms;before()
            kwargs['before_commit']=expires
        return original(*args,**kwargs)
    monkeypatch.setattr(world[0],'_record',record)
    with pytest.raises(StoreUnavailable):service.confirm(world[5],request=body,expected_version=preview['state_version'],idempotency_key='last-millisecond')
    assert world[1].query(prefix='improvement-grant#',limit=20)[0]==[]


def test_http_round_trip_returns_integer_metadata_and_denies_operator_access(world, improvement_case):
    service,asset,_=improvement_case
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,
        purpose_service=service.purposes,asset_service=service.assets,improvement_service=service)
    headers={'Origin':'https://proofpack.test','X-CSRF-Token':world[4].csrf,'Idempotency-Key':'http-review'}
    with TestClient(app,base_url='https://proofpack.test',cookies={COOKIE:world[4].cookie}) as client:
        response=client.post('/api/v1/privacy/improvement-previews',json={'asset_ids':[asset]},headers=headers)
        assert response.status_code==201;preview=response.json();assert type(preview['assets'][0]['expires_at_ms']) is int
        response=client.post('/api/v1/privacy/improvement-permissions',json=request(world,preview).model_dump(mode='json'),
            headers={**headers,'Idempotency-Key':'http-confirm','If-Match':str(preview['state_version'])})
        assert response.status_code==201 and response.json()['usable']
        ident=response.json()['id'];assert client.get('/api/v1/privacy/improvement-permissions/'+ident).status_code==200
        _,credentials,_,*_ = invite_and_join(world,'no-improvement-role')
        client.cookies.clear();client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/privacy/improvement-permissions/'+ident).status_code==403


def test_another_current_owner_can_withdraw_without_rewriting_original_attestation(world, improvement_case):
    service=improvement_case[0];value=confirm(world,improvement_case)
    _,_,successor,*_=invite_and_join(world,'data-successor',roles=(Role.OWNER,),mfa=True)
    result=service.withdraw(successor,value['id'],expected_version=value['state_version'],idempotency_key='successor-withdraw')
    assert result['withdrawn'] and result['grant_sha256']==value['grant_sha256']
    assert world[1].snapshot((grant_key(value['id']),))[grant_key(value['id'])].data['owner_id']==world[3]
