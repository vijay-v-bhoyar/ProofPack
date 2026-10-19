"""Owned DynamoDB Local transactions; synthetic identity and no real provider."""
from copy import deepcopy
import pytest
from test_access_lifecycle import repository_factory, world, proof
from proofpack.auth.policy import Role
from proofpack.auth.service import digest, invitation_key
from proofpack.evidence.repository import Write
from proofpack.evidence.invitation_history import discover, InvitationHistoryLimits, InvitationHistoryHeld


def snapshot(repository):
    result=[]
    for table in ('state','events'):
        page,cursor=repository.partition_page(table=table,limit=100)
        assert cursor is None, 'owned fixture snapshot must fit its original finite bound'
        result.extend(page)
    return tuple(result)


def selected(rows):
    roots=tuple(row for row in rows if row.key.table=='state' and row.key.resource.startswith('invitation#'))
    peers=tuple(row for row in rows if row.data.get('resource_bindings',{}).get('operation') in
        {'invite','accept-invite','decline-invite','revoke-invite'})
    return roots,peers


def parse(repository,rows):
    roots,peers=selected(rows)
    return discover(roots,peers,deployment=repository.deployment,limits=InvitationHistoryLimits(100,1000000,200,10000,200000),
        deadline_ns=10000,tick=lambda:1,checkpoint=lambda:None)


def create(world,mode):
    access,repo,clock,_,credentials,_=world
    owner=lambda:access.resolve(credentials.cookie)
    def invite(subject,key,ttl=60):return access.create_invitation(owner(),target_subject=subject,
        target_email=subject+'@example.invalid',roles=[Role.OPERATOR],ttl_seconds=ttl,idempotency_key=key)
    first=invite('first','create',1 if mode in {'expired','expired-revoked','cascade'} else 60)
    if mode in {'accepted','declined','declined-revoked'}:
        restricted=access.login(proof(clock,'first',mfa=False),invitation_id=first['id'])
        actor=access.resolve(restricted.cookie,allow_invitee=True)
        if mode=='accepted':access.accept_invitation(actor,invitation_id=first['id'],capability=first['capability'],
            idempotency_key='accept',notice_version=access.config.notice_version,notice_sha256=digest(access.config.notice_text))
        else:access.decline_invitation(actor,invitation_id=first['id'],idempotency_key='decline')
    if mode in {'expired','expired-revoked','cascade'}:
        clock.value+=1100;invite('second','second',1 if mode=='cascade' else 60)
    if mode=='cascade':clock.value+=1100;invite('third','third')
    if mode in {'revoked','repeat-revoked','declined-revoked','expired-revoked'}:
        key=invitation_key(first['id']);row=repo.snapshot((key,))[key]
        access.revoke_invitation(owner(),invitation_id=first['id'],expected_revision=row.revision,idempotency_key='revoke')
    if mode=='repeat-revoked':
        key=invitation_key(first['id']);row=repo.snapshot((key,))[key]
        access.revoke_invitation(owner(),invitation_id=first['id'],expected_revision=row.revision,idempotency_key='repeat')
    if mode=='checked-pending':invite('second','second')
    return first


@pytest.mark.parametrize('mode',['pending','accepted','declined','revoked','repeat-revoked','expired',
    'expired-revoked','declined-revoked','cascade','checked-pending'])
def test_stored_versioned_lifecycle_is_read_only_and_non_authorizing(world,mode):
    create(world,mode);repo=world[1];before=snapshot(repo)
    result=parse(repo,before)
    assert result.historical is True and result.read_only is True
    assert result.grants_current_access is False and result.can_confirm_cleanup is False
    assert result.families==len(selected(before)[0]) and snapshot(repo)==before


def test_legacy_shape_acceptance_preserves_missing_history_on_local_store(world):
    access,repo,clock,_,credentials,_=world;first=create(world,'pending');key=invitation_key(first['id'])
    row=repo.snapshot((key,))[key];data=deepcopy(row.data)
    for name in ('history_schema_version','created_at_ms','ttl_seconds'):data.pop(name)
    repo.transact((Write(key,row.revision,data),))
    restricted=access.login(proof(clock,'first',mfa=False),invitation_id=first['id'])
    result=access.accept_invitation(access.resolve(restricted.cookie,allow_invitee=True),invitation_id=first['id'],
        capability=first['capability'],idempotency_key='legacy',notice_version=access.config.notice_version,
        notice_sha256=digest(access.config.notice_text))
    assert result['sign_in_required'] is True
    persisted=repo.snapshot((key,))[key]
    assert 'history_schema_version' not in persisted.data and 'notice_version' not in persisted.data
    before=snapshot(repo)
    with pytest.raises(InvitationHistoryHeld):parse(repo,before)
    assert snapshot(repo)==before


@pytest.mark.parametrize('fault',['boolean-schema','undeclared-field'])
def test_malformed_stored_provenance_holds_without_mutation(world,fault):
    first=create(world,'pending');repo=world[1];key=invitation_key(first['id']);row=repo.snapshot((key,))[key]
    data=deepcopy(row.data)
    if fault=='boolean-schema':data['history_schema_version']=True
    else:data['inspection_id']='00000000-0000-0000-0000-000000000099'
    repo.transact((Write(key,row.revision,data),));before=snapshot(repo)
    with pytest.raises(InvitationHistoryHeld):parse(repo,before)
    assert snapshot(repo)==before
