"""Real access operations on modeled storage; identities are synthetic."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from decimal import Decimal
import pytest
from botocore.client import BaseClient
from test_auth_head_integrity import world
from proofpack.auth.service import IdentityProof, digest, invitation_key, HEAD
from proofpack.auth.policy import Role


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('pure invitation history attempted SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def family(mode='pending'):
    access,repo,proof,credentials,_=world();clock=[1000]
    access.clock_ms=lambda:clock[0]
    access.config=replace(access.config,notice_version='synthetic-v1',notice_text='synthetic notice')
    owner=lambda:access.resolve(credentials.cookie)
    def invite(subject,key,ttl=60):return access.create_invitation(owner(),target_subject=subject,
        target_email=subject+'@example.test',roles=[Role.OPERATOR.value],ttl_seconds=ttl,idempotency_key=key)
    first=invite('first','create',1 if mode in {'expired','expired-revoked','cascade'} else 60)
    if mode in {'accepted','declined','declined-revoked'}:
        p=IdentityProof(proof.issuer,'first','first@example.test',True,False,1000,100000,'Synthetic invitee')
        restricted=access.login(p,invitation_id=first['id']);actor=access.resolve(restricted.cookie,allow_invitee=True)
        if mode=='accepted':access.accept_invitation(actor,invitation_id=first['id'],capability=first['capability'],
            idempotency_key='accept',notice_version='synthetic-v1',notice_sha256=digest('synthetic notice'))
        else:access.decline_invitation(actor,invitation_id=first['id'],idempotency_key='decline')
    if mode in {'expired','expired-revoked','cascade'}:
        clock[0]=2100;invite('second','second',1 if mode=='cascade' else 60)
    if mode=='cascade':clock[0]=3200;invite('third','third')
    if mode in {'revoked','repeat-revoked','declined-revoked','expired-revoked'}:
        row=repo.rows[invitation_key(first['id'])]
        access.revoke_invitation(owner(),invitation_id=first['id'],expected_revision=row.revision,idempotency_key='revoke')
    if mode=='repeat-revoked':
        row=repo.rows[invitation_key(first['id'])]
        access.revoke_invitation(owner(),invitation_id=first['id'],expected_revision=row.revision,idempotency_key='revoke-again')
    if mode=='checked-pending':invite('second','second')
    roots=tuple(row for key,row in repo.rows.items() if key.resource.startswith('invitation#'))
    peers=tuple(row for row in repo.rows.values() if row.data.get('resource_bindings',{}).get('operation') in
        {'invite','accept-invite','decline-invite','revoke-invite'})
    return roots,peers,access,repo,first,credentials


def limits():
    from proofpack.evidence.invitation_history import InvitationHistoryLimits
    return InvitationHistoryLimits(100,1000000,200,10000,200000)


def run(roots,rows,**kwargs):
    from proofpack.evidence.invitation_history import discover
    return discover(roots,rows,**({'deployment':'synthetic','limits':limits(),'deadline_ns':10000,
        'tick':lambda:1,'checkpoint':lambda:None}|kwargs))


def test_writer_retains_exact_creation_and_acceptance_provenance_with_unchanged_public_view():
    roots,_,access,repo,first,credentials=family('accepted');row=roots[0]
    assert row.data['history_schema_version']==1 and row.data['created_at_ms']==1000
    assert row.data['ttl_seconds']==60 and row.data['expires_at_ms']==61000
    assert row.data['notice_version']=='synthetic-v1' and row.data['notice_sha256']==digest('synthetic notice')
    public=access.public_invitation(row)
    assert set(public)=={'id','target_subject','roles','status','expires_at_ms','state_version','delivery_status'}
    assert not {'history_schema_version','created_at_ms','ttl_seconds','notice_sha256'}&public.keys()
    before=deepcopy(repo.rows)
    original=access.create_invitation(access.resolve(credentials.cookie),target_subject='first',target_email='first@example.test',
        roles=[Role.OPERATOR.value],ttl_seconds=60,idempotency_key='create')
    assert original==first and repo.rows==before


@pytest.mark.parametrize('mode',['pending','accepted','declined','revoked','repeat-revoked','expired',
    'expired-revoked','declined-revoked','cascade','checked-pending'])
def test_supported_lifecycles_are_private_frozen_complete_and_non_authorizing(mode):
    roots,rows,_,repo,*_=family(mode);before=deepcopy(repo.rows);result=run(roots,rows)
    assert result==run(tuple(reversed(roots)),tuple(reversed(rows))) and repo.rows==before
    assert len(result.records)==len(roots)+len(rows) and result.families==len(roots)
    assert result.historical is True and result.read_only is True
    assert result.grants_current_access is False and result.can_confirm_cleanup is False
    assert roots[0].data['id'] not in repr(result) and 'cookie#' not in repr(result)
    with pytest.raises(FrozenInstanceError):result.work=0


def test_legacy_live_invitation_still_accepts_but_cannot_claim_versioned_history():
    from proofpack.evidence.invitation_history import InvitationHistoryHeld
    roots,rows,access,repo,first,credentials=family('pending');root=roots[0]
    for name in ('history_schema_version','created_at_ms','ttl_seconds'):root.data.pop(name)
    repo.rows[root.key]=root
    p=IdentityProof(access.config.issuer,'first','first@example.test',True,False,1000,100000,'Legacy invitee')
    restricted=access.login(p,invitation_id=first['id'])
    result=access.accept_invitation(access.resolve(restricted.cookie,allow_invitee=True),invitation_id=first['id'],
        capability=first['capability'],idempotency_key='legacy',notice_version='synthetic-v1',notice_sha256=digest('synthetic notice'))
    assert result['sign_in_required'] is True
    assert 'history_schema_version' not in repo.rows[root.key].data and 'notice_version' not in repo.rows[root.key].data
    with pytest.raises(InvitationHistoryHeld):run(roots,rows)


@pytest.mark.parametrize('mode',['accepted','expired-revoked','declined-revoked','cascade'])
def test_integral_decimal_storage(mode):
    roots,rows,*_=family(mode)
    def convert(v):
        if type(v)is int:return Decimal(v)
        if type(v)is dict:return {k:convert(x) for k,x in v.items()}
        if type(v)is list:return [convert(x) for x in v]
        return v
    assert run(roots,rows)==run(tuple(replace(r,data=convert(r.data)) for r in roots),tuple(replace(r,data=convert(r.data)) for r in rows))


@pytest.mark.parametrize('fault',['extra-root','missing-time','boolean-schema','float-ttl','nonfinite-ttl',
    'ttl-expiry','bad-role','notice-digest','extra-event','extra-result','body-hash','missing-create',
    'missing-terminal','missing-peer','duplicate-root','duplicate-peer','foreign','bad-revision',
    'binding-sha','unknown-write','wrong-identity','wrong-scope','late-accept'])
def test_corrupt_or_incomplete_families_hold(fault):
    from proofpack.evidence.invitation_history import InvitationHistoryHeld
    roots,rows,*_=family('accepted');roots=deepcopy(roots);rows=deepcopy(rows);kwargs={}
    root=roots[0];event=next(r for r in rows if r.key.table=='events' and r.data['kind']=='accept-invite')
    replay=next(r for r in rows if r.key.table=='state' and r.data['resource_bindings']['operation']=='accept-invite')
    if fault=='extra-root':root.data['inspection_id']='private'
    elif fault=='missing-time':root.data.pop('created_at_ms')
    elif fault=='boolean-schema':root.data['history_schema_version']=True
    elif fault=='float-ttl':root.data['ttl_seconds']=60.0
    elif fault=='nonfinite-ttl':root.data['ttl_seconds']=Decimal('sNaN')
    elif fault=='ttl-expiry':root.data['ttl_seconds']=59
    elif fault=='bad-role':root.data['roles']=['administrator']
    elif fault=='notice-digest':root.data['notice_sha256']='0'*64
    elif fault=='extra-event':event.data['inspection_id']='private'
    elif fault=='extra-result':replay.data['result']['inspection_id']='private'
    elif fault=='body-hash':replay.data['body_hash']='0'*64
    elif fault=='missing-create':rows=tuple(r for r in rows if r.data['resource_bindings']['operation']!='invite')
    elif fault=='missing-terminal':rows=tuple(r for r in rows if r.data['resource_bindings']['operation']=='invite')
    elif fault=='missing-peer':rows=tuple(r for r in rows if r!=event)
    elif fault=='duplicate-root':roots+=roots[:1]
    elif fault=='duplicate-peer':rows+=rows[:1]
    elif fault=='foreign':kwargs['deployment']='foreign'
    elif fault=='bad-revision':roots=(replace(root,revision=root.revision+1),)
    elif fault in {'binding-sha','unknown-write','wrong-identity'}:
        for peer in (event,replay):
            refs=peer.data['resource_bindings']['writes']
            if fault=='binding-sha':next(v for v in refs if v['resource']==root.key.resource)['sha256']='0'*64
            elif fault=='unknown-write':
                refs.append({'table':'state','resource':'unknown-content','previous_revision':None,'revision':1,'sha256':'a'*64})
                refs.sort(key=lambda v:(v['table'],v['resource']))
            else:next(v for v in refs if v['resource'].startswith('identity#'))['sha256']='0'*64
    elif fault=='wrong-scope':event.data['actor_scope']='0'*64
    elif fault=='late-accept':event.data['at_ms']=root.data['expires_at_ms']
    with pytest.raises(InvitationHistoryHeld):run(roots,rows,**kwargs)


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
def test_exact_and_one_below_independent_limits(field):
    from proofpack.evidence.invitation_history import InvitationHistoryHeld
    roots,rows,*_=family('cascade');result=run(roots,rows)
    n={'max_records':len(result.records),'max_payload_bytes':result.payload_bytes,'max_dependencies':len(result.dependencies),
        'max_work':result.work,'max_summary_bytes':result.summary_bytes}[field]
    assert run(roots,rows,limits=replace(limits(),**{field:n}))==result
    with pytest.raises(InvitationHistoryHeld):run(roots,rows,limits=replace(limits(),**{field:n-1}))


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[True,0,-1,1.5,'1',2**63])
def test_invalid_limits(field,value):
    with pytest.raises(ValueError):replace(limits(),**{field:value})


@pytest.mark.parametrize('fault',['deadline','backwards','checkpoint','final-expiry','final-mutation'])
def test_original_fence_and_final_source_reconciliation(fault):
    from proofpack.evidence.invitation_history import InvitationHistoryHeld
    roots,rows,*_=family('accepted');measured=[0]
    def count():measured[0]+=1
    run(roots,rows,checkpoint=count);calls=[0];now=[1]
    def checkpoint():
        calls[0]+=1
        if calls[0]==measured[0]:
            if fault=='checkpoint':raise RuntimeError('original authority lost')
            if fault=='final-expiry':now[0]=10000
            if fault=='final-mutation':roots[0].data['ttl_seconds']+=1
    ticks=iter([1,0]);kwargs={'checkpoint':checkpoint,'tick':lambda:now[0]}
    if fault=='deadline':kwargs['tick']=lambda:10000
    if fault=='backwards':kwargs['tick']=lambda:next(ticks,0)
    with pytest.raises(RuntimeError if fault=='checkpoint' else InvitationHistoryHeld):run(roots,rows,**kwargs)
