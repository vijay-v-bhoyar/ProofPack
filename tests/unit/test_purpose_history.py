"""Real purpose/access writers, modeled store and explicit synthetic authority."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from decimal import Decimal
from itertools import count
from types import MethodType, SimpleNamespace
import pytest
from botocore.client import BaseClient
from test_privacy_admission import ModelRepository, ident
from proofpack.auth.policy import Role
from proofpack.auth.service import AccessService, Actor, HEAD, RUNTIME, digest
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.purposes import DataPurposes, PurposeRequest, purpose_key
from proofpack.evidence.originals import ORIGINAL_NOTICE_SHA256
from proofpack.runtime.control import DATA


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    monkeypatch.setattr(BaseClient,'_make_api_call',lambda *a,**k:pytest.fail('pure purpose history invoked SDK'))


def family(mode='created',original=False):
    repo=ModelRepository(); clock=count(100)
    cookie=Row(Key('state','cookie#'+'c'*64),1,{'synthetic':'cookie'})
    session=Row(Key('state','session#'+ident(2)),1,{'id':ident(2),'issuer':'https://synthetic.test','subject':'synthetic'})
    member=Row(Key('state','user#'+ident(3)),1,{'id':ident(3),'access_version':1})
    head=Row(HEAD,1,{'synthetic':'head'})
    actor=Actor(cookie,session,member,head,SimpleNamespace(roles=frozenset({Role.OWNER})))
    repo.rows.update((r.key,r) for r in (cookie,session,member,head,Row(RUNTIME,1,{'synthetic':'runtime'}),Row(DATA,1,{'epoch':1,'changed_at_ms':0})))
    access=SimpleNamespace(repository=repo,now=lambda:next(clock),_fresh=lambda actor,*a,**k:actor,
        operational_notice=lambda actor:{'version':'synthetic-v1','sha256':digest('synthetic notice')})
    for name in ('_idempotency','_record','_prepare_linked','_commit'):
        setattr(access,name,MethodType(getattr(AccessService,name),access))
    runtime=SimpleNamespace(access=access,matches=lambda row:row is not None)
    service=DataPurposes(access,runtime,max_lifetime_ms=10000)
    request=PurposeRequest(notice_version='synthetic-v1',notice_sha256=digest('synthetic notice'),
        source_permission_reference='synthetic-source',operational_use_acknowledged=True,expires_at_ms=1000,
        **({'original_capture_retention_acknowledged':True,'original_capture_notice_sha256':ORIGINAL_NOTICE_SHA256} if original else {}))
    result=service.create(actor,request=request,idempotency_key='create')
    if mode!='created':service.withdraw(actor,ident=result['id'],expected_version=1,idempotency_key='withdraw')
    if mode=='noop':service.withdraw(actor,ident=result['id'],expected_version=2,idempotency_key='noop')
    root=repo.rows[purpose_key(result['id'])]
    rows=tuple(r for k,r in repo.rows.items() if k.table=='events' or k.resource.startswith('idempotency#'))
    return root,rows,service,actor,repo


def limits():
    from proofpack.evidence.purpose_history import PurposeHistoryLimits
    return PurposeHistoryLimits(100,1_000_000,1000,10000,1_000_000)


def run(root,rows,**changes):
    from proofpack.evidence.purpose_history import discover
    return discover(root,rows,**(dict(deployment='synthetic',limits=limits(),deadline_ns=1000,
        tick=lambda:1,checkpoint=lambda:None)|changes))


@pytest.mark.parametrize('mode',['created','withdrawn','noop'])
@pytest.mark.parametrize('original',[False,True])
def test_actual_writers_complete_history_is_frozen_private_and_not_rights_authority(mode,original):
    root,rows,_,_,repo=family(mode,original);before=deepcopy(repo.rows)
    result=run(root,rows)
    assert result.policy=='purpose-history-v1' and result.state==('ACTIVE_HISTORY' if mode=='created' else 'WITHDRAWN_HISTORY')
    assert len(result.records)==1+len(rows) and result.historical is True
    assert result.rights_independently_verified is False and result.can_confirm_cleanup is False
    assert result==run(root,rows) and repo.rows==before
    assert all(token not in repr(result) for token in (root.data['id'],ident(2),ident(3),'synthetic-source','cookie#'))
    with pytest.raises(FrozenInstanceError):result.work=0


@pytest.mark.parametrize('fault',['root_extra','root_revision','boolean_withdrawn','boolean_epoch','original_notice',
    'wrong_id','missing_create_event','missing_create_replay','missing_withdraw','duplicate','foreign','event_extra',
    'details_extra','result_extra','body_digest','purpose_digest','unexpected_peer','session_mismatch','future_create','withdraw_time'])
def test_corrupt_or_incomplete_history_never_returns_partial_result(fault):
    from proofpack.evidence.purpose_history import PurposeHistoryHeld
    root,rows,_,_,_=family('withdrawn',True);root=deepcopy(root);rows=deepcopy(rows);kwargs={}
    creation=next(r for r in rows if r.key.table=='events' and r.data['kind']=='purpose-create')
    replay=next(r for r in rows if r.key.table=='state' and r.data['resource_bindings']['operation']=='purpose-create')
    if fault=='root_extra':root.data['copied_inspection']='PRIVATE'
    elif fault=='root_revision':root=replace(root,revision=3)
    elif fault=='boolean_withdrawn':root.data['withdrawn']=1
    elif fault=='boolean_epoch':root.data['owner_access_version']=True
    elif fault=='original_notice':root.data['original_capture_notice_text']='wrong'
    elif fault=='wrong_id':root.data['id']=ident(99)
    elif fault=='missing_create_event':rows=tuple(r for r in rows if r!=creation)
    elif fault=='missing_create_replay':rows=tuple(r for r in rows if r!=replay)
    elif fault=='missing_withdraw':rows=tuple(r for r in rows if r.data['resource_bindings']['operation']=='purpose-create')
    elif fault=='duplicate':rows+=rows[:1]
    elif fault=='foreign':kwargs['deployment']='foreign'
    elif fault=='event_extra':creation.data['copied_inspection']='PRIVATE'
    elif fault=='details_extra':creation.data['details']['copied_inspection']='PRIVATE'
    elif fault=='result_extra':replay.data['result']['copied_inspection']='PRIVATE'
    elif fault=='body_digest':replay.data['body_hash']='0'*64
    elif fault=='purpose_digest':root.data['source_permission_reference']='different-source'
    elif fault=='unexpected_peer':creation.data['resource_bindings']['writes'][0]['resource']='other'
    elif fault=='session_mismatch':creation.data['session_id']=ident(99)
    elif fault=='future_create':root.data['created_at_ms']=999
    elif fault=='withdraw_time':root.data['withdrawn_at_ms']=0
    with pytest.raises(PurposeHistoryHeld):run(root,rows,**kwargs)


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
def test_independent_exact_limits_and_one_below(field):
    from proofpack.evidence.purpose_history import PurposeHistoryHeld
    root,rows,*_=family('noop');result=run(root,rows)
    actual={'max_records':len(result.records),'max_payload_bytes':result.payload_bytes,
        'max_dependencies':len(result.dependencies),'max_work':result.work,'max_summary_bytes':result.summary_bytes}[field]
    assert actual>1 and run(root,rows,limits=replace(limits(),**{field:actual}))==result
    with pytest.raises(PurposeHistoryHeld):run(root,rows,limits=replace(limits(),**{field:actual-1}))


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[True,0,-1,1.5,'3',2**63])
def test_limits_reject_implicit_or_unbounded_values(field,value):
    with pytest.raises(ValueError):replace(limits(),**{field:value})


def test_ambiguous_repeated_noop_outputs_hold_instead_of_inventing_pairing():
    from proofpack.evidence.purpose_history import PurposeHistoryHeld
    root,rows,service,actor,repo=family('noop')
    service.withdraw(actor,ident=root.data['id'],expected_version=2,idempotency_key='another-noop')
    rows=tuple(r for k,r in repo.rows.items() if k.table=='events' or k.resource.startswith('idempotency#'))
    with pytest.raises(PurposeHistoryHeld):run(root,rows)


def test_storage_decimal_roundtrip_does_not_change_provenance():
    root,rows,*_=family('noop',True)
    def decimal(value):
        if type(value)is int:return Decimal(value)
        if type(value)is dict:return {k:decimal(v) for k,v in value.items()}
        if type(value)is list:return [decimal(v) for v in value]
        return value
    assert run(replace(root,data=decimal(root.data)),tuple(replace(r,data=decimal(r.data)) for r in rows))==run(root,rows)


@pytest.mark.parametrize('fault',['expired','backwards','checkpoint'])
def test_original_execution_fences(fault):
    from proofpack.evidence.purpose_history import PurposeHistoryHeld
    root,rows,*_=family();kwargs={}
    if fault=='expired':kwargs['tick']=lambda:1000
    elif fault=='backwards':
        ticks=iter([2,1]);kwargs['tick']=lambda:next(ticks)
    else:
        def checkpoint():raise RuntimeError('original authority revoked')
        kwargs['checkpoint']=checkpoint
        with pytest.raises(RuntimeError,match='original authority revoked'):run(root,rows,**kwargs)
        return
    with pytest.raises(PurposeHistoryHeld):run(root,rows,**kwargs)


@pytest.mark.parametrize('fault',['extra_write','missing_runtime','missing_data','foreign_user','wrong_session'])
def test_same_envelope_corruption_cannot_bypass_operation_specific_dependencies(fault):
    from proofpack.evidence.purpose_history import PurposeHistoryHeld
    root,rows,*_=family()
    binding=deepcopy(rows[0].data['resource_bindings'])
    if fault=='extra_write':
        extra=deepcopy(binding['writes'][0]);extra['resource']='unrelated'
        binding['writes'].append(extra);binding['writes'].sort(key=lambda r:(r['table'],r['resource']))
    elif fault=='missing_runtime':binding['checks']=[r for r in binding['checks'] if r['resource']!=RUNTIME.resource]
    elif fault=='missing_data':binding['checks']=[r for r in binding['checks'] if r['resource']!=DATA.resource]
    elif fault=='foreign_user':
        for r in binding['checks']:
            if r['resource'].startswith('user#'):r['resource']='user#'+ident(99)
    elif fault=='wrong_session':
        for r in binding['checks']:
            if r['resource'].startswith('session#'):r['resource']='session#'+ident(99)
    changed=tuple(replace(r,data={**r.data,'resource_bindings':deepcopy(binding)}) for r in rows)
    with pytest.raises(PurposeHistoryHeld):run(root,changed)
