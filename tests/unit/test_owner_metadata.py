"""Real authorization/runtime services on a modeled store; no provider or HTTP proof."""
from copy import deepcopy
from dataclasses import replace
from threading import Thread,Event
from types import SimpleNamespace
import pytest
from botocore.client import BaseClient
from test_privacy_admission import ModelRepository,ident
from proofpack.auth.service import AccessService,AuthConfig,BootstrapApproval,IdentityProof,RUNTIME
from proofpack.auth.policy import Denied,Role
from proofpack.evidence.repository import Key,Row,Write,StoreConflict,StoreUnavailable
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits,AdmissionHeld,GATE,REGISTRY
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits,OwnerMetadataBusy,OwnerMetadataLimited,request_key
from proofpack.runtime.control import RuntimeControl,DATA
from proofpack.runtime.ownership import ResourceOwner


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*a,**k):raise AssertionError('modeled owner request invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def world():
    repo=ModelRepository();clock=SimpleNamespace(value=1_000_000)
    def now():return clock.value
    issuer='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic'
    access=AccessService(repo,AuthConfig(repo.deployment,issuer,b'synthetic-not-a-real-key'*3,
        initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64),clock_ms=now)
    proof=IdentityProof(issuer,'owner','owner@example.invalid',True,True,now(),now()+3_600_000,'Synthetic owner')
    access.bootstrap(BootstrapApproval(issuer,'owner','a'*64),proof);credentials=access.login(proof);actor=access.resolve(credentials.cookie)
    runtime=RuntimeControl(access,instance_id=ident(90),artifact_sha256='a'*64,controls_sha256='b'*64,environment='test');runtime.start()
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(8,1000),clock_ms=now);admission.initialize('c'*64)
    owner=ResourceOwner();service=OwnerMetadataRequests(access,admission,owner,limits=OwnerMetadataLimits(10,20,100,20000),tick_ns=lambda:1)
    key=Key('state','inspection#'+ident(1));repo.rows[key]=Row(key,1,{'id':ident(1),'state':'CLOSED','private':'DO_NOT_DISCLOSE'})
    return service,actor,repo,clock,owner,proof


def create(service,actor,**changes):
    context=service.context(actor)
    return service.create(actor,**(dict(inspection_ids=(ident(1),),expected_gate_version=context['gate_version'],
        expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='owner-create')|changes))


def cancel(service,actor,request,**changes):
    return service.cancel(actor,**(dict(ident=request['id'],confirmed_scope_sha256=request['scope_sha256'],
        expected_request_version=request['state_version'],expected_gate_version=request['gate_version'],
        expected_control_version=request['control_version'],no_erasure_acknowledged=True,idempotency_key='owner-cancel')|changes))


def test_owner_request_hold_and_explicit_cancel_fence_without_enabling_or_erasing():
    service,actor,repo,clock,owner,_=world();before=deepcopy(repo.rows);created=create(service,actor)
    assert created['status']=='held' and created['drain_status']=='empty' and created['can_cancel']
    assert created['current_hold'] and not created['can_confirm_cleanup'] and not created['request_fulfilled']
    assert not created['inspection_enabled'] and not created['erasure_complete'] and owner.wait_for_drain(0)
    assert 'DO_NOT_DISCLOSE' not in repr(created) and 'creation_operation_resource' not in created
    original=repo.rows[request_key(created['id'])].data
    proof=service.admission.drained(request_id=created['id'],scope_sha256=created['scope_sha256'])
    ended=cancel(service,actor,created)
    assert ended['status']=='cancelled' and ended['gate_phase']=='OPEN' and not ended['current_hold']
    assert not ended['can_cancel'] and not ended['inspection_enabled'] and not ended['request_fulfilled']
    assert ended['gate_epoch']==created['gate_epoch']+1 and ended['control_version']==created['control_version']+1
    assert repo.rows[DATA].data['epoch']==before[DATA].data['epoch']+1
    assert repo.rows[request_key(created['id'])].data['scope']==original['scope']
    assert repo.rows[Key('state','inspection#'+ident(1))]==before[Key('state','inspection#'+ident(1))]
    with pytest.raises(AdmissionHeld):service.admission.assert_drained(proof)
    assert owner.wait_for_drain(0)


def test_replays_do_not_renew_change_scope_or_reopen_a_later_hold():
    service,actor,repo,clock,owner,_=world();context=service.context(actor);first=create(service,actor)
    original=dict(inspection_ids=(ident(1),),expected_gate_version=context['gate_version'],expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='owner-create')
    version=repo.rows[GATE].revision
    assert service.create(actor,**original)['id']==first['id'] and repo.rows[GATE].revision==version
    ended=cancel(service,actor,first);second=create(service,actor,idempotency_key='second-create')
    before=deepcopy(repo.rows);replayed=cancel(service,actor,first)
    assert replayed['replayed'] and replayed['status']=='cancelled' and not replayed['current_hold']
    assert service.create(actor,**original)['status']=='cancelled' and repo.rows==before
    assert repo.rows[GATE].data['request_id']==second['id']
    with pytest.raises(StoreConflict):service.create(actor,**(original|{'inspection_ids':(ident(2),)}))


@pytest.mark.parametrize('operation',['create','cancel'])
def test_lost_write_acknowledgment_recovers_original_durable_commit(operation):
    service,actor,repo,clock,owner,_=world()
    if operation=='create':repo.lose_reply=True;result=create(service,actor)
    else:
        first=create(service,actor);repo.lose_reply=True;result=cancel(service,actor,first)
    assert result['status']==('held' if operation=='create' else 'cancelled')
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['session','membership','mfa','scope','runtime_enabled','missing_inspection','open_inspection','stale_gate','stale_control','ack'])
def test_denials_create_no_request_or_hold(fault):
    service,actor,repo,clock,owner,_=world();changes={}
    if fault=='session':repo.rows[actor.session.key]=replace(actor.session,data={**actor.session.data,'active':False})
    elif fault=='membership':repo.rows[actor.member.key]=replace(actor.member,data={**actor.member.data,'roles':['operator']})
    elif fault=='mfa':clock.value+=600001
    elif fault=='scope':changes['inspection_ids']=(ident(1),ident(1))
    elif fault=='runtime_enabled':
        r=repo.rows[RUNTIME];repo.rows[RUNTIME]=replace(r,data={**r.data,'inspection_enabled':True})
    elif fault=='missing_inspection':changes['inspection_ids']=(ident(99),)
    elif fault=='open_inspection':
        key=Key('state','inspection#'+ident(1));r=repo.rows[key];repo.rows[key]=replace(r,data={**r.data,'state':'OBSERVING'})
    elif fault=='stale_gate':changes['expected_gate_version']=999
    elif fault=='stale_control':changes['expected_control_version']=999
    else:changes['interruption_acknowledged']=False
    with pytest.raises((Denied,AdmissionHeld,StoreConflict,ValueError)):create(service,actor,**changes)
    assert repo.rows[GATE].data['phase']=='OPEN' and not any(k.resource.startswith('metadata-request#') for k in repo.rows)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['owner','runtime','gate','inspection'])
def test_atomic_admission_rejects_sources_changed_at_commit(fault):
    service,actor,repo,clock,owner,_=world()
    def change():
        key={'owner':actor.member.key,'runtime':RUNTIME,'gate':GATE,'inspection':Key('state','inspection#'+ident(1))}[fault]
        r=repo.rows[key];repo.rows[key]=replace(r,revision=r.revision+1)
    repo.before_commit=change
    with pytest.raises(StoreConflict):create(service,actor)
    assert repo.rows[GATE].data['phase']=='OPEN' and not any(k.resource.startswith('metadata-request#') for k in repo.rows)
    assert owner.wait_for_drain(0)


def test_hold_preserves_active_expired_work_and_cancel_waits_for_actual_release():
    service,actor,repo,clock,owner,_=world();work=service.admission.prepare(work_id=ident(80),kind='http',lease_ms=100)
    service.admission.admit(work);prepared=service.admission.prepare(work_id=ident(81),kind='worker',lease_ms=100)
    first=create(service,actor);assert first['drain_status']=='waiting' and not first['can_cancel']
    clock.value+=101
    with pytest.raises(AdmissionHeld):cancel(service,actor,first)
    assert ident(80) in repo.rows[REGISTRY].data['active']
    service.admission.release(work);current=service.get(actor,first['id']);cancel(service,actor,current)
    with pytest.raises(AdmissionHeld):service.admission.admit(prepared)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['scope','status','original_hash','creation_operation'])
def test_corrupt_request_provenance_holds_read_and_cancellation(fault):
    service,actor,repo,clock,owner,_=world();first=create(service,actor);key=request_key(first['id']);r=repo.rows[key]
    if fault=='scope':value={**r.data,'scope_sha256':'f'*64}
    elif fault=='status':value={**r.data,'status':'cleanup_committed'}
    elif fault=='original_hash':value={**r.data,'original_request_sha256':'f'*64}
    else:
        repo.rows.pop(Key('state',r.data['creation_operation_resource']));value=r.data
    repo.rows[key]=replace(r,data=value)
    with pytest.raises(AdmissionHeld):service.get(actor,first['id'])
    with pytest.raises(AdmissionHeld):cancel(service,actor,first)
    assert repo.rows[GATE].data['phase']=='HELD' and owner.wait_for_drain(0)


def test_reauthentication_preserves_creator_history_and_requires_current_authority():
    service,actor,repo,clock,owner,proof=world();first=create(service,actor)
    clock.value+=1000;new=service.access.resolve(service.access.login(replace(proof,auth_time_ms=clock.value)).cookie)
    view=service.get(new,first['id']);assert not view['original_owner_session'] and view['id']==first['id']
    ended=cancel(service,new,view);assert ended['status']=='cancelled'
    assert repo.rows[request_key(first['id'])].data['owner_session_id']==actor.session.data['id']


def test_read_allowance_has_no_store_write_and_write_allowance_survives_reinstantiation():
    service,actor,repo,clock,owner,_=world();limits=OwnerMetadataLimits(10,1,1,20000)
    service=OwnerMetadataRequests(service.access,service.admission,owner,limits=limits,tick_ns=service.tick_ns)
    before=deepcopy(repo.rows);service.context(actor);assert repo.rows==before
    with pytest.raises(OwnerMetadataLimited):service.context(actor)
    # A write has its own allowance; the exhausted read budget cannot hide its commit.
    runtime=repo.rows[RUNTIME]
    first=service.create(actor,inspection_ids=(ident(1),),expected_gate_version=repo.rows[GATE].revision,
        expected_control_version=int(runtime.data['control_version']),interruption_acknowledged=True,idempotency_key='quota-create')
    other=OwnerMetadataRequests(service.access,service.admission,owner,limits=limits,tick_ns=service.tick_ns)
    with pytest.raises(OwnerMetadataLimited):cancel(other,actor,first)
    assert repo.rows[GATE].data['phase']=='HELD'


def test_interruption_retains_actual_local_ownership_and_rejects_next_call(monkeypatch):
    service,actor,repo,clock,owner,_=world()
    monkeypatch.setattr(repo,'snapshot',lambda *a,**k:(_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):service.context(actor)
    assert service.release_pending and not owner.wait_for_drain(0)
    with pytest.raises(AdmissionHeld):service.context(actor)


def test_concurrent_equivalent_intent_commits_one_hold_and_charges_once():
    service,actor,repo,clock,owner,_=world()
    other=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns);results=[]
    repo.before_commit=lambda:results.append(create(other,actor))
    result=create(service,actor)
    assert result['id']==results[0]['id'] and result['replayed']
    assert len([k for k in repo.rows if k.resource.startswith('metadata-request#')])==1
    assert repo.rows[Key('state','metadata-owner-quota#'+actor.scope)].data['count']==1


def test_known_precommit_store_failure_creates_no_hold(monkeypatch):
    service,actor,repo,clock,owner,_=world();before=deepcopy(repo.rows)
    def unavailable(*a,**k):raise StoreUnavailable('synthetic before commit')
    monkeypatch.setattr(repo,'transact',unavailable)
    with pytest.raises(StoreUnavailable):create(service,actor)
    assert repo.rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['target','auth_config','limits','runtime_artifact','admission_limits','clock'])
def test_changed_dependency_configuration_is_denied_before_a_new_operation(fault):
    service,actor,repo,clock,owner,_=world()
    if fault=='target':repo.client=object()
    elif fault=='auth_config':service.access.config=replace(service.access.config,session_ttl_seconds=3599)
    elif fault=='limits':service.limits=replace(service.limits,reads_per_minute=99)
    elif fault=='runtime_artifact':service.runtime.artifact_sha256='d'*64
    elif fault=='admission_limits':service.admission.limits=AdmissionLimits(7,1000)
    else:service.access.clock_ms=lambda:clock.value
    with pytest.raises(AdmissionHeld):service.context(actor)
    assert owner.wait_for_drain(0)


def test_one_incarnation_never_runs_concurrent_owner_calls(monkeypatch):
    service,actor,repo,clock,owner,_=world();entered=Event();release=Event();result=[];original=service._heads
    def held():
        entered.set();assert release.wait(5);return original()
    monkeypatch.setattr(service,'_heads',held)
    thread=Thread(target=lambda:result.append(service.context(actor)));thread.start();assert entered.wait(5)
    try:
        with pytest.raises(OwnerMetadataBusy):service.context(actor)
        assert not owner.wait_for_drain(0)
    finally:release.set();thread.join(5)
    assert not thread.is_alive() and result and owner.wait_for_drain(0)


def test_cancel_racing_new_active_registry_entry_does_not_reopen():
    service,actor,repo,clock,owner,_=world();first=create(service,actor)
    def changed():
        row=repo.rows[REGISTRY];repo.rows[REGISTRY]=replace(row,revision=row.revision+1)
    repo.before_commit=changed
    with pytest.raises(StoreConflict):cancel(service,actor,first)
    assert repo.rows[GATE].data['phase']=='HELD' and repo.rows[request_key(first['id'])].data['status']=='held'


@pytest.mark.parametrize('fault',['deadline','rollback'])
def test_original_operation_clock_stops_final_preparation_before_hold(monkeypatch,fault):
    service,actor,repo,clock,owner,_=world();ticks=SimpleNamespace(value=100)
    service=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=lambda:ticks.value)
    original=service.access._prepare_linked
    def changed(operation,writes,checks=()):
        result=original(operation,writes,checks)
        if operation=='owner-metadata-create':ticks.value=0 if fault=='rollback' else 20_000_000_100
        return result
    monkeypatch.setattr(service.access,'_prepare_linked',changed)
    with pytest.raises(AdmissionHeld):create(service,actor)
    assert repo.rows[GATE].data['phase']=='OPEN' and not any(k.resource.startswith('metadata-request#') for k in repo.rows)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['gate_epoch','data_epoch','control_version'])
def test_counter_headroom_is_required_before_committing_a_hold(field):
    service,actor,repo,clock,owner,_=world();key={'gate_epoch':GATE,'data_epoch':DATA,'control_version':RUNTIME}[field]
    name={'gate_epoch':'epoch','data_epoch':'epoch','control_version':'control_version'}[field]
    row=repo.rows[key];repo.rows[key]=replace(row,data={**row.data,name:9007199254740991})
    if field=='gate_epoch':
        row=repo.rows[REGISTRY];repo.rows[REGISTRY]=replace(row,data={**row.data,'gate_epoch':9007199254740991})
    with pytest.raises((AdmissionHeld,ValueError)):create(service,actor)
    assert repo.rows[GATE].data['phase']=='OPEN' and owner.wait_for_drain(0)


@pytest.mark.parametrize('operation',['create','cancel'])
def test_duplicate_committing_between_lookup_and_source_review_is_reconciled(monkeypatch,operation):
    service,actor,repo,clock,owner,_=world()
    other=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns)
    context=service.context(actor);first=create(service,actor) if operation=='cancel' else None
    original=service._heads;winner=[]
    def heads():
        if not winner:
            winner.append(create(other,actor) if operation=='create' else cancel(other,actor,first))
        return original()
    monkeypatch.setattr(service,'_heads',heads)
    if operation=='create':
        result=service.create(actor,inspection_ids=(ident(1),),expected_gate_version=context['gate_version'],
            expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='owner-create')
    else:result=cancel(service,actor,first)
    assert result['replayed'] and result['id']==winner[0]['id']
    assert result['status']==('held' if operation=='create' else 'cancelled')
    assert len([k for k in repo.rows if k.resource.startswith('metadata-request#')])==1
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_inspections','writes_per_minute','reads_per_minute','operation_timeout_ms'])
@pytest.mark.parametrize('value',[0,-1,True,1.0])
def test_explicit_limits_reject_ambiguous_numbers(field,value):
    with pytest.raises(ValueError):replace(OwnerMetadataLimits(10,20,100,20000),**{field:value})
