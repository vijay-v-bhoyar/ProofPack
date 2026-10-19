"""Actual transition persistence with TEST-INJECTED trusted assurance records.

No golden cases run here. The reader fixture is not a product qualification
writer and its claims cannot qualify physical, beta or human use.
"""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4
import json
import pytest
from test_policy_candidates import policies,draft,world,repository_factory
from proofpack.auth.policy import Denied
from proofpack.auth.service import RUNTIME
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.planner.activation import (PolicyActivations,ActivationConfig,ActivationRequest,QualifiedPolicySnapshot,
    ActivationLimited,qualification_key,qualification_head,activation_key)
from proofpack.runtime.control import DATA,integer
from proofpack.runtime.control import RuntimeControl
from proofpack.stations.service import POLICY


@pytest.fixture
def activation(world,policies):
    candidates,reviewer,_=policies;repo=world[1];clock=world[2]
    class InjectedReader:
        def __init__(self):
            self.policies=candidates;self.access=candidates.access;self.runtime=candidates.runtime;self.repository=repo;self.calls=0;self.guard=None
        def read_current(self,ident):
            self.calls+=1;report=repo.snapshot((qualification_key(ident),))[qualification_key(ident)]
            if report is None:raise StoreUnavailable('test qualification missing')
            head=qualification_head(report.data['policy_id'],integer(report.data['policy_revision']));source=Key('state',report.data['test_source_key'])
            rows=repo.snapshot((head,source))
            def gate():
                if self.guard:self.guard()
                current=repo.snapshot((source,))[source]
                if current!=rows[source] or current.data['status']!='current' or clock()>=integer(current.data['expires_at_ms']):raise StoreUnavailable('test source no longer current')
            return QualifiedPolicySnapshot(report,tuple(rows.values()),integer(report.data['expires_at_ms']),gate)
    reader=InjectedReader();service=PolicyActivations(candidates,ActivationConfig(20,120,60000,80,'c'*64),reader)
    def issue(candidate,*,patch=None,expiry=None,rollback_target=None):
        ident=str(uuid4());runtime,data=(repo.snapshot((RUNTIME,DATA))[k] for k in (RUNTIME,DATA))
        _,record,_=candidates._load(candidate['id'],candidate['revision']);source=Key('state','test-qualification-source#'+ident)
        expires=clock()+300000 if expiry is None else expiry
        value={'schema_version':1,'runner':'policy_qualification_v1','status':'qualified','scope':'synthetic_demo_only','id':ident,
            'policy_id':candidate['id'],'policy_revision':candidate['revision'],'policy_revision_sha256':candidate['revision_sha256'],
            'behavior_sha256':record.data['behavior_sha256'],'installed_sha256':candidates.installed_sha256,'registry_sha256':'c'*64,
            'environment':service.runtime.environment,'artifact_sha256':service.runtime.artifact_sha256,'controls_sha256':service.runtime.controls_sha256,
            'runtime_epoch':integer(runtime.data['runtime_epoch']),'control_version':integer(runtime.data['control_version']),'data_epoch':integer(data.data['epoch']),
            'issued_at_ms':clock(),'expires_at_ms':expires,'required_case_count':3,'completed_case_count':3,'failed_case_count':0,'unknown_case_count':0,
            'preparation_report_sha256':'d'*64,'golden_report_sha256':'e'*64,'test_source_key':source.resource,**(patch or {})}
        if rollback_target is not None:value['rollback_target']=rollback_target
        value['sha256']=digest(value);key=qualification_head(candidate['id'],candidate['revision']);prior=repo.snapshot((key,))[key]
        repo.transact((Write(qualification_key(ident),None,value),Write(key,None if prior is None else prior.revision,{'qualification_id':ident,'report_sha256':value['sha256'],'status':'qualified'}),
            Write(source,None,{'status':'current','expires_at_ms':expires})))
        active=repo.snapshot((POLICY,))[POLICY]
        body={'operation':'bootstrap' if active is None else 'promote','policy_id':candidate['id'],'policy_revision':candidate['revision'],'policy_state_version':candidate['state_version'],
            'policy_revision_sha256':candidate['revision_sha256'],'qualification_id':ident,'qualification_report_sha256':value['sha256'],
            'expected_active_version':0 if active is None else active.revision,'expected_control_version':integer(runtime.data['control_version']),'invalidation_acknowledged':True}
        return ActivationRequest.model_validate_json(json.dumps(body))
    return service,reader,issue,candidates,reviewer


def new(activation,priority=None):
    _,_,_,candidates,reviewer=activation
    return candidates.write(reviewer,request=draft() if priority is None else draft(priority=priority),idempotency_key=str(uuid4()))


def test_atomic_bootstrap_is_historical_exact_retry_and_does_not_enable(world,activation):
    service,reader,issue,*_=activation;candidate=new(activation);request=issue(candidate);before=world[1].snapshot((RUNTIME,DATA))
    result=service.transition(world[5],request=request,idempotency_key='bootstrap')
    roots=world[1].snapshot((POLICY,RUNTIME,DATA,activation_key(result['transition_id'])))
    assert result['active_version']==1 and result['control_version']==integer(before[RUNTIME].data['control_version'])+1
    assert roots[POLICY].data['definition']==candidate['spec'] and roots[POLICY].data['expires_at_ms']>world[2]()+service.config.review_window_ms
    assert roots[RUNTIME].data['inspection_enabled'] is False and roots[RUNTIME].data['enable_receipt_id'] is None and roots[DATA]==before[DATA]
    assert roots[activation_key(result['transition_id'])].revision==1
    service.reader=None
    assert service.transition(world[5],request=request,idempotency_key='bootstrap')==result
    assert world[1].snapshot(tuple(roots))==roots
    assert service.receipt(world[5],result['transition_id'])['current_qualification_verified'] is False
    with pytest.raises(StoreConflict):service.transition(world[5],request=request.model_copy(update={'qualification_id':str(uuid4())}),idempotency_key='bootstrap')


def test_promotion_and_requalified_exact_predecessor_rollback_disable_inspections(world,activation):
    service,reader,issue,*_=activation;first=new(activation);original=service.transition(world[5],request=issue(first),idempotency_key='first')
    second=new(activation,('PLACE_FLAT','RECAPTURE','SEPARATE_REGION'));request=issue(second)
    runtime=world[1].snapshot((RUNTIME,))[RUNTIME]
    world[1].transact((Write(RUNTIME,runtime.revision,{**runtime.data,'inspection_enabled':True,'enable_receipt_id':str(uuid4()),'enable_expires_at_ms':world[2]()+10000}),))
    promoted=service.transition(world[5],request=request,idempotency_key='promote')
    active=world[1].snapshot((POLICY,RUNTIME));assert active[POLICY].data['definition']['priority']==list(second['spec']['priority'])
    assert active[RUNTIME].data['inspection_enabled'] is False and active[RUNTIME].data['enable_expires_at_ms'] is None
    target={'active_version':promoted['active_version'],'activation_id':promoted['transition_id'],'predecessor_activation_id':original['transition_id']}
    old=issue(first,rollback_target=target).model_copy(update={'operation':'rollback','predecessor_activation_id':str(uuid4())})
    with pytest.raises(StoreConflict):service.transition(world[5],request=old,idempotency_key='wrong-predecessor')
    rollback=old.model_copy(update={'predecessor_activation_id':original['transition_id']})
    rolled=service.transition(world[5],request=rollback,idempotency_key='rollback')
    assert rolled['control_version']==promoted['control_version']+1 and rolled['active_version']==3
    assert world[1].snapshot((POLICY,))[POLICY].data['policy_id']==first['id']
    assert len(world[1].query(prefix='policy-activation#',limit=20)[0])==3


@pytest.mark.parametrize('patch',[{'status':'failed'},{'scope':'physical'},{'completed_case_count':2},{'failed_case_count':1},{'unknown_case_count':1},
    {'registry_sha256':'f'*64},{'data_epoch':999},{'control_version':999},{'artifact_sha256':'f'*64},{'installed_sha256':'f'*64},{'environment':'beta'}])
def test_unqualified_mismatched_or_partial_private_reports_cannot_activate(world,activation,patch):
    service,_,issue,*_=activation;request=issue(new(activation),patch=patch);before=world[1].snapshot((POLICY,RUNTIME))
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='reject')
    assert world[1].snapshot((POLICY,RUNTIME))==before


def test_missing_reader_reviewer_expiry_and_superseded_qualification_deny(world,activation):
    service,reader,issue,_,reviewer=activation;candidate=new(activation);request=issue(candidate);before=world[1].snapshot((POLICY,RUNTIME))
    with pytest.raises(Denied):service.transition(reviewer,request=request,idempotency_key='reviewer')
    service.reader=None
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='no-reader')
    service.reader=reader;issue(candidate)
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='superseded')
    expired=issue(candidate,expiry=world[2]())
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=expired,idempotency_key='expired')
    assert world[1].snapshot((POLICY,RUNTIME))==before


def test_final_source_guard_and_monotonic_clock_fence_transaction(world,activation):
    service,reader,issue,*_=activation;request=issue(new(activation));before=world[1].snapshot((POLICY,RUNTIME));calls=[0]
    def expire():
        calls[0]+=1
        if calls[0]==2:world[2].value+=service.config.review_window_ms
    reader.guard=expire
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='final-expiry')
    assert calls[0]==2 and world[1].snapshot((POLICY,RUNTIME))==before
    reader.guard=None;service.tick=iter((10,True)).__next__
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='bad-clock')
    assert world[1].snapshot((POLICY,RUNTIME))==before


def test_committed_response_loss_recovers_one_transition_without_reader_or_second_control_change(world,activation,monkeypatch):
    service,_,issue,*_=activation;request=issue(new(activation));commit=service.access._commit;lost=[False]
    def wrapped(writes,checks=()):
        commit(writes,checks)
        if not lost[0] and any(w.key==POLICY for w in writes):lost[0]=True;raise StoreUnavailable('synthetic response loss after commit')
    monkeypatch.setattr(service.access,'_commit',wrapped)
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='lost')
    state=world[1].snapshot((POLICY,RUNTIME));service.reader=None
    recovered=service.transition(world[5],request=request,idempotency_key='lost')
    assert recovered['historical_receipt'] and world[1].snapshot((POLICY,RUNTIME))==state
    assert len(world[1].query(prefix='policy-activation#',limit=20)[0])==1


def test_competing_bootstraps_commit_one_atomic_head_event_and_control_change(world,activation,monkeypatch):
    service,_,issue,*_=activation;request=issue(new(activation));commit=service.access._commit;barrier=Barrier(2)
    def competing(writes,checks=()):
        if any(w.key==POLICY for w in writes):barrier.wait(timeout=10)
        return commit(writes,checks)
    monkeypatch.setattr(service.access,'_commit',competing)
    def run(key):
        try:return service.transition(world[5],request=request,idempotency_key=key)
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,('left','right')))
    assert sum(r is not None for r in results)==1
    assert world[1].snapshot((POLICY,))[POLICY].revision==1 and len(world[1].query(prefix='policy-activation#',limit=20)[0])==1


@pytest.mark.parametrize('boundary',['dependency_count','schema_boolean','configuration_change'])
def test_activation_final_subject_and_total_qualification_dependency_capacity_are_strict(world,activation,boundary):
    service,reader,issue,*_=activation
    request=issue(new(activation),patch={'schema_version':True} if boundary=='schema_boolean' else None)
    if boundary=='dependency_count':service.config=replace(service.config,max_qualification_rows=2)  # report + current head + source = three
    if boundary=='configuration_change':
        def change():service.config=replace(service.config,qualification_registry_sha256='f'*64)
        reader.guard=change
    before=world[1].snapshot((POLICY,RUNTIME))
    with pytest.raises((StoreUnavailable,StoreConflict)):service.transition(world[5],request=request,idempotency_key='strict-boundary')
    assert world[1].snapshot((POLICY,RUNTIME))==before


@pytest.mark.parametrize('change',['source','candidate','runtime','data'])
def test_source_candidate_runtime_and_data_races_cannot_publish_activation(world,activation,change):
    service,reader,issue,candidates,reviewer=activation;candidate=new(activation);request=issue(candidate);fired=[False]
    def mutate():
        if fired[0]:return
        fired[0]=True
        if change=='source':
            record=world[1].snapshot((qualification_key(request.qualification_id),))[qualification_key(request.qualification_id)]
            key=Key('state',record.data['test_source_key']);row=world[1].snapshot((key,))[key]
            world[1].transact((Write(key,row.revision,{**row.data,'status':'withdrawn'}),))
        elif change=='candidate':candidates.write(reviewer,request=draft('Changed revision'),ident=candidate['id'],expected_version=1,idempotency_key='racing-revision')
        elif change=='runtime':RuntimeControl(service.access,instance_id=str(uuid4()),artifact_sha256=service.runtime.artifact_sha256,
            controls_sha256=service.runtime.controls_sha256,environment=service.runtime.environment).start()
        else:
            row=world[1].snapshot((DATA,))[DATA];world[1].transact((Write(DATA,row.revision,{**row.data,'epoch':integer(row.data['epoch'])+1}),))
    reader.guard=mutate
    with pytest.raises((StoreConflict,StoreUnavailable)):service.transition(world[5],request=request,idempotency_key='race')
    assert fired[0] and world[1].snapshot((POLICY,))[POLICY] is None
    assert world[1].query(prefix='policy-activation#',limit=20)[0]==[]


def test_mfa_expiring_in_last_guard_denies_without_activation(world,activation):
    service,reader,issue,*_=activation;request=issue(new(activation),expiry=world[2]()+3600000);calls=[0]
    def expire():
        calls[0]+=1
        if calls[0]==2:world[2].value+=service.access.config.mfa_grant_max_age_seconds*1000+1
    reader.guard=expire
    with pytest.raises(Denied,match='recent target MFA'):service.transition(world[5],request=request,idempotency_key='mfa-last-boundary')
    assert calls[0]==2 and world[1].snapshot((POLICY,))[POLICY] is None


def test_committed_transition_and_metadata_reads_obey_separate_nonrefunded_quotas(world,activation):
    original,reader,issue,candidates,_=activation;service=PolicyActivations(candidates,replace(original.config,writes_per_minute=1,reads_per_minute=1),reader)
    first=service.transition(world[5],request=issue(new(activation)),idempotency_key='quota-first')
    before=world[1].snapshot((POLICY,RUNTIME));second=issue(new(activation,('RECAPTURE','PLACE_FLAT','SEPARATE_REGION')))
    with pytest.raises(ActivationLimited):service.transition(world[5],request=second,idempotency_key='quota-second')
    assert world[1].snapshot((POLICY,RUNTIME))==before
    assert service.receipt(world[5],first['transition_id'])['historical_receipt']
    with pytest.raises(ActivationLimited):service.receipt(world[5],first['transition_id'])


def test_concurrent_exact_duplicate_recovers_one_transition_for_both_callers(world,activation,monkeypatch):
    service,_,issue,*_=activation;request=issue(new(activation));commit=service.access._commit;barrier=Barrier(2)
    def competing(writes,checks=()):
        if any(w.key==POLICY for w in writes):barrier.wait(timeout=10)
        return commit(writes,checks)
    monkeypatch.setattr(service.access,'_commit',competing)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:service.transition(world[5],request=request,idempotency_key='same'),range(2)))
    assert results[0]==results[1] and len(world[1].query(prefix='policy-activation#',limit=20)[0])==1
    assert world[1].snapshot((POLICY,))[POLICY].revision==1


def test_expiry_during_last_owner_read_is_checked_after_that_read_before_commit(world,activation,monkeypatch):
    service,_,issue,*_=activation;request=issue(new(activation));owner=service._owner;calls=[0]
    def last_read(actor):
        value=owner(actor);calls[0]+=1
        if calls[0]==5:world[2].value+=service.config.review_window_ms
        return value
    monkeypatch.setattr(service,'_owner',last_read)
    with pytest.raises(StoreUnavailable):service.transition(world[5],request=request,idempotency_key='last-owner-time')
    assert world[1].snapshot((POLICY,))[POLICY] is None


@pytest.mark.parametrize('mode',['maximum','excess','last_dependency_changed'])
def test_full_qualification_dependency_capacity_is_fenced_without_truncation(world,activation,mode):
    service,reader,issue,*_=activation;request=issue(new(activation));original=reader.read_current
    # Qualification report, current qualification head and source are three;
    # 77 additional distinct records reach the configured total of 80.
    count=78 if mode=='excess' else 77
    keys=tuple(Key('state','test-qualification-dependency#'+str(uuid4())) for _ in range(count))
    world[1].transact(tuple(Write(key,None,{'version':1}) for key in keys))
    def complete(ident):
        base=original(ident);extra=tuple(world[1].snapshot(keys).values())
        def guard():
            base.final_guard()
            if mode=='last_dependency_changed':
                row=world[1].snapshot((keys[-1],))[keys[-1]];world[1].transact((Write(keys[-1],row.revision,{'version':2}),))
        return replace(base,dependencies=(*base.dependencies,*extra),final_guard=guard)
    reader.read_current=complete
    if mode=='maximum':assert service.transition(world[5],request=request,idempotency_key='full-capacity')['active_version']==1
    else:
        with pytest.raises((StoreUnavailable,StoreConflict)):service.transition(world[5],request=request,idempotency_key='full-capacity')
        assert world[1].snapshot((POLICY,))[POLICY] is None
