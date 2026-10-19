"""Actual owner/held-reader protocols on modeled storage; no provider proof."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import pytest
from botocore.client import BaseClient
from test_inventory_readset import setup
from test_privacy_admission import ModelRepository,ident
from test_held_corpus import INV,BOUNDS
from test_replay_corpus import corpus,DEPLOYMENT
from test_corpus_accounting import LIMITS
from proofpack.auth.service import AccessService,AuthConfig,BootstrapApproval,IdentityProof
from proofpack.auth.policy import Denied
from proofpack.runtime.control import RuntimeControl
from proofpack.runtime.ownership import ResourceOwner
from proofpack.evidence.repository import Key,Row,StoreConflict
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits,AdmissionHeld,GATE
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits,OwnerMetadataLimited,request_key
from proofpack.evidence.held_corpus import HeldCorpusReader,HeldCorpusHeld
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*a,**k):raise AssertionError('owner review model invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def world(monkeypatch,*,max_lease_ms=1000):
    repo,data,calls,_=setup(monkeypatch,0);repo.deployment=DEPLOYMENT
    data.update((r.key,deepcopy(r)) for r in corpus())
    model=ModelRepository();model.rows=data
    monkeypatch.setattr(repo,'snapshot',model.snapshot);monkeypatch.setattr(repo,'transact',model.transact)
    clock=SimpleNamespace(value=100,tick=1)
    def now():return clock.value
    def tick():return clock.tick
    issuer='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic'
    access=AccessService(repo,AuthConfig(repo.deployment,issuer,b'synthetic-not-a-real-key'*3,
        initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64),clock_ms=now)
    proof=IdentityProof(issuer,'owner','owner@example.invalid',True,True,now(),now()+3_600_000,'Synthetic owner')
    access.bootstrap(BootstrapApproval(issuer,'owner','a'*64),proof);credentials=access.login(proof);actor=access.resolve(credentials.cookie)
    runtime=RuntimeControl(access,instance_id=ident(90),artifact_sha256='a'*64,controls_sha256='b'*64,environment='test');runtime.start()
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(8,max_lease_ms),clock_ms=now);admission.initialize('c'*64)
    owner=ResourceOwner();requests=OwnerMetadataRequests(access,admission,owner,limits=OwnerMetadataLimits(10,20,100,20000),tick_ns=tick)
    context=requests.context(actor)
    original=requests.create(actor,inspection_ids=(ident(1),),expected_gate_version=context['gate_version'],
        expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='owner-create')
    reader=HeldCorpusReader(admission,owner,inventory_limits=INV,limits=BOUNDS,tick=tick)
    service=OwnerMetadataReview(requests,reader,accounting_limits=LIMITS,max_response_bytes=8192)
    return service,requests,reader,actor,repo,data,clock,original,owner


def read(w,**changes):
    service,_,_,actor,_,_,_,original,_=w
    return service.read(actor,ident=original['id'],**(dict(expected_request_version=original['state_version'],
        expected_gate_version=original['gate_version'],expected_control_version=original['control_version'])|changes))


def test_real_owner_and_private_reader_return_complete_minimized_non_authorizing_counts(monkeypatch):
    w=world(monkeypatch);before=deepcopy(w[5]);result=read(w)
    assert set(result)=={'id','scope_sha256','request_version','gate_version','control_version','accounting_policy',
        'counts','total_records','historical','read_only','can_confirm_cleanup','erasure_complete','request_fulfilled'}
    assert result['id']==w[7]['id'] and result['scope_sha256']==w[7]['scope_sha256']
    assert set(result['counts'])=={'AFFECTED','SHARED','CONTEXT','UNRELATED','UNRESOLVED'}
    assert sum(result['counts'].values())==result['total_records']==len(before)
    assert result['counts']['AFFECTED']>0 and result['counts']['UNRESOLVED']>0
    assert result['historical'] is True and result['read_only'] is True
    assert all(result[k] is False for k in ['can_confirm_cleanup','erasure_complete','request_fulfilled'])
    assert before==w[5] and w[-1].wait_for_drain(0)
    assert all(k not in repr(result) for k in ['idempotency#','member#','session#','PRIVATE-PAYLOAD','owner@example.invalid'])


@pytest.mark.parametrize('field',['expected_request_version','expected_gate_version','expected_control_version'])
def test_stale_versions_never_start_private_reader(monkeypatch,field):
    w=world(monkeypatch)
    monkeypatch.setattr(w[2],'read_accounting',lambda **k:pytest.fail('stale request reached private reader'))
    with pytest.raises(StoreConflict):read(w,**{field:999})
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('field',['expected_request_version','expected_gate_version','expected_control_version'])
@pytest.mark.parametrize('value',[True,0,-1,1.0,2**53])
def test_exact_safe_version_inputs(monkeypatch,field,value):
    w=world(monkeypatch)
    with pytest.raises(ValueError):read(w,**{field:value})


@pytest.mark.parametrize('change',['actor','grant','mfa','cancelled','active','scope','config','clock','reader_pending'])
def test_changed_authority_source_or_lifetime_holds_without_output(monkeypatch,change):
    w=world(monkeypatch);s,requests,reader,actor,repo,data,clock,original,owner=w
    if change=='actor':w=(s,requests,reader,None,repo,data,clock,original,owner)
    elif change=='grant':
        r=data[actor.member.key];data[r.key]=Row(r.key,r.revision+1,{**r.data,'enabled':False})
    elif change=='mfa':clock.value+=1_000_000
    elif change=='cancelled':
        requests.cancel(actor,ident=original['id'],confirmed_scope_sha256=original['scope_sha256'],expected_request_version=original['state_version'],
            expected_gate_version=original['gate_version'],expected_control_version=original['control_version'],no_erasure_acknowledged=True,idempotency_key='cancel')
    elif change=='active':
        # Exact public work is registered under HELD; it is never a drain exemption.
        intent=requests.admission._prepare_public_asset(work_id=ident(91),lease_ms=500)
        requests.admission._admit_public_asset(intent)
    elif change=='scope':data[request_key(original['id'])].data['scope']['inspection_ids']=[ident(2)]
    elif change=='config':s.max_response_bytes=8191
    elif change=='clock':clock.tick=-1
    elif change=='reader_pending':reader.release_pending=True
    with pytest.raises((Denied,AdmissionHeld,HeldCorpusHeld,StoreConflict,ValueError)):read(w)
    assert not data[GATE].data['phase']=='OPEN' or change=='cancelled'


def test_reader_uses_original_deadline_and_final_owner_is_rechecked(monkeypatch):
    w=world(monkeypatch);original=w[2].read_accounting;seen=[]
    def inspect(**kw):
        seen.append(kw);result=original(**kw)
        actor=w[3];row=w[5][actor.member.key]
        w[5][row.key]=Row(row.key,row.revision+1,{**row.data,'enabled':False})
        return result
    monkeypatch.setattr(w[2],'read_accounting',inspect)
    with pytest.raises((Denied,StoreConflict,AdmissionHeld)):read(w)
    assert seen[0]['deadline_ns']==1+20000*1_000_000
    assert seen[0]['inspection_ids']==(ident(1),) and seen[0]['request_id']==w[7]['id']
    assert w[-1].wait_for_drain(0)


def test_read_budget_and_response_bound_are_independent(monkeypatch):
    w=world(monkeypatch);w[1]._read_count=w[1].limits.reads_per_minute
    with pytest.raises(OwnerMetadataLimited):read(w)
    w=world(monkeypatch)
    s=OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=128)
    with pytest.raises(HeldCorpusHeld):read((s,*w[1:]))
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('value',[True,0,-1,1.5,65537])
def test_explicit_response_limits_validate_without_io(monkeypatch,value):
    w=world(monkeypatch)
    monkeypatch.setattr(w[4],'snapshot',lambda *a:pytest.fail('constructor performed I/O'))
    with pytest.raises(ValueError):OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=value)


def test_reader_configuration_and_uncertain_completion_are_retained(monkeypatch):
    w=world(monkeypatch)
    def uncertain(**kw):w[2].release_pending=True;raise HeldCorpusHeld('completion unknown')
    monkeypatch.setattr(w[2],'read_accounting',uncertain)
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[1].release_pending is True
    with pytest.raises(AdmissionHeld):w[1].context(w[3])


def test_foreign_reader_and_independent_clock_are_refused(monkeypatch):
    w=world(monkeypatch);other=world(monkeypatch)
    with pytest.raises(ValueError):OwnerMetadataReview(w[1],other[2],accounting_limits=LIMITS,max_response_bytes=8192)
    w[2].tick=lambda:1
    with pytest.raises(ValueError):OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=8192)


@pytest.mark.parametrize('change',['phantom','payload'])
def test_complete_source_is_reconciled_after_private_reader_return(monkeypatch,change):
    w=world(monkeypatch);original=w[2].read_accounting
    def race(**kw):
        result=original(**kw)
        if change=='phantom':
            key=Key('state','unknown#after-private-return');w[5][key]=Row(key,1,{'private':'DO_NOT_DISCLOSE'})
        else:
            key=Key('state','inspection#'+ident(1));old=w[5][key]
            w[5][key]=Row(key,old.revision+1,{**old.data,'private':'DO_NOT_DISCLOSE'})
        return result
    monkeypatch.setattr(w[2],'read_accounting',race)
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('budget',['snapshot_batches','payload_bytes'])
def test_exhausted_cumulative_budget_stops_before_additional_inventory_io(monkeypatch,budget):
    w=world(monkeypatch);original=w[2].read_accounting;passed=SimpleNamespace(done=False);extra=[]
    snapshot=w[4].inventory_snapshot
    def observe(keys):
        if passed.done:extra.append(len(keys))
        return snapshot(keys)
    monkeypatch.setattr(w[4],'inventory_snapshot',observe)
    def exhaust(**kw):
        result=original(**kw);passed.done=True
        limit=w[2].limits.max_total_snapshot_batches if budget=='snapshot_batches' else w[2].limits.max_total_payload_bytes
        return replace(result,corpus=replace(result.corpus,**{budget:limit}))
    monkeypatch.setattr(w[2],'read_accounting',exhaust)
    with pytest.raises(HeldCorpusHeld):read(w)
    assert extra==[], 'spent original capacity must be checked before any extra inventory request'
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['bool','negative','unsafe','sum','missing','duplicate','policy','proof','inventory'])
def test_private_result_cannot_supply_malformed_counts_or_foreign_bindings(monkeypatch,fault):
    w=world(monkeypatch);original=w[2].read_accounting
    def corrupt(**kw):
        result=original(**kw);a=result.accounting;counts=list(a.counts)
        if fault in {'bool','negative','unsafe','sum'}:
            counts[0]=(counts[0][0],{'bool':True,'negative':-1,'unsafe':2**53,'sum':counts[0][1]+1}[fault])
            a=replace(a,counts=tuple(counts))
        elif fault=='missing':a=replace(a,counts=a.counts[:-1])
        elif fault=='duplicate':a=replace(a,counts=(a.counts[0],)*5)
        elif fault=='policy':a=replace(a,policy='unsupported-policy')
        elif fault=='inventory':a=replace(a,inventory_sha256='0'*64)
        else:return replace(result,corpus=replace(result.corpus,proof=replace(result.corpus.proof,request_id=ident(999))))
        return replace(result,accounting=a)
    monkeypatch.setattr(w[2],'read_accounting',corrupt)
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['grant','deadline','target','reader_config'])
def test_final_inventory_pass_cannot_outlive_authority_clock_or_target(monkeypatch,fault):
    w=world(monkeypatch);original=w[2].read_accounting;phase=SimpleNamespace(final=False)
    snapshot=w[4].inventory_snapshot
    def after_inner(**kw):
        result=original(**kw);phase.final=True;return result
    def final_snapshot(keys):
        result=snapshot(keys)
        if phase.final:
            phase.final=False
            if fault=='grant':
                r=w[5][w[3].member.key];w[5][r.key]=Row(r.key,r.revision+1,{**r.data,'enabled':False})
            elif fault=='deadline':w[6].tick=w[1]._deadline
            elif fault=='target':w[4].client=object()
            else:w[2].limits=replace(w[2].limits,max_binding_bytes=w[2].limits.max_binding_bytes-1)
        return result
    monkeypatch.setattr(w[2],'read_accounting',after_inner);monkeypatch.setattr(w[4],'inventory_snapshot',final_snapshot)
    with pytest.raises((HeldCorpusHeld,AdmissionHeld,Denied,StoreConflict)):read(w)
    assert w[-1].wait_for_drain(0)


def test_unknown_executor_retains_request_resource_and_blocks_reuse(monkeypatch):
    w=world(monkeypatch)
    def interrupt(**kw):raise KeyboardInterrupt('synthetic unknown executor')
    monkeypatch.setattr(w[2],'read_accounting',interrupt)
    with pytest.raises(KeyboardInterrupt):read(w)
    assert w[1].release_pending and not w[-1].wait_for_drain(0)
    with pytest.raises(AdmissionHeld):read(w)
