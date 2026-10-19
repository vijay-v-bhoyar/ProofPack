"""Complete held purpose use/history on coherent synthetic writer models."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from itertools import count
from types import SimpleNamespace
from uuid import UUID
import pytest
from test_held_corpus import world,INV,BOUNDS,REQUEST,no_sdk
from test_capture_lineage import family as capture_family,uid,DEPLOYMENT
from test_corpus_accounting import LIMITS
from test_runtime_context import limits as runtime_limits
from test_ownership_classification import bounds
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,Row,Write
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.evidence.capture_lineage import OBSERVATION
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits
from proofpack.evidence.held_corpus import HeldCorpusReader,HeldCorpusHeld,inspection_scope,scope_sha256
from proofpack.runtime.control import RuntimeControl,DATA,ALLOCATION
from proofpack.runtime.ownership import ResourceOwner


def complete(monkeypatch,mode='created',second=False):
    import test_purpose_history as helper
    import proofpack.evidence.purposes as writer
    original_factory=helper.ModelRepository
    def repository():
        value=original_factory();value.deployment=DEPLOYMENT;return value
    with monkeypatch.context() as m:
        m.setattr(helper,'ModelRepository',repository)
        m.setattr(writer,'uuid4',lambda:UUID(uid(12)))
        m.setattr(helper,'count',lambda start:count(0))
        purpose,outputs,service,actor,purpose_repo=helper.family()
    original=deepcopy(purpose)
    _,_,_,repo,data,*_=world(monkeypatch,held=False);data.clear()
    data[DATA]=deepcopy(purpose_repo.rows[DATA]);data[ALLOCATION]=Row(ALLOCATION,1,{'slots':{}})
    # Startup checks the created-purpose data head; withdrawal occurs after capture.
    clock=count(6)
    access=SimpleNamespace(repository=repo,now=lambda:next(clock),
        _prepare_linked=lambda op,w,c:prepare_linked(repo.deployment,op,w,c))
    runtime=RuntimeControl(access,instance_id=uid(4),artifact_sha256='e'*64,controls_sha256='b'*64,environment='test')
    runtime.start()
    second_purpose=None
    if second:
        from proofpack.evidence.purposes import PurposeRequest,purpose_key
        later=count(10);service.access.now=lambda:next(later)
        request=PurposeRequest(notice_version='synthetic-v1',notice_sha256=original.data['notice_sha256'],
            source_permission_reference='second-source',operational_use_acknowledged=True,expires_at_ms=1000)
        with monkeypatch.context() as m:
            m.setattr(writer,'uuid4',lambda:UUID(uid(1012)))
            created=service.create(actor,request=request,idempotency_key='second-purpose')
        second_purpose=purpose_repo.rows[purpose_key(created['id'])]
        data[DATA]=deepcopy(purpose_repo.rows[DATA])
        outputs=tuple(r for k,r in purpose_repo.rows.items() if k.table=='events' or k.resource.startswith('idempotency#'))
    if mode!='created':
        later=count(200);service.access.now=lambda:next(later)
        service.withdraw(actor,ident=purpose.data['id'],expected_version=1,idempotency_key='withdraw')
        if mode=='noop':service.withdraw(actor,ident=purpose.data['id'],expected_version=2,idempotency_key='noop')
        purpose=purpose_repo.rows[purpose.key];data[DATA]=deepcopy(purpose_repo.rows[DATA])
        outputs=tuple(r for k,r in purpose_repo.rows.items() if k.table=='events' or k.resource.startswith('idempotency#'))
    def attach(root,records,original_purpose):
        permit=next(r for r in records if r.key.resource.startswith('capture-permit#'))
        observation=next(r for r in records if r.key.resource.startswith('observation#'))
        event=next(r for r in records if r.data.get('kind')=='observation_admitted')
        raw={k:v for k,v in event.data.items() if k!='resource_bindings'}
        writes=(Write(root.key,1,{**root.data,'state':'OBSERVING'}),Write(permit.key,1,permit.data),
            Write(observation.key,None,{k:v for k,v in observation.data.items() if k in OBSERVATION}|{'status':'admitted'}),Write(event.key,None,raw))
        linked,_=prepare_linked(repo.deployment,'observation_admitted',writes,(original_purpose,))
        records=[Row(event.key,1,next(w.data for w in linked if w.key==event.key)) if r.key==event.key else r for r in records]
        data[root.key]=root;data.update((r.key,r) for r in records)
    attach(*capture_family(),original)
    if second:
        import test_capture_lineage as capture_helper
        actual_uid=capture_helper.uid
        with monkeypatch.context() as m:
            m.setattr(capture_helper,'uid',lambda n:actual_uid(n+1000))
            other=capture_family()
        attach(*other,second_purpose);data[second_purpose.key]=second_purpose
    data[purpose.key]=purpose
    data.update((r.key,r) for r in outputs)
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(8,1000),clock_ms=lambda:500)
    admission.initialize('a'*64);scope=inspection_scope(repo.deployment,(uid(1),),max_inspections=30)
    admission.hold(request_id=REQUEST,scope_sha256=scope_sha256(scope));owner=ResourceOwner()
    reader=HeldCorpusReader(admission,owner,inventory_limits=INV,limits=BOUNDS,tick=lambda:1)
    return reader,owner,repo,data,purpose,outputs


def limits():
    from proofpack.evidence.purpose_corpus import PurposeCorpusLimits
    from proofpack.evidence.purpose_history import PurposeHistoryLimits
    return PurposeCorpusLimits(20,PurposeHistoryLimits(100,1_000_000,1000,10000,1_000_000),400000,4_000_000)


def read(reader,**changes):
    return reader.read_purpose_accounting(**(dict(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,
        accounting_limits=LIMITS,runtime_context_limits=runtime_limits(),purpose_corpus_limits=limits())|changes))


def classify(reader,**changes):
    return reader.read_purpose_classification(**(dict(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,
        accounting_limits=LIMITS,runtime_context_limits=runtime_limits(),purpose_corpus_limits=limits(),classification_limits=bounds())|changes))


@pytest.mark.parametrize('mode',['created','withdrawn','noop'])
def test_referenced_history_is_retained_with_explicit_reason_and_v2_unchanged(monkeypatch,mode):
    reader,owner,repo,data,purpose,outputs=complete(monkeypatch,mode);before=deepcopy(data)
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('context read wrote'))
    old=reader.read_runtime_accounting(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,
        accounting_limits=LIMITS,runtime_context_limits=runtime_limits())
    current=read(reader);p=current.corpus.purposes
    assert old.accounting.policy=='conservative-family-accounting-v2' and old.corpus.purposes is None
    assert dict(old.accounting.counts)['UNRESOLVED']==1+len(outputs) and dict(current.accounting.counts)['UNRESOLVED']==0
    assert current.accounting.policy=='conservative-family-accounting-v3' and p.family_count==1 and len(p.records)==1+len(outputs)
    assert p.read_only is True and p.can_confirm_cleanup is False and p.rights_independently_verified is False
    assert read(reader)==current and owner.wait_for_drain(0) and data==before
    assert purpose.data['id'] not in repr(p)
    with pytest.raises(FrozenInstanceError):p.work=0
    c=classify(reader).classification
    assert c.policy=='whole-scope-family-ownership-v3' and c.accounting==current.accounting
    assert any(e.retention_reasons==('retained_original_operational_purpose_and_history_for_interpretation',) for e in c.entries)


@pytest.mark.parametrize('fault',['missing_event','missing_replay','purpose_extra','event_extra','wrong_check'])
def test_selected_missing_corrupt_or_unreconciled_history_holds(monkeypatch,fault):
    reader,owner,_,data,purpose,outputs=complete(monkeypatch)
    event=next(r for r in outputs if r.key.table=='events');replay=next(r for r in outputs if r.key.table=='state')
    if fault=='missing_event':del data[event.key]
    elif fault=='missing_replay':del data[replay.key]
    elif fault=='purpose_extra':purpose.data['copied_payload']='PRIVATE'
    elif fault=='event_extra':event.data['details']['copied_payload']='PRIVATE'
    elif fault=='wrong_check':
        admitted=next(r for r in data.values() if r.data.get('kind')=='observation_admitted')
        admitted.data['resource_bindings']['checks'][0]['sha256']='0'*64
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_original_deadline_and_post_derivation_source_phantom(monkeypatch):
    import proofpack.evidence.held_corpus as module
    reader,owner,_,data,_,_=complete(monkeypatch)
    with pytest.raises(HeldCorpusHeld):read(reader,deadline_ns=1)
    actual=module.purpose_derive
    def phantom(*a,**k):
        assert not owner.wait_for_drain(0);value=actual(*a,**k)
        key=Key('state','future#late');data[key]=Row(key,1,{});return value
    monkeypatch.setattr(module,'purpose_derive',phantom)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_families','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[True,0,-1,1.5,'3',2**63])
def test_explicit_finite_corpus_limits(field,value):
    with pytest.raises(ValueError):replace(limits(),**{field:value})


def test_exact_combined_runtime_purpose_and_classification_work(monkeypatch):
    reader,owner,*_=complete(monkeypatch);result=classify(reader);c=result.classification
    assert c.work>result.corpus.runtime_context.work+result.corpus.purposes.work+c.accounting.work
    assert classify(reader,classification_limits=replace(bounds(),max_work=c.work)).classification==c
    with pytest.raises(HeldCorpusHeld):classify(reader,classification_limits=replace(bounds(),max_work=c.work-1))
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_work','max_summary_bytes'])
def test_exact_corpus_bound_and_one_below(monkeypatch,field):
    reader,owner,*_=complete(monkeypatch);p=read(reader).corpus.purposes
    actual=p.work if field=='max_work' else p.summary_bytes
    assert read(reader,purpose_corpus_limits=replace(limits(),**{field:actual})).corpus.purposes==p
    with pytest.raises(HeldCorpusHeld):read(reader,purpose_corpus_limits=replace(limits(),**{field:actual-1}))
    assert owner.wait_for_drain(0)


def test_family_count_exact_and_one_below_preserve_original_request_scope(monkeypatch):
    reader,owner,*_=complete(monkeypatch,second=True)
    result=read(reader,purpose_corpus_limits=replace(limits(),max_families=2))
    assert result.corpus.purposes.family_count==2 and result.corpus.scope.inspection_ids==(uid(1),)
    with pytest.raises(HeldCorpusHeld):read(reader,purpose_corpus_limits=replace(limits(),max_families=1))
    assert owner.wait_for_drain(0)


def test_unreferenced_purpose_stays_unknown_and_prevents_complete_classification(monkeypatch):
    import test_purpose_history as helper
    import proofpack.evidence.purposes as writer
    reader,owner,repo,data,_,_=complete(monkeypatch)
    factory=helper.ModelRepository
    original_access=helper.AccessService
    class SeparateIntent(original_access):
        def _idempotency(self,actor,operation,key,body):
            return original_access._idempotency(self,actor,operation,key+'-unreferenced',body)
    def repository():
        value=factory();value.deployment=repo.deployment;return value
    with monkeypatch.context() as m:
        m.setattr(writer,'uuid4',lambda:UUID(uid(99)));m.setattr(helper,'ModelRepository',repository)
        m.setattr(helper,'AccessService',SeparateIntent)
        purpose,outputs,*_=helper.family()
    data[purpose.key]=purpose;data.update((r.key,r) for r in outputs)
    result=read(reader)
    assert result.corpus.purposes.family_count==1 and dict(result.accounting.counts)['UNRESOLVED']==3
    assert all(r.key!=purpose.key for r in result.corpus.purposes.records)
    with pytest.raises(HeldCorpusHeld):classify(reader)
    assert owner.wait_for_drain(0)


def test_complete_inventory_detects_ambiguous_selected_noop_peers(monkeypatch):
    reader,owner,_,data,_,outputs=complete(monkeypatch,'noop')
    for r in outputs:
        if r.data['resource_bindings']['operation']=='purpose-withdraw' and not r.data['resource_bindings']['writes']:
            key=Key(r.key.table,'access#'+uid(998) if r.key.table=='events' else 'idempotency#'+'9'*64)
            data[key]=Row(key,1,deepcopy(r.data))
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['digest','inventory','scope','proof','cleanup','rights','work','duplicate','family'])
def test_private_return_requires_exact_non_authorizing_bound_shape(monkeypatch,fault):
    import proofpack.evidence.held_corpus as module
    reader,owner,*_=complete(monkeypatch);actual=module.purpose_derive
    def changed(*a,**k):
        value=actual(*a,**k)
        updates={'digest':{'summary_sha256':'0'*64},'inventory':{'inventory_sha256':'0'*64},
            'scope':{'scope_sha256':'0'*64},'proof':{'proof_sha256':'0'*64},'cleanup':{'can_confirm_cleanup':True},
            'rights':{'rights_independently_verified':True},'work':{'work':True},
            'duplicate':{'records':value.records+value.records[:1]},'family':{'families':(replace(value.families[0],purpose=False),)}}
        return replace(value,**updates[fault])
    monkeypatch.setattr(module,'purpose_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('mode',['accounting','classification'])
def test_purpose_core_cannot_omit_the_required_original_runtime_context(monkeypatch,mode):
    from proofpack.evidence.corpus_accounting import account,AccountingHeld
    from proofpack.evidence.ownership_classification import classify as core,ClassificationHeld
    reader,_,*_=complete(monkeypatch);result=read(reader);c=result.corpus
    kwargs=dict(requested_inspections=c.scope.inspection_ids,scope_sha256=scope_sha256(c.scope),deadline_ns=1000,
        tick=lambda:1,checkpoint=lambda:None,purpose_corpus=c.purposes,reference_corpus=c.references)
    with pytest.raises(AccountingHeld if mode=='accounting' else ClassificationHeld):
        if mode=='accounting':account(c.selection,c.inventory,c.proof,limits=LIMITS,**kwargs)
        else:core(c.selection,c.inventory,c.proof,limits=bounds(),accounting_limits=LIMITS,**kwargs)
