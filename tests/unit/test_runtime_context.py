"""Opt-in private held runtime context; actual writers on modeled storage only."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from types import SimpleNamespace
from itertools import count
import pytest
from test_held_corpus import world, INV, BOUNDS, REQUEST, no_sdk
from test_capture_lineage import family, uid
from test_corpus_accounting import LIMITS
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionLimits
from proofpack.evidence.held_corpus import HeldCorpusReader, HeldCorpusHeld, inspection_scope, scope_sha256
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.runtime.control import RuntimeControl, ALLOCATION, DATA
from proofpack.runtime.ownership import ResourceOwner


def complete(monkeypatch):
    _, _, _, repo, data, _, _ = world(monkeypatch, held=False)
    # New isolated model, not a removal of real stored obligations.
    data.clear()
    clock = count(1)
    access = SimpleNamespace(repository=repo, now=lambda: next(clock),
        _prepare_linked=lambda op, writes, checks: prepare_linked(repo.deployment, op, writes, checks))
    runtime = RuntimeControl(access, instance_id=uid(4), artifact_sha256='e'*64,
        controls_sha256='b'*64, environment='test')
    runtime.start()
    root, records = family()
    data[root.key] = root; data.update((r.key, r) for r in records)
    admission = PersistentAdmission(runtime, limits=AdmissionLimits(8, 1000), clock_ms=lambda:100)
    admission.initialize('a'*64)
    scope=inspection_scope(repo.deployment,(uid(1),),max_inspections=30)
    admission.hold(request_id=REQUEST,scope_sha256=scope_sha256(scope))
    owner=ResourceOwner()
    reader=HeldCorpusReader(admission,owner,inventory_limits=INV,limits=BOUNDS,tick=lambda:1)
    return reader, admission, owner, repo, data


def limits():
    from proofpack.evidence.runtime_context import RuntimeContextLimits
    return RuntimeContextLimits(1000,4_000_000,400_000,4_000_000)


def read(reader, **changes):
    return reader.read_runtime_accounting(**(dict(request_id=REQUEST,inspection_ids=(uid(1),),
        deadline_ns=1000,accounting_limits=LIMITS,runtime_context_limits=limits())|changes))


def classify(reader, **changes):
    from test_ownership_classification import bounds
    return reader.read_runtime_classification(**(dict(request_id=REQUEST,inspection_ids=(uid(1),),
        deadline_ns=1000,accounting_limits=LIMITS,runtime_context_limits=limits(),classification_limits=bounds())|changes))


def test_current_supported_startup_and_empty_heads_are_context_without_mutation(monkeypatch):
    reader,_,owner,repo,data=complete(monkeypatch); before=deepcopy(data)
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('private read wrote'))
    old=reader.read_accounting(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,accounting_limits=LIMITS)
    result=read(reader); ctx=result.corpus.runtime_context
    assert result.accounting.policy=='conservative-family-accounting-v2'
    assert old.accounting.policy=='conservative-family-accounting-v1' and old.corpus.runtime_context is None
    assert dict(old.accounting.counts)['UNRESOLVED']==4 and dict(result.accounting.counts)['UNRESOLVED']==0
    assert dict(result.accounting.counts)['CONTEXT']==7 and len(ctx.records)==4
    assert ctx.policy=='runtime-maintenance-context-v1' and ctx.inventory_sha256==result.corpus.inventory.summary_sha256
    assert ctx.scope_sha256==scope_sha256(result.corpus.scope) and ctx.read_only is True and ctx.can_confirm_cleanup is False
    assert data==before and owner.wait_for_drain(0) and read(reader)==result
    assert uid(1) not in repr(ctx) and uid(4) not in repr(ctx)
    with pytest.raises(FrozenInstanceError):ctx.work=0
    current=classify(reader).classification
    assert current.policy=='whole-scope-family-ownership-v2' and current.accounting==result.accounting
    assert dict(current.counts)['UNRESOLVED']==0
    assert {r for e in current.entries for r in e.retention_reasons} >= {
        'retained_original_runtime_provenance','retained_original_empty_allocation_fence','retained_original_data_epoch_fence'}


@pytest.mark.parametrize('fault',['occupied','allocation_extra','data_extra','future_data','boolean_epoch','runtime_extra','missing_marker','missing_event'])
def test_known_invalid_fences_and_missing_peers_hold_whole_read(monkeypatch,fault):
    from proofpack.auth.service import RUNTIME
    reader,_,owner,_,data=complete(monkeypatch)
    if fault=='occupied':data[ALLOCATION].data['slots']={uid(1):uid(2)}
    elif fault=='allocation_extra':data[ALLOCATION].data['copied_payload']='PRIVATE'
    elif fault=='data_extra':data[DATA].data['copied_payload']='PRIVATE'
    elif fault=='future_data':data[DATA].data['changed_at_ms']=101
    elif fault=='boolean_epoch':data[DATA].data['epoch']=True
    elif fault=='runtime_extra':data[RUNTIME].data['copied_payload']='PRIVATE'
    elif fault=='missing_marker':del data[next(k for k in data if k.resource.startswith('runtime-start#'))]
    elif fault=='missing_event':del data[next(k for k in data if k.resource.startswith('runtime#'))]
    before=deepcopy(data)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0) and data==before


def test_changed_original_creation_stays_unresolved_and_cannot_be_classified(monkeypatch):
    reader,_,owner,_,data=complete(monkeypatch)
    data[DATA]=Row(DATA,2,{'epoch':2,'changed_at_ms':99})
    result=read(reader)
    assert dict(result.accounting.counts)['UNRESOLVED']==2
    assert len(result.corpus.runtime_context.obligations)==2
    with pytest.raises(HeldCorpusHeld):classify(reader)
    assert owner.wait_for_drain(0)


def test_unknown_payload_keeps_obligation_even_with_valid_runtime_context(monkeypatch):
    reader,_,owner,_,data=complete(monkeypatch)
    key=Key('state','future#private');data[key]=Row(key,1,{'payload':'PRIVATE'})
    assert dict(read(reader).accounting.counts)['UNRESOLVED']==1
    with pytest.raises(HeldCorpusHeld):classify(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_work','max_summary_bytes'])
def test_context_exact_independent_bounds_and_one_below(monkeypatch,field):
    reader,_,owner,_,_=complete(monkeypatch);c=read(reader).corpus.runtime_context
    actual={'max_records':c.source_records,'max_payload_bytes':c.payload_bytes,'max_work':c.work,'max_summary_bytes':c.summary_bytes}[field]
    assert actual>1 and read(reader,runtime_context_limits=replace(limits(),**{field:actual})).corpus.runtime_context==c
    with pytest.raises(HeldCorpusHeld):read(reader,runtime_context_limits=replace(limits(),**{field:actual-1}))
    assert owner.wait_for_drain(0)


def test_final_source_phantom_and_original_resource_lifetime(monkeypatch):
    import proofpack.evidence.held_corpus as module
    reader,_,owner,_,data=complete(monkeypatch); actual=module.runtime_derive
    def changed(*args,**kwargs):
        assert not owner.wait_for_drain(0)
        value=actual(*args,**kwargs);key=Key('state','future#late');data[key]=Row(key,1,{})
        return value
    monkeypatch.setattr(module,'runtime_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_original_deadline_cannot_be_renewed(monkeypatch):
    reader,_,owner,_,_=complete(monkeypatch)
    with pytest.raises(HeldCorpusHeld):read(reader,deadline_ns=1)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['digest','inventory','proof','scope','cleanup','read_only','work','duplicate','policy'])
def test_returned_context_must_be_original_bounded_and_non_authorizing(monkeypatch,fault):
    import proofpack.evidence.held_corpus as module
    reader,_,owner,_,_=complete(monkeypatch); actual=module.runtime_derive
    def changed(*args,**kwargs):
        value=actual(*args,**kwargs)
        changes={'digest':{'summary_sha256':'0'*64},'inventory':{'inventory_sha256':'0'*64},
            'proof':{'proof_sha256':'0'*64},'scope':{'scope_sha256':'0'*64},'cleanup':{'can_confirm_cleanup':True},
            'read_only':{'read_only':False},'work':{'work':True},'duplicate':{'records':value.records+value.records[:1]},
            'policy':{'records':(replace(value.records[0],policy='UNSUPPORTED'),)+value.records[1:]}}
        return replace(value,**changes[fault])
    monkeypatch.setattr(module,'runtime_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_classification_combines_context_accounting_and_classification_work(monkeypatch):
    from test_ownership_classification import bounds
    reader,_,owner,_,_=complete(monkeypatch)
    current=classify(reader); c=current.classification
    assert c.work > c.accounting.work+current.corpus.runtime_context.work
    exact=replace(bounds(),max_work=c.work)
    assert classify(reader,classification_limits=exact).classification==c
    with pytest.raises(HeldCorpusHeld):classify(reader,classification_limits=replace(exact,max_work=c.work-1))
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[True,0,-1,1.5,'3',2**63])
def test_context_limits_are_explicit_exact_finite_integers(field,value):
    with pytest.raises(ValueError):replace(limits(),**{field:value})


@pytest.mark.parametrize('fault',['marker_extra','event_extra','marker_epoch','event_future'])
def test_missing_old_creation_does_not_bypass_known_schema_checks(monkeypatch,fault):
    reader,_,owner,_,data=complete(monkeypatch)
    data[DATA]=Row(DATA,2,{'epoch':2,'changed_at_ms':99})
    marker=next(r for k,r in data.items() if k.resource.startswith('runtime-start#'))
    event=next(r for k,r in data.items() if k.resource.startswith('runtime#'))
    if fault=='marker_extra':marker.data['copied_payload']='PRIVATE'
    elif fault=='event_extra':event.data['copied_payload']='PRIVATE'
    elif fault=='marker_epoch':marker.data['runtime_epoch']=True
    elif fault=='event_future':event.data['at_ms']=101
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)
