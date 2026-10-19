"""Server protocols on deliberately complete modeled families; not real-user truth."""
from dataclasses import replace,FrozenInstanceError
from copy import deepcopy
import pytest
from test_held_corpus import world,REQUEST,no_sdk
from test_capture_lineage import family,uid
from test_corpus_accounting import LIMITS
from proofpack.evidence.repository import Key,Row,ErasureMarker
from proofpack.evidence.held_corpus import HeldCorpusHeld,inspection_scope,scope_sha256

def complete(monkeypatch):
    reader,admission,owner,repo,data,*_=world(monkeypatch)
    scope=inspection_scope(repo.deployment,(uid(1),),max_inspections=30)
    proof=admission.drained(request_id=REQUEST,scope_sha256=scope_sha256(scope))
    kept={ref.key:data[ref.key] for ref in (proof.gate,proof.registry,proof.runtime)}
    root,records=family()
    data.clear();data.update(kept);data[root.key]=root;data.update((row.key,row) for row in records)
    return reader,admission,owner,repo,data

def bounds():
    from proofpack.evidence.ownership_classification import ClassificationLimits
    return ClassificationLimits(1000,10000,400000,4_000_000)

def run(reader,limits=None,**changes):
    return reader.read_classification(**(dict(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,
        accounting_limits=LIMITS,classification_limits=bounds() if limits is None else limits)|changes))

def test_complete_supported_server_corpus_has_frozen_non_authorizing_classification(monkeypatch):
    reader,_,owner,repo,data=complete(monkeypatch);before=deepcopy(data)
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('classification wrote metadata'))
    result=run(reader);c=result.classification
    assert c.policy=='whole-scope-family-ownership-v1'
    assert c.inventory_sha256==result.corpus.inventory.summary_sha256 and c.scope_sha256==scope_sha256(result.corpus.scope)
    assert c.accounting_sha256==c.accounting.summary_sha256 and c.requested_inspections==(uid(1),)
    assert len(c.entries)==len(data) and sum(dict(c.counts).values())==len(data)
    assert dict(c.counts)['CONTEXT']==3 and dict(c.counts)['AFFECTED']>0 and dict(c.counts)['UNRESOLVED']==dict(c.counts)['SHARED']==0
    assert c.historical is c.read_only is True and c.can_confirm_cleanup is c.erasure_complete is c.request_fulfilled is False
    assert all(e.retention_reasons==('retained_original_maintenance_fence',) for e in c.entries if e.disposition=='CONTEXT')
    assert data==before and owner.wait_for_drain(0) and run(reader).classification==c
    assert all(token not in repr(result) for token in [uid(1),'inspection#','session#','deployments/'])
    with pytest.raises(FrozenInstanceError):c.work=0

def test_unknown_family_holds_instead_of_accepting_partial_classification(monkeypatch):
    r,_,owner,_,data=complete(monkeypatch);key=Key('state','future#private');data[key]=Row(key,1,{'private':'NEVER_DISCLOSE'})
    before=deepcopy(data)
    with pytest.raises(HeldCorpusHeld):run(r)
    assert data==before and owner.wait_for_drain(0)

@pytest.mark.parametrize('field',['max_records','max_edges','max_work','max_summary_bytes'])
def test_each_independent_bound_accepts_exact_and_holds_one_below(monkeypatch,field):
    r,_,owner,_,_=complete(monkeypatch);c=run(r).classification
    actual={'max_records':len(c.entries),'max_edges':len(c.relationships),'max_work':c.work,'max_summary_bytes':c.summary_bytes}[field]
    assert actual>1 and run(r,replace(bounds(),**{field:actual})).classification==c
    with pytest.raises(HeldCorpusHeld):run(r,replace(bounds(),**{field:actual-1}))
    assert owner.wait_for_drain(0)

@pytest.mark.parametrize('field',['max_records','max_edges','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[0,-1,True,1.5,'3',2**63])
def test_strict_explicit_bounds(field,value):
    with pytest.raises(ValueError):replace(bounds(),**{field:value})

@pytest.mark.parametrize('fault',['digest','inventory','scope','count','policy','reason','shared','missing','duplicate','edge'])
def test_recomputed_accounting_output_is_validated(monkeypatch,fault):
    import proofpack.evidence.ownership_classification as module
    r,_,owner,_,_=complete(monkeypatch);actual=module.account
    def changed(*args,**kwargs):
        a=actual(*args,**kwargs);entry=next(e for e in a.entries if e.disposition=='AFFECTED')
        if fault=='digest':return replace(a,summary_sha256='0'*64)
        if fault=='inventory':return replace(a,inventory_sha256='0'*64)
        if fault=='scope':return replace(a,requested_inspections=(uid(9),))
        if fault=='count':return replace(a,counts=tuple((n,True if n=='AFFECTED' else c) for n,c in a.counts))
        if fault=='missing':return replace(a,entries=a.entries[:-1])
        if fault=='duplicate':
            assert len(a.entries)>1 and a.entries[0].reference!=a.entries[1].reference
            return replace(a,entries=a.entries[:1]+a.entries[:1]+a.entries[2:])
        if fault=='edge':return replace(a,relationships=a.relationships[:-1])
        e=replace(entry,**({'policies':('FUTURE',)} if fault=='policy' else {'reason':'UNPROVED'} if fault=='reason' else {'disposition':'SHARED'}))
        return replace(a,entries=tuple(e if row is entry else row for row in a.entries))
    monkeypatch.setattr(module,'account',changed)
    with pytest.raises(HeldCorpusHeld):run(r)
    assert owner.wait_for_drain(0)

def test_original_resource_stays_held_and_post_classification_phantom_withholds_result(monkeypatch):
    from proofpack.evidence import held_corpus
    r,_,owner,_,data=complete(monkeypatch);actual=held_corpus.classify;seen=[]
    def phantom(*args,**kwargs):
        assert not owner.wait_for_drain(0);value=actual(*args,**kwargs);seen.append(True)
        key=Key('state','future#after-classification');data[key]=Row(key,1,{'private':'NEVER_DISCLOSE'});return value
    monkeypatch.setattr(held_corpus,'classify',phantom)
    with pytest.raises(HeldCorpusHeld):run(r)
    assert seen==[True] and owner.wait_for_drain(0)

def test_original_expired_deadline_does_not_renew(monkeypatch):
    r,_,owner,_,_=complete(monkeypatch)
    with pytest.raises(HeldCorpusHeld):run(r,deadline_ns=1)
    assert owner.wait_for_drain(0)

def test_other_supported_inspection_stays_unrelated_without_scope_expansion(monkeypatch):
    r,_,owner,_,data=complete(monkeypatch);root,_=family()
    other=replace(root,key=Key('state','inspection#'+uid(9000)),data={**root.data,'id':uid(9000),
        'latest_input_sequence':0,'verified_sequence':0,'latest_observation_id':None})
    data[other.key]=other;c=run(r).classification
    entry=next(e for e in c.entries if e.reference.key==other.key)
    assert entry.disposition=='UNRELATED' and entry.retention_reasons==() and c.requested_inspections==(uid(1),)
    assert owner.wait_for_drain(0)

def test_validated_label_context_has_explicit_retention_reason(monkeypatch):
    import test_label_lineage as fixture
    r,admission,owner,repo,data=complete(monkeypatch)
    scope=inspection_scope(repo.deployment,(uid(1),),max_inspections=30)
    proof=admission.drained(request_id=REQUEST,scope_sha256=scope_sha256(scope))
    kept={ref.key:data[ref.key] for ref in (proof.gate,proof.registry,proof.runtime)}
    root,capture,recipe,purposes,history=fixture.labels(1,epoch_start=4)
    data.clear();data.update(kept);data.update((row.key,row) for row in (root,*capture,recipe,*purposes,*history))
    c=run(r).classification;context=[e for e in c.entries if e.disposition=='CONTEXT']
    assert any(e.reference.key==recipe.key and e.retention_reasons==('retained_original_recipe_or_purpose_for_interpretation',) for e in context)
    assert all(e.retention_reasons==() for e in c.entries if e.disposition!='CONTEXT')
    assert owner.wait_for_drain(0)

def test_retained_marker_without_journal_cannot_be_classified(monkeypatch):
    r,_,owner,repo,data=complete(monkeypatch);key=Key('state','erased#prior')
    data[key]=ErasureMarker(key,2,'c'*64,repo._erasure_identity(key))
    with pytest.raises(HeldCorpusHeld):run(r)
    assert owner.wait_for_drain(0)

def test_accounting_cannot_receive_work_already_spent_on_inventory(monkeypatch):
    import proofpack.evidence.ownership_classification as module
    r,_,owner,_,_=complete(monkeypatch);budget=run(r).classification.work;actual=module.account;seen=[]
    def bounded(selection,inventory,*args,**kwargs):
        allowance=kwargs['limits'].max_work
        assert allowance<=budget-len(inventory.entries),'delegated accounting allowance renews already consumed inventory work'
        seen.append(allowance);return actual(selection,inventory,*args,**kwargs)
    monkeypatch.setattr(module,'account',bounded)
    assert run(r,replace(bounds(),max_work=budget)).classification.work==budget and seen and owner.wait_for_drain(0)

def test_reader_does_not_deliver_forged_cleanup_authority(monkeypatch):
    from proofpack.evidence import held_corpus
    r,_,owner,_,_=complete(monkeypatch);actual=held_corpus.classify
    monkeypatch.setattr(held_corpus,'classify',lambda *a,**kw:replace(actual(*a,**kw),can_confirm_cleanup=True))
    with pytest.raises(HeldCorpusHeld):run(r)
    assert owner.wait_for_drain(0)

@pytest.mark.parametrize('field,value',[('policy','future'),('inventory_sha256','0'*64),('scope_sha256','0'*64),
    ('accounting_sha256','0'*64),('requested_inspections',(uid(9),)),('historical',False),('read_only',False),
    ('erasure_complete',True),('request_fulfilled',True),('work',True),('summary_bytes',True),('entries',()),('relationships',()),('summary_sha256','invalid')])
def test_reader_validates_original_return_binding_and_non_authorizing_flags(monkeypatch,field,value):
    from proofpack.evidence import held_corpus
    r,_,owner,_,_=complete(monkeypatch);actual=held_corpus.classify
    monkeypatch.setattr(held_corpus,'classify',lambda *a,**kw:replace(actual(*a,**kw),**{field:value}))
    with pytest.raises(HeldCorpusHeld):run(r)
    assert owner.wait_for_drain(0)
