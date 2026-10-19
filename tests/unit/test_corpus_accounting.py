"""Server-owned modeled store/accounting; no physical, provider or owner proof."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import pytest
from botocore.client import BaseClient

from test_held_corpus import world, REQUEST
from test_capture_lineage import family, uid, key
from proofpack.evidence.repository import Row, Key, ErasureMarker
from proofpack.evidence import held_corpus
from proofpack.evidence.held_corpus import HeldCorpusHeld, HeldAccountedCorpus
from proofpack.evidence.corpus_accounting import AccountingLimits

LIMITS = AccountingLimits(1000,30,10000,200000,2_000_000)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*a,**k): raise AssertionError('accounting model invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def run(reader,limits=LIMITS):
    return reader.read_accounting(request_id=REQUEST,inspection_ids=(uid(1),),
        deadline_ns=1000,accounting_limits=limits)


def entries(result):
    return {r.reference.key:r for r in result.accounting.entries}


def changed_inspections(selection, **kwargs):
    datasets=selection.datasets;permissions=datasets.permissions;labels=permissions.labels
    return replace(selection,datasets=replace(datasets,permissions=replace(permissions,
        labels=replace(labels,inspections=replace(labels.inspections,**kwargs)))))


def test_accounts_every_original_identity_and_keeps_unknowns_and_context_separate(monkeypatch):
    reader,admission,owner,repo,data,_,_=world(monkeypatch)
    private=Key('state','future#opaque');data[private]=Row(private,1,{'secret':'NEVER_DISCLOSE'})
    before=deepcopy(data);result=run(reader);indexed=entries(result)
    assert type(result) is HeldAccountedCorpus and set(indexed)==set(data)
    assert result.accounting.inventory_sha256==result.corpus.inventory.summary_sha256
    assert indexed[Key('state','inspection#'+uid(1))].disposition=='AFFECTED'
    assert indexed[private].disposition=='UNRESOLVED'
    assert all(indexed[r.key].disposition=='CONTEXT' for r in (
        result.corpus.proof.gate,result.corpus.proof.registry,result.corpus.proof.runtime))
    assert sum(dict(result.accounting.counts).values())==len(data)
    assert result.accounting.requested_inspections==result.corpus.scope.inspection_ids==(uid(1),)
    assert len(result.accounting.summary_sha256)==64 and owner.wait_for_drain(0)
    assert data==before and run(reader).accounting==result.accounting
    assert not hasattr(result.accounting,'can_delete') and not hasattr(result.accounting,'ready')
    assert all(s not in repr(result) for s in ['NEVER_DISCLOSE',uid(1),'deployments/','source_context'])
    with pytest.raises(FrozenInstanceError):result.accounting.work=0


def test_supported_other_inspection_is_unrelated_without_expanding_scope(monkeypatch):
    reader,_,_,_,data,_,_=world(monkeypatch)
    root,_=family();second=replace(root,key=key('inspection',9000),data={**root.data,'id':uid(9000),
        'latest_input_sequence':0,'verified_sequence':0,'latest_observation_id':None})
    data[second.key]=second
    result=run(reader);entry=entries(result)[second.key]
    assert entry.disposition=='UNRELATED' and entry.inspection_ids==(uid(9000),)
    assert result.accounting.requested_inspections==(uid(1),)


@pytest.mark.parametrize('field',['max_records','max_scope','max_relationships','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[0,-1,True,1.0])
def test_independent_limits_are_positive_exact_integers(field,value):
    with pytest.raises(ValueError):replace(LIMITS,**{field:value})


@pytest.mark.parametrize('field',['max_records','max_relationships','max_work','max_summary_bytes'])
def test_each_budget_accepts_exact_consumption_and_holds_one_below(monkeypatch,field):
    reader,_,owner,_,_,_,_=world(monkeypatch);result=run(reader)
    actual={'max_records':len(result.corpus.inventory.entries),'max_relationships':len(result.accounting.relationships),
        'max_work':result.accounting.work,'max_summary_bytes':max(result.corpus.inventory.summary_bytes,result.accounting.summary_bytes)}[field]
    assert actual>1 and run(reader,replace(LIMITS,**{field:actual})).accounting==result.accounting
    with pytest.raises(HeldCorpusHeld):run(reader,replace(LIMITS,**{field:actual-1}))
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['summary','missing','extra','boolean_revision','payload','order'])
def test_inventory_forgery_is_held_before_acceptance(monkeypatch,fault):
    reader,_,owner,_,_,_,_=world(monkeypatch);original=held_corpus.account
    def forged(selection,inventory,proof,**options):
        if fault=='summary':inventory=replace(inventory,summary_sha256='a'*64)
        elif fault=='missing':inventory=replace(inventory,entries=inventory.entries[1:])
        elif fault=='extra':inventory=replace(inventory,entries=inventory.entries+(inventory.entries[-1],))
        elif fault=='order':inventory=replace(inventory,entries=tuple(reversed(inventory.entries)))
        else:
            entry=inventory.entries[0]
            changed=replace(entry,**({'revision':True} if fault=='boolean_revision' else {'payload_sha256':'a'*64}))
            inventory=replace(inventory,entries=(changed,*inventory.entries[1:]))
        return original(selection,inventory,proof,**options)
    monkeypatch.setattr(held_corpus,'account',forged)
    with pytest.raises(HeldCorpusHeld):run(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['missing_original','missing_residual','duplicate_residual','original_revision','scope_flag','scope_proof'])
def test_selector_coverage_and_scope_conflicts_hold_the_entire_operation(monkeypatch,fault):
    reader,_,owner,_,data,_,_=world(monkeypatch);original=held_corpus.account
    unknown=Key('state','unrecognized#kept');data[unknown]=Row(unknown,1,{'private':True})
    def forged(selection,inventory,proof,**options):
        source=selection.datasets.permissions.labels.inspections
        if fault=='missing_original':selection=changed_inspections(selection,residual=tuple(r for r in source.residual if r.key!=unknown))
        elif fault=='missing_residual':selection=replace(selection,residual=tuple(r for r in selection.residual if r.key!=unknown))
        elif fault=='duplicate_residual':selection=replace(selection,residual=(*selection.residual,selection.residual[-1]))
        elif fault=='scope_proof':proof=replace(proof,scope_sha256='a'*64)
        else:
            family=source.families[0]
            family=replace(family,requested=False) if fault=='scope_flag' else replace(family,capture=replace(
                family.capture,inspection=replace(family.capture.inspection,revision=True)))
            selection=changed_inspections(selection,families=(family,*source.families[1:]))
        return original(selection,inventory,proof,**options)
    monkeypatch.setattr(held_corpus,'account',forged)
    with pytest.raises(HeldCorpusHeld):run(reader)
    assert owner.wait_for_drain(0)


def test_actual_store_mutation_after_accounting_is_caught_before_return(monkeypatch):
    reader,_,owner,_,data,_,_=world(monkeypatch);original=held_corpus.account;called=[]
    def changing(*a,**k):
        result=original(*a,**k);called.append(True)
        unknown=Key('state','after-accounting#phantom');data[unknown]=Row(unknown,1,{'private':True})
        return result
    monkeypatch.setattr(held_corpus,'account',changing)
    with pytest.raises(HeldCorpusHeld):run(reader)
    assert called==[True] and owner.wait_for_drain(0)


def test_accounting_retains_outer_resource_until_final_checks(monkeypatch):
    reader,_,owner,_,_,_,_=world(monkeypatch);original=held_corpus.account;closed=[]
    def stopping(*a,**k):
        assert not owner.wait_for_drain(0);owner.stop_accepting();owner.after_drain(lambda:closed.append(True))
        result=original(*a,**k);assert not closed;return result
    monkeypatch.setattr(held_corpus,'account',stopping)
    assert run(reader).accounting.entries and closed==[True] and owner.wait_for_drain(0)


def test_prior_marker_and_shared_group_policy_remain_unresolved(monkeypatch):
    reader,_,_,repo,data,_,_=world(monkeypatch)
    k=Key('state','erased#prior');data[k]=ErasureMarker(k,2,'c'*64,repo._erasure_identity(k))
    result=run(reader);indexed=entries(result)
    assert indexed[k].disposition=='UNRESOLVED' and indexed[k].reason=='MARKER_JOURNAL_REQUIRED'
    groups=result.corpus.selection.datasets.groups;assert groups
    assert all(indexed[g.history.group.key].disposition=='UNRESOLVED' for g in groups)


def test_known_reference_permission_scope_remains_unresolved(monkeypatch):
    import test_held_corpus as fixture
    from test_improvement_corpus import corpus
    monkeypatch.setattr(fixture,'corpus',lambda:corpus(reference=True))
    reader,_,_,_,_,_,_=world(monkeypatch);result=run(reader);indexed=entries(result)
    permissions=result.corpus.selection.datasets.permissions.families;assert permissions
    assert all(indexed[f.history.preview.key].disposition=='UNRESOLVED' for f in permissions)
    assert indexed[Key('state','asset#'+uid(900))].disposition=='UNRESOLVED'


def test_real_mixed_permission_content_is_shared_without_scope_expansion(monkeypatch):
    import test_held_corpus as fixture
    import test_capture_lineage as capture_fixture
    import test_label_lineage as label_fixture
    from test_improvement_corpus import corpus
    with monkeypatch.context() as patch:
        offset=lambda n:uid(n+1000)
        patch.setattr(capture_fixture,'uid',offset);patch.setattr(label_fixture,'uid',offset)
        root,capture,recipe,purposes,history=label_fixture.labels(1,ident=uid(20),epoch_start=4)
    other=(root,*capture,recipe,*purposes,*history)
    raw=corpus(other_rows=other)
    monkeypatch.setattr(fixture,'corpus',lambda:raw)
    reader,_,_,_,_,_,_=world(monkeypatch);result=run(reader);indexed=entries(result)
    permissions=result.corpus.selection.datasets.permissions.families;assert permissions
    for f in permissions:
        entry=indexed[f.history.preview.key]
        assert entry.disposition=='SHARED' and entry.inspection_ids==(uid(1),uid(1001))
    assert indexed[root.key].disposition=='UNRELATED'
    assert result.accounting.requested_inspections==(uid(1),)


def test_source_change_changes_accounting_binding_without_mutating_prior_result(monkeypatch):
    reader,_,_,_,data,_,_=world(monkeypatch)
    k=Key('state','future#changing');data[k]=Row(k,1,{'private':'FIRST'})
    first=run(reader);saved=deepcopy(first.accounting)
    data[k]=Row(k,2,{'private':'SECOND'});second=run(reader)
    assert first.accounting==saved and first.accounting.summary_sha256!=second.accounting.summary_sha256
    assert first.corpus.binding_sha256!=second.corpus.binding_sha256
    assert entries(first)[k].reference.revision==1 and entries(second)[k].reference.revision==2


def test_pure_callbacks_revalidate_exact_proof_within_32_calls(monkeypatch):
    reader,admission,owner,_,_,_,_=world(monkeypatch)
    derive=held_corpus.derive;assert_drained=admission.assert_drained;checks=[]
    def checked(proof):checks.append(proof);return assert_drained(proof)
    monkeypatch.setattr(admission,'assert_drained',checked)
    def selecting(*a,**k):
        start=len(checks)
        for _ in range(31):k['checkpoint']()
        assert len(checks)==start
        k['checkpoint']();assert len(checks)==start+2
        assert checks[-1]==checks[-2]
        return derive(*a,**k)
    monkeypatch.setattr(held_corpus,'derive',selecting)
    assert run(reader).accounting.entries and owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['expiry','configuration','original_control'])
def test_pure_accounting_checks_clock_config_and_original_proof_without_reset(monkeypatch,fault):
    from proofpack.auth.service import RUNTIME
    reader,_,owner,_,data,_,_=world(monkeypatch);clock={'value':1};called=[]
    reader=held_corpus.HeldCorpusReader(reader.admission,owner,inventory_limits=reader.inventory_limits,
        limits=reader.limits,tick=lambda:clock['value'])
    def accounting(*a,**k):
        called.append(True)
        if fault=='expiry':clock['value']=1000
        elif fault=='configuration':reader.inventory_limits=replace(reader.inventory_limits,max_payload_bytes=1)
        else:
            row=data[RUNTIME];data[RUNTIME]=replace(row,revision=row.revision+1)
        for _ in range(32 if fault=='original_control' else 1):k['checkpoint']()
        pytest.fail('pure-phase bound did not reject expired/changed original authority')
    monkeypatch.setattr(held_corpus,'account',accounting)
    with pytest.raises(HeldCorpusHeld):run(reader)
    assert called==[True] and owner.wait_for_drain(0)
