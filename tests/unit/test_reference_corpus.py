"""Full modeled held-reader reference selection/accounting, not provider truth."""
from copy import deepcopy
from dataclasses import replace,FrozenInstanceError
import pytest
from test_held_corpus import world,REQUEST,no_sdk
from test_corpus_accounting import LIMITS as ACCOUNTING
from test_reference_lineage import family
from test_capture_lineage import uid
from proofpack.evidence import held_corpus,reference_corpus
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.reference_corpus import ReferenceCorpusLimits,ReferenceCorpusHeld
from proofpack.evidence.reference_lineage import ReferenceLimits
from proofpack.evidence.repository import Key,Row,ErasureMarker


def setup(monkeypatch,state='linked'):
    reader,admission,owner,repo,data,calls,clock=world(monkeypatch)
    root,rows=family(state,target={'history_version':2,'storage_binding_sha256':'9'*64})
    data.update((r.key,deepcopy(r)) for r in (root,*rows))
    return reader,owner,repo,data,root,rows


def read(reader):
    return reader.read_accounting(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,accounting_limits=ACCOUNTING)


@pytest.mark.parametrize('state',['reserved','writing','failed_reserved','failed_writing','linked'])
def test_server_joins_complete_upload_history_and_keeps_all_records_unresolved(monkeypatch,state):
    reader,owner,repo,data,root,rows=setup(monkeypatch,state);before=deepcopy(data)
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('private selection wrote metadata'))
    result=read(reader);refs=result.corpus.references
    assert refs.family_count==1 and refs.families[0].state==root.data['status']
    assert refs.work>=result.corpus.selection.work and refs.summary_bytes>0
    assert len(refs.summary_sha256)==64 and data==before and owner.wait_for_drain(0)
    index={x.reference.key:x for x in result.accounting.entries}
    for r in (root,*rows):
        assert index[r.key].disposition=='UNRESOLVED'
        assert index[r.key].inspection_ids==()
        assert 'REFERENCE_UPLOAD_HISTORY' in index[r.key].policies
        assert index[r.key].reason=='INSPECTION_ORIGIN_NOT_RECORDED'
    assert sum(dict(result.accounting.counts).values())==len(data)
    assert root.key in {r.key for r in result.corpus.selection.residual}
    assert not hasattr(refs,'can_delete') and uid(801) not in repr(result) and 'PRIVATE_VERSION' not in repr(result)
    with pytest.raises(FrozenInstanceError):refs.work=0


@pytest.mark.parametrize('index',range(4))
def test_missing_committed_peer_holds_actual_reader_delivery(monkeypatch,index):
    reader,owner,repo,data,root,rows=setup(monkeypatch);data.pop(rows[index].key)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_references','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[0,-1,True,1.0])
def test_limits_are_explicit_exact_positive_integers(field,value):
    limits=ReferenceCorpusLimits(100,ReferenceLimits(32,1_000_000,64,10000),200000,1_000_000)
    with pytest.raises(ValueError):replace(limits,**{field:value})


@pytest.mark.parametrize('field',['max_work','max_summary_bytes'])
def test_cumulative_work_and_summary_cannot_be_silently_exceeded(monkeypatch,field):
    reader,owner,*_=setup(monkeypatch)
    limits=replace(reader.limits,references=replace(reader.limits.references,**{field:1}))
    reader.limits=limits;reader._initial=(reader.admission,reader.resource_owner,reader.inventory_limits,limits,reader.tick,reader.admission.repository)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work'])
def test_each_family_bound_is_enforced_in_held_path(monkeypatch,field):
    reader,owner,*_=setup(monkeypatch)
    refs=replace(reader.limits.references,family=replace(reader.limits.references.family,**{field:1}))
    limits=replace(reader.limits,references=refs);reader.limits=limits
    reader._initial=(reader.admission,reader.resource_owner,reader.inventory_limits,limits,reader.tick,reader.admission.repository)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('mutation',['payload','phantom','remove'])
def test_final_real_inventory_reconciliation_detects_reference_phase_changes(monkeypatch,mutation):
    reader,owner,repo,data,root,rows=setup(monkeypatch);original=held_corpus.reference_derive
    def changed(*a,**k):
        result=original(*a,**k)
        if mutation=='payload':data[root.key]=replace(root,revision=root.revision+1)
        elif mutation=='phantom':
            key=Key('state','unknown#late');data[key]=Row(key,1,{'private':'unknown'})
        else:data.pop(root.key)
        return result
    monkeypatch.setattr(held_corpus,'reference_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_original_upstream_snapshot_cannot_be_replaced_before_reference_derivation(monkeypatch):
    reader,owner,repo,data,root,rows=setup(monkeypatch);original=held_corpus.reference_derive
    def changed(raw,selection,**kwargs):
        raw=tuple(replace(r,revision=r.revision+1) if r.key==root.key else r for r in raw)
        return original(raw,selection,**kwargs)
    monkeypatch.setattr(held_corpus,'reference_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_legacy_parentless_reference_and_marker_remain_unresolved(monkeypatch):
    reader,admission,owner,repo,data,*_=world(monkeypatch)
    key=Key('state','asset#'+uid(900));data[key]=Row(key,1,{'id':uid(900),'kind':'reference','status':'committed'})
    result=read(reader);assert result.corpus.references.family_count==0
    assert next(x for x in result.accounting.entries if x.reference.key==key).disposition=='UNRESOLVED'
    assert owner.wait_for_drain(0)


def test_reference_summary_changes_binding_but_does_not_expand_inspection_scope(monkeypatch):
    reader,owner,repo,data,root,rows=setup(monkeypatch);first=read(reader)
    assert first.corpus.scope.inspection_ids==(uid(1),)
    assert first.corpus.references.summary_sha256!=__import__('hashlib').sha256(b'').hexdigest()
    assert first.corpus.binding_sha256==read(reader).corpus.binding_sha256
