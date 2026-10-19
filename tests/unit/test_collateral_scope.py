from dataclasses import replace,FrozenInstanceError
import pytest
from proofpack.evidence.collateral_scope import propose,CollateralLimits,CollateralHeld
from proofpack.evidence.corpus_accounting import CorpusAccounting,AccountedRecord,DISPOSITIONS,POLICY
from proofpack.evidence.inventory import InventoryEntry
from proofpack.evidence.repository import Key

def uid(n):return '00000000-0000-0000-0000-'+str(n).zfill(12)
def row(n,ids,disposition,policy='DATASET_ARTIFACT_CONTENT'):
 return AccountedRecord(InventoryEntry(Key('state','private#'+str(n)),1,'live','a'*64,None,None),disposition,'validated',tuple(uid(i) for i in ids),(policy,))
def accounting(rows):
 return CorpusAccounting(POLICY,'b'*64,'c'*64,(uid(1),),tuple(rows),(),tuple((d,sum(r.disposition==d for r in rows)) for d in DISPOSITIONS),1,1)
def run(value,limits=None,**kwargs):return propose(value,limits=limits or CollateralLimits(100,100,100,1000),deadline_ns=100,tick=lambda:1,checkpoint=lambda:None,**kwargs)
def test_transitive_scope_includes_initially_unrelated_copies_but_not_context_or_unknown():
 rows=[row(1,[1,2],'SHARED'),row(2,[2,3],'UNRELATED'),row(3,[3,4],'CONTEXT'),row(4,[3,5],'UNRESOLVED'),row(5,[8,9],'UNRELATED')]
 value=accounting(rows);result=run(value)
 assert result.proposed_scope==(uid(1),uid(2),uid(3))
 assert result.implicated==tuple(r.reference for r in rows[:2]) and result.unresolved==(rows[3].reference,)
 assert result.historical and not result.can_confirm_cleanup and 'private#' not in repr(result) and uid(1) not in repr(result)
 assert run(value)==result
 with pytest.raises(FrozenInstanceError):result.work=0
@pytest.mark.parametrize('field,value',[('max_records',1),('max_memberships',3),('max_scope',2),('max_work',2)])
def test_independent_exhaustion_never_returns_truncated_scope(field,value):
 with pytest.raises(CollateralHeld):run(accounting([row(1,[1,2],'SHARED'),row(2,[2,3],'UNRELATED')]),replace(CollateralLimits(100,100,100,1000),**{field:value}))
@pytest.mark.parametrize('bad',[True,0,-1,1.5,'3',2**63])
def test_bounds_strict(bad):
 with pytest.raises(ValueError):CollateralLimits(bad,100,100,100)
@pytest.mark.parametrize('fault',['duplicate','unsorted','wrong_disposition','unknown_policy','counts','summary','scope'])
def test_bad_accounting_holds(fault):
 rows=[row(1,[1,2],'SHARED')];value=accounting(rows)
 if fault=='duplicate':value=accounting(rows*2)
 if fault=='unsorted':value=accounting([replace(rows[0],inspection_ids=(uid(2),uid(1)))])
 if fault=='wrong_disposition':value=accounting([replace(rows[0],disposition='UNRELATED')])
 if fault=='unknown_policy':value=accounting([replace(rows[0],policies=('future-policy',))])
 if fault=='counts':value=replace(value,counts=())
 if fault=='summary':value=replace(value,summary_sha256='x')
 if fault=='scope':value=replace(value,requested_inspections=())
 with pytest.raises(CollateralHeld):run(value)
@pytest.mark.parametrize('ticks',[[100],[True],[2,1]])
def test_original_clock_faults_hold(ticks):
 values=iter(ticks);last=ticks[-1]
 with pytest.raises(CollateralHeld):propose(accounting([row(1,[1],'AFFECTED')]),limits=CollateralLimits(100,100,100,1000),deadline_ns=100,tick=lambda:next(values,last),checkpoint=lambda:None)
def test_checkpoint_denial_propagates():
 def denied():raise RuntimeError('authority changed')
 with pytest.raises(RuntimeError,match='authority changed'):propose(accounting([]),limits=CollateralLimits(100,100,100,1000),deadline_ns=100,tick=lambda:1,checkpoint=denied)

@pytest.mark.parametrize('fault',['resource','revision','kind','digest','count_bool'])
def test_bad_reference_and_strict_counts(fault):
 value=accounting([row(1,[1],'AFFECTED')]);entry=value.entries[0];ref=entry.reference
 if fault=='resource':ref=replace(ref,key=Key('state','x'*257))
 if fault=='revision':ref=replace(ref,revision=True)
 if fault=='kind':ref=replace(ref,kind='future')
 if fault=='digest':ref=replace(ref,payload_sha256='bad')
 value=replace(value,entries=(replace(entry,reference=ref),))
 if fault=='count_bool':value=replace(value,counts=tuple((name,True if count else 0) for name,count in value.counts))
 with pytest.raises(CollateralHeld):run(value)
def test_membership_bound_precedes_validation_work(monkeypatch):
 import proofpack.evidence.collateral_scope as module
 original=module.uuid;seen=[]
 def observed(ident):seen.append(ident);return original(ident)
 monkeypatch.setattr(module,'uuid',observed)
 with pytest.raises(CollateralHeld):run(accounting([row(1,[1,2],'SHARED')]),CollateralLimits(100,1,100,1000))
 assert seen==[uid(1)],'only bounded original scope is validated before oversized record memberships are rejected'

def test_actual_held_reader_proposal_retains_resource_and_original_scope(monkeypatch):
 from test_held_corpus import world,REQUEST
 from test_corpus_accounting import LIMITS
 from proofpack.evidence import held_corpus
 reader,admission,owner,repo,data,_,_=world(monkeypatch)
 before=dict(data);called=[]
 original=held_corpus.propose
 def observed(*args,**kwargs):
  assert not owner.wait_for_drain(0);called.append(True);return original(*args,**kwargs)
 monkeypatch.setattr(held_corpus,'propose',observed)
 result=reader.read_scope_proposal(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,accounting_limits=LIMITS,collateral_limits=CollateralLimits(1000,10000,1000,200000))
 assert called==[True] and result.corpus.scope.inspection_ids==(uid(1),) and result.proposal.original_scope==(uid(1),)
 assert result.proposal.historical and not result.proposal.can_confirm_cleanup and data==before and owner.wait_for_drain(0)
 assert result.accounting.summary_sha256==result.proposal.accounting_sha256

def test_post_proposal_source_phantom_withholds_complete_held_result(monkeypatch):
 from test_held_corpus import world,REQUEST
 from test_corpus_accounting import LIMITS
 from proofpack.evidence import held_corpus
 from proofpack.evidence.repository import Row
 reader,admission,owner,repo,data,_,_=world(monkeypatch)
 original=held_corpus.propose
 def changed(*args,**kwargs):
  result=original(*args,**kwargs);k=Key('state','unexpected#copy');data[k]=Row(k,1,{'private':'not a proof of absence'});return result
 monkeypatch.setattr(held_corpus,'propose',changed)
 with pytest.raises(held_corpus.HeldCorpusHeld):reader.read_scope_proposal(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,accounting_limits=LIMITS,collateral_limits=CollateralLimits(1000,10000,1000,200000))
 assert owner.wait_for_drain(0)

@pytest.mark.parametrize('disposition',['AFFECTED','UNRESOLVED'])
def test_retained_marker_never_becomes_supported_owned_content(disposition):
 record=row(1,[1],disposition);marker=replace(record.reference,revision=2,kind='erased',payload_sha256=None,reference_sha256='a'*64,resource_sha256='b'*64)
 value=accounting([replace(record,reference=marker)])
 if disposition=='AFFECTED':
  with pytest.raises(CollateralHeld):run(value)
 else:
  result=run(value);assert result.unresolved==(marker,) and not result.implicated and not result.can_confirm_cleanup
