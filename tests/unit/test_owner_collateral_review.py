"""Owner-authenticated advisory collateral service on modeled storage; SDK denied."""
from copy import deepcopy
from dataclasses import replace
import pytest
from test_owner_accounting_review import world as base_world,ident,LIMITS
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
from proofpack.evidence.collateral_scope import CollateralLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import Key,Row,StoreConflict
from proofpack.auth.policy import Denied
from proofpack.evidence.privacy_admission import AdmissionHeld

BOUNDS=CollateralLimits(1000,10000,10,200000)
def world(monkeypatch):
 w=base_world(monkeypatch);return (OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=8192,collateral_limits=BOUNDS),*w[1:])
def read(w,**overrides):
 r=w[7];return w[0].read_collateral(w[3],**(dict(ident=r['id'],expected_request_version=r['state_version'],expected_gate_version=r['gate_version'],expected_control_version=r['control_version'])|overrides))
def test_owner_receives_closed_historical_scope_without_mutation(monkeypatch):
 w=world(monkeypatch);before=deepcopy(w[5]);r=read(w)
 assert set(r)==set('id scope_sha256 request_version gate_version control_version proposal_policy original_inspection_ids proposed_inspection_ids additional_inspection_ids implicated_records unresolved_records total_records historical read_only scope_changed can_confirm_cleanup erasure_complete request_fulfilled'.split())
 assert r['id']==w[7]['id'] and r['scope_sha256']==w[7]['scope_sha256'] and r['original_inspection_ids']==[ident(1)]
 assert set(r['original_inspection_ids'])<=set(r['proposed_inspection_ids']) and r['additional_inspection_ids']==sorted(set(r['proposed_inspection_ids'])-set(r['original_inspection_ids']))
 assert r['historical'] is r['read_only'] is True and r['implicated_records']>0 and r['unresolved_records']>0
 assert all(r[k] is False for k in ['scope_changed','can_confirm_cleanup','erasure_complete','request_fulfilled'])
 assert r['implicated_records']+r['unresolved_records']<=r['total_records'] and w[5]==before and w[-1].wait_for_drain(0)
 assert not any(x in repr(r) for x in ['session#','idempotency#','PRIVATE-PAYLOAD','owner@example.invalid'])
def test_absent_collateral_configuration_is_unavailable(monkeypatch):
 w=base_world(monkeypatch)
 with pytest.raises(HeldCorpusHeld):read(w)
@pytest.mark.parametrize('field',['expected_request_version','expected_gate_version','expected_control_version'])
def test_stale_versions_deny_before_private_scope_read(monkeypatch,field):
 w=world(monkeypatch);monkeypatch.setattr(w[2],'read_scope_proposal',lambda **kw:pytest.fail('stale request started private scope read'))
 with pytest.raises(StoreConflict):read(w,**{field:999})
@pytest.mark.parametrize('bad',[True,0,{},'configured'])
def test_exact_limits_required_without_store_io(monkeypatch,bad):
 w=base_world(monkeypatch);monkeypatch.setattr(w[4],'snapshot',lambda *a:pytest.fail('configuration performed I/O'))
 with pytest.raises(ValueError):OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=8192,collateral_limits=bad)
def test_scope_limit_cannot_exceed_owner_request_capacity(monkeypatch):
 w=base_world(monkeypatch)
 with pytest.raises(ValueError):OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=8192,collateral_limits=replace(BOUNDS,max_scope=11))
@pytest.mark.parametrize('when',['before','after'])
def test_current_owner_rechecked(monkeypatch,when):
 w=world(monkeypatch);original=w[2].read_scope_proposal
 def revoke():
  r=w[5][w[3].member.key];w[5][r.key]=Row(r.key,r.revision+1,{**r.data,'enabled':False})
 def changed(**kw):
  result=original(**kw);revoke();return result
 if when=='before':revoke()
 else:monkeypatch.setattr(w[2],'read_scope_proposal',changed)
 with pytest.raises((Denied,StoreConflict,AdmissionHeld)):read(w)
 assert w[-1].wait_for_drain(0)
def test_post_reader_phantom_withholds_scope(monkeypatch):
 w=world(monkeypatch);original=w[2].read_scope_proposal
 def changed(**kw):
  result=original(**kw);key=Key('state','future#private-copy');w[5][key]=Row(key,1,{'private':'KEEP_UNKNOWN'});return result
 monkeypatch.setattr(w[2],'read_scope_proposal',changed)
 with pytest.raises(HeldCorpusHeld):read(w)
 assert w[-1].wait_for_drain(0)
@pytest.mark.parametrize('fault',['policy','original','missing_original','unsorted','duplicate','scope_capacity','authority','historical','accounting'])
def test_corrupt_private_proposal_never_supplies_owner_view(monkeypatch,fault):
 w=world(monkeypatch);original=w[2].read_scope_proposal
 def corrupt(**kw):
  result=original(**kw);p=result.proposal
  changes={'policy':{'policy':'future'},'original':{'original_scope':(ident(2),)},'missing_original':{'proposed_scope':(ident(2),)},'unsorted':{'proposed_scope':(ident(2),ident(1))},'duplicate':{'proposed_scope':(ident(1),ident(1))},'scope_capacity':{'proposed_scope':tuple(ident(i) for i in range(1,12))},'authority':{'can_confirm_cleanup':True},'historical':{'historical':False},'accounting':{'accounting_sha256':'b'*64}}[fault]
  return replace(result,proposal=replace(p,**changes))
 monkeypatch.setattr(w[2],'read_scope_proposal',corrupt)
 with pytest.raises(HeldCorpusHeld):read(w)
 assert w[-1].wait_for_drain(0)

@pytest.mark.parametrize('fault',['invalid_identifier','missing_implicated','context_implicated','unknown_identifier'])
def test_private_scope_and_implicated_references_are_complete(monkeypatch,fault):
 w=world(monkeypatch);original=w[2].read_scope_proposal
 def corrupt(**kw):
  result=original(**kw);p=result.proposal
  if fault=='invalid_identifier':p=replace(p,proposed_scope=tuple(sorted((*p.proposed_scope,'invalid-private-id'))))
  if fault=='unknown_identifier':p=replace(p,proposed_scope=tuple(sorted((*p.proposed_scope,ident(777)))))
  if fault=='missing_implicated':p=replace(p,implicated=())
  if fault=='context_implicated':
   context=next(e.reference for e in result.accounting.entries if e.disposition=='CONTEXT');p=replace(p,implicated=(*p.implicated,context))
  return replace(result,proposal=p)
 monkeypatch.setattr(w[2],'read_scope_proposal',corrupt)
 with pytest.raises(HeldCorpusHeld):read(w)
 assert w[-1].wait_for_drain(0)
