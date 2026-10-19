"""Actual local stored CV history and held proposal; synthetic provider identity/S3."""
from time import monotonic_ns
from uuid import uuid4
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_owner_accounting_review_store import prepared,inventory
from proofpack.evidence.collateral_scope import CollateralLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import Key,Write

BOUNDS=CollateralLimits(2000,10000,30,200000)
def proposal(p,**overrides):
 return p[2].read_scope_proposal(**(dict(request_id=p[4]['id'],inspection_ids=(p[5],),deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,collateral_limits=BOUNDS)|overrides))

def test_actual_proposal_is_read_only_original_scoped_and_keeps_obligations(world,publication_case,monkeypatch):
 p=prepared(world,publication_case);before=inventory(world[1]);called=[]
 from proofpack.evidence import held_corpus
 original=held_corpus.propose
 def observed(*args,**kwargs):
  assert not p[3].wait_for_drain(0);called.append(True);return original(*args,**kwargs)
 monkeypatch.setattr(held_corpus,'propose',observed)
 monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('proposal wrote business metadata'))
 result=proposal(p)
 assert called==[True] and result.corpus.scope.inspection_ids==result.proposal.original_scope==(p[5],)
 assert result.proposal.proposed_scope==(p[5],) and result.proposal.implicated and result.proposal.unresolved
 assert result.proposal.accounting_sha256==result.accounting.summary_sha256
 assert result.proposal.historical is True and result.proposal.can_confirm_cleanup is False
 assert inventory(world[1])==before and p[3].wait_for_drain(0)
 assert all(v not in repr(result) for v in [p[5],'inspection#','session#','deployments/'])

def test_actual_post_proposal_phantom_denies_delivery_and_releases_resources(world,publication_case,monkeypatch):
 p=prepared(world,publication_case)
 from proofpack.evidence import held_corpus
 original=held_corpus.propose;changed=[]
 def phantom(*args,**kwargs):
  result=original(*args,**kwargs);world[1].transact((Write(Key('state','future-collateral#'+str(uuid4())),None,{'secret':'KEEP_UNKNOWN'}),));changed.append(True);return result
 monkeypatch.setattr(held_corpus,'propose',phantom)
 with pytest.raises(HeldCorpusHeld):proposal(p)
 assert changed==[True] and p[3].wait_for_drain(0)

@pytest.mark.parametrize('field',['max_records','max_memberships'])
def test_actual_exhaustion_returns_no_partial_proposal_or_mutation(world,publication_case,field):
 from dataclasses import replace
 p=prepared(world,publication_case);before=inventory(world[1])
 with pytest.raises(HeldCorpusHeld):proposal(p,collateral_limits=replace(BOUNDS,**{field:1}))
 assert inventory(world[1])==before and p[3].wait_for_drain(0)

def test_actual_original_expired_deadline_grants_no_proposal_or_renewal(world,publication_case):
 p=prepared(world,publication_case);before=inventory(world[1])
 with pytest.raises(HeldCorpusHeld):proposal(p,deadline_ns=monotonic_ns()-1)
 assert inventory(world[1])==before and p[3].wait_for_drain(0)
