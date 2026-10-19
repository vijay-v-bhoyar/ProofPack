"""Genuine configured owner read over owned local stores; synthetic identity/images."""
from dataclasses import replace
import pytest
from test_access_lifecycle import repository_factory
from test_purpose_context_store import world,complete_publication,RUNTIME,PURPOSE
from test_access_context_store import ACCESS
from test_auth_history_consumption_store import AUTH,oauth
from test_owner_accounting_review_store import prepared,inventory,read
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview,AuthReviewLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import StoreConflict
from proofpack.auth.policy import Denied


def configured(world,complete_publication):
    p=prepared(world,complete_publication)
    service=OwnerMetadataReview(p[1],p[2],accounting_limits=p[0].accounting_limits,max_response_bytes=8192,
        auth_review=AuthReviewLimits(RUNTIME,ACCESS,AUTH,PURPOSE))
    return (service,*p[1:])


def test_genuine_owner_receives_v5_counts_without_policy_or_cleanup_authority(world,complete_publication,monkeypatch):
    p=configured(world,complete_publication);oauth(world);before=inventory(world[1])
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('owner auth review mutated business rows'))
    result=read(p,world[5])
    assert result['accounting_policy']=='conservative-family-accounting-v5'
    assert result['auth_history_policy_resolved'] is False
    assert result['historical_auth_authority_proven'] is False
    assert result['historical'] is True and result['read_only'] is True
    assert all(result[k] is False for k in ['can_confirm_cleanup','erasure_complete','request_fulfilled'])
    assert result['total_records']==sum(result['counts'].values())==len(before)
    assert result['counts']['UNRESOLVED']>0
    assert inventory(world[1])==before and p[3].wait_for_drain(0)
    assert not any(secret in repr(result) for secret in ['session#','cookie#','oauth-flow#','family_digests','example.test'])


def test_operator_cannot_reach_configured_auth_reader(world,complete_publication,monkeypatch):
    p=configured(world,complete_publication)
    monkeypatch.setattr(p[2],'read_auth_accounting',lambda **kw:pytest.fail('operator reached auth inventory'))
    with pytest.raises(Denied):read(p,complete_publication[3])
    assert p[3].wait_for_drain(0)


def test_stale_owner_review_cannot_reach_configured_auth_reader(world,complete_publication,monkeypatch):
    p=configured(world,complete_publication)
    monkeypatch.setattr(p[2],'read_auth_accounting',lambda **kw:pytest.fail('stale review reached auth inventory'))
    with pytest.raises(StoreConflict):read(p,world[5],expected_gate_version=p[4]['gate_version']+1)
    assert p[3].wait_for_drain(0)


def test_valid_v1_result_cannot_silently_replace_configured_v5(world,complete_publication,monkeypatch):
    p=configured(world,complete_publication);original=p[2].read_accounting
    def downgrade(**kw):
        args={k:kw[k] for k in ['request_id','inspection_ids','deadline_ns','accounting_limits']}
        return original(**args)
    monkeypatch.setattr(p[2],'read_auth_accounting',downgrade)
    with pytest.raises(HeldCorpusHeld):read(p,world[5])
    assert p[3].wait_for_drain(0)
