"""Owned local store/CV and real service methods; synthetic identity/intercepted S3."""
from time import monotonic_ns
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit
import pytest
from test_access_lifecycle import repository_factory
from test_purpose_context_store import world, complete_publication, PURPOSE, RUNTIME
from test_owner_accounting_review_store import prepared, inventory
from test_access_context_store import ACCESS, origin, read as read_v4
from proofpack.auth.oauth import OAuthConfig, OAuthFlows
from proofpack.evidence.repository import Key, Write
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.auth_history import AuthHistoryLimits

AUTH=AuthHistoryLimits(2000,8_000_000,10000,800_000,8_000_000)


def read(p):
    return p[2].read_auth_accounting(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
        runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE,access_context_limits=ACCESS,auth_history_limits=AUTH)


def oauth(world):
    flows=OAuthFlows(world[1],OAuthConfig(world[1].deployment,'https://provider.example.test','syntheticclient',
        'https://proofpack.example.test/api/v1/auth/callback',b'z'*32),clock_ms=world[0].clock_ms)
    started=flows.begin();flows.admit_callback()
    state=parse_qs(urlsplit(started.authorization_url).query)['state'][0]
    flows.consume(state=state,browser_cookie=started.browser_cookie)


def test_stored_families_and_consumed_oauth_remain_policy_held_and_unchanged(world,complete_publication,monkeypatch):
    p=prepared(world,complete_publication);oauth(world);before=inventory(world[1]);old=read_v4(p)
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('auth history read wrote stored rows'))
    result=read(p);auth=result.corpus.auth_history
    assert result.accounting.policy=='conservative-family-accounting-v5' and result.accounting.counts==old.accounting.counts
    assert auth.invitation_families>0 and auth.dependencies>0 and auth.policy_resolved is False
    assert auth.can_confirm_cleanup is False and auth.read_only is True
    assert {'oauth-flow','oauth-quota','invitation','bootstrap'} <= {r.family for r in auth.records}
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_stored_revoked_origin_preserves_no_current_authority(world,complete_publication):
    p=prepared(world,complete_publication);_,member_key,_=origin(world[1],p[5])
    member=world[1].snapshot((member_key,))[member_key]
    world[0].revoke_sessions(world[5],user_id=member.data['id'],expected_version=int(member.data['access_version']),idempotency_key='auth-history-revoke')
    before=inventory(world[1]);result=read(p)
    assert result.corpus.auth_history.historical_authority_proven is False
    assert any(r.family=='access-replay' and r.validation=='ACCESS_RESULT_AND_BINDING' for r in result.corpus.auth_history.records)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_stored_malformed_oauth_is_not_repaired_or_classified(world,complete_publication):
    p=prepared(world,complete_publication);oauth(world)
    key=Key('state','oauth-quota#login');row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{**row.data,'unexpected':True}),));before=inventory(world[1])
    with pytest.raises(HeldCorpusHeld):read(p)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_stored_post_auth_derivation_phantom_is_not_published(world,complete_publication,monkeypatch):
    import proofpack.evidence.held_corpus as held
    p=prepared(world,complete_publication);original=held.auth_derive;changed=[]
    def alter(*a,**k):
        result=original(*a,**k)
        key=Key('state','unknown-auth-history#'+str(uuid4()))
        world[1].transact((Write(key,None,{'synthetic':True}),));changed.append(key)
        return result
    monkeypatch.setattr(held,'auth_derive',alter)
    with pytest.raises(HeldCorpusHeld):read(p)
    assert len(changed)==1 and world[1].snapshot(tuple(changed))[changed[0]] is not None and p[3].wait_for_drain(0)
