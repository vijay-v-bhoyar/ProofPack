"""Actual local storage/CV with synthetic identity and intercepted media only."""
from dataclasses import replace
from time import monotonic_ns
from uuid import uuid4
import pytest
from test_access_lifecycle import repository_factory
from test_purpose_context_store import world, complete_publication, PURPOSE, RUNTIME
from test_owner_accounting_review_store import prepared, inventory
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import Key, Write
from proofpack.evidence.access_context import AccessContextLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.ownership_classification import ClassificationLimits
from proofpack.evidence.runtime_lineage import _integer as stored_integer

ACCESS=AccessContextLimits(2000,8_000_000,400_000,8_000_000)


def read(p, **changes):
    return p[2].read_access_accounting(**(dict(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
        runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE,access_context_limits=ACCESS)|changes))


def origin(repository, ident):
    root=repository.snapshot((Key('state','inspection#'+ident),))[Key('state','inspection#'+ident)]
    return root,Key('state','user#'+root.data['originating_user_id']),Key('state','session#'+root.data['originating_session_id'])


def test_actual_origin_context_reduces_only_exact_unknowns_and_preserves_v3(world,complete_publication,monkeypatch):
    p=prepared(world,complete_publication);before=inventory(world[1])
    old=p[2].read_purpose_accounting(request_id=p[4]['id'],inspection_ids=(p[5],),deadline_ns=monotonic_ns()+20_000_000_000,
        accounting_limits=p[0].accounting_limits,runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE)
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('private context read wrote'))
    result=read(p);context=result.corpus.access_context
    assert old.accounting.policy=='conservative-family-accounting-v3' and old.corpus.access_context is None
    assert result.accounting.policy=='conservative-family-accounting-v4' and len(context.origins)==1
    assert len(context.records)==4 and context.can_confirm_cleanup is False
    differences=[(a,b) for a,b in zip(old.accounting.entries,result.accounting.entries) if a!=b]
    expected={r.key for r in context.records}
    assert {a.reference.key for a,b in differences}==expected
    assert all(a.reference==b.reference and a.disposition=='UNRESOLVED' and b.disposition=='CONTEXT' and not b.inspection_ids for a,b in differences)
    assert 0<dict(result.accounting.counts)['UNRESOLVED']==dict(old.accounting.counts)['UNRESOLVED']-4
    with pytest.raises(HeldCorpusHeld):
        p[2].read_access_classification(request_id=p[4]['id'],inspection_ids=(p[5],),deadline_ns=monotonic_ns()+20_000_000_000,
            accounting_limits=p[0].accounting_limits,runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE,
            access_context_limits=ACCESS,classification_limits=ClassificationLimits(2000,10000,1_200_000,8_000_000))
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_actual_revocation_preserves_original_interpretation_without_restoring_login(world,complete_publication):
    p=prepared(world,complete_publication);root,member_key,session_key=origin(world[1],p[5])
    member=world[1].snapshot((member_key,))[member_key]
    world[0].revoke_sessions(world[5],user_id=member.data['id'],expected_version=stored_integer(member.data['access_version'],minimum=1),idempotency_key='revoke-origin-context')
    credentials=complete_publication[4]
    with pytest.raises(Denied):world[0].resolve(credentials.cookie)
    before=inventory(world[1]);context=read(p).corpus.access_context
    assert member_key in {r.key for r in context.records} and session_key in {r.key for r in context.records}
    assert context.read_only is True and context.can_confirm_cleanup is False
    with pytest.raises(Denied):world[0].resolve(credentials.cookie)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


@pytest.mark.parametrize('change',['copied_content','expired_at_origin'])
def test_actual_selected_access_corruption_stays_held(world,complete_publication,change):
    p=prepared(world,complete_publication);root,member_key,session_key=origin(world[1],p[5])
    key=member_key if change=='copied_content' else session_key
    row=world[1].snapshot((key,))[key]
    patch={'inspection_id':p[5]} if change=='copied_content' else {'expires_at_ms':root.data['created_at_ms']}
    world[1].transact((Write(key,row.revision,{**row.data,**patch}),))
    before=inventory(world[1])
    with pytest.raises(HeldCorpusHeld):read(p)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_actual_source_phantom_after_derivation_is_not_lost(world,complete_publication,monkeypatch):
    import proofpack.evidence.held_corpus as held
    p=prepared(world,complete_publication);original=held.access_derive;changed=[]
    def alter(*args,**kwargs):
        result=original(*args,**kwargs)
        key=Key('state','unknown-access-context#'+str(uuid4()))
        world[1].transact((Write(key,None,{'private':'synthetic-only-unknown'}),));changed.append(key)
        return result
    monkeypatch.setattr(held,'access_derive',alter)
    with pytest.raises(HeldCorpusHeld):read(p)
    assert len(changed)==1 and world[1].snapshot(tuple(changed))[changed[0]] is not None and p[3].wait_for_drain(0)
