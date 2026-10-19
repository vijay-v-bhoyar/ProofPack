"""Actual local SDK/store and genuine synthetic CV; no physical/user evidence."""
from time import monotonic_ns
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_owner_accounting_review_store import prepared,inventory
from proofpack.evidence.runtime_context import RuntimeContextLimits
from proofpack.evidence.ownership_classification import ClassificationLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld

CONTEXT=RuntimeContextLimits(2000,8_000_000,400000,8_000_000)


def read(p,**changes):
    return p[2].read_runtime_accounting(**(dict(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
        runtime_context_limits=CONTEXT)|changes))


def test_actual_history_only_validated_context_reduces_unknowns_without_writes(world,publication_case,monkeypatch):
    p=prepared(world,publication_case);before=inventory(world[1])
    old=p[2].read_accounting(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits)
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('context read wrote'))
    current=read(p);ctx=current.corpus.runtime_context
    old_unknown=dict(old.accounting.counts)['UNRESOLVED'];new_unknown=dict(current.accounting.counts)['UNRESOLVED']
    assert 0 < new_unknown < old_unknown
    changed=[(a,b) for a,b in zip(old.accounting.entries,current.accounting.entries) if a!=b]
    assert len(changed)==old_unknown-new_unknown==len(ctx.records)
    assert all(a.disposition=='UNRESOLVED' and b.disposition=='CONTEXT' and not b.inspection_ids for a,b in changed)
    with pytest.raises(HeldCorpusHeld):
        p[2].read_runtime_classification(request_id=p[4]['id'],inspection_ids=(p[5],),
            deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
            runtime_context_limits=CONTEXT,classification_limits=ClassificationLimits(2000,10000,400000,8_000_000))
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_actual_context_keeps_original_expired_deadline(world,publication_case):
    p=prepared(world,publication_case);before=inventory(world[1])
    with pytest.raises(HeldCorpusHeld):read(p,deadline_ns=monotonic_ns()-1)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)
