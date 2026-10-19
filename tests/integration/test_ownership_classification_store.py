"""Actual local metadata/CV; unknown histories stay held, not accepted ownership."""
from dataclasses import replace
from time import monotonic_ns
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_owner_accounting_review_store import prepared,inventory
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.ownership_classification import ClassificationLimits

BOUNDS=ClassificationLimits(2000,10000,400000,8_000_000)
def read(p,**changes):
    return p[2].read_classification(**(dict(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
        classification_limits=BOUNDS)|changes))

def test_actual_published_history_with_unknowns_cannot_be_accepted_or_mutated(world,publication_case,monkeypatch):
    p=prepared(world,publication_case);before=inventory(world[1])
    accounted=p[2].read_accounting(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits)
    assert dict(accounted.accounting.counts)['UNRESOLVED']>0
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('classification wrote business metadata'))
    with pytest.raises(HeldCorpusHeld):read(p)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)

def test_actual_record_bound_holds_before_recomputed_accounting_allocation(world,publication_case,monkeypatch):
    import proofpack.evidence.ownership_classification as module
    p=prepared(world,publication_case);before=inventory(world[1])
    monkeypatch.setattr(module,'account',lambda *a,**k:pytest.fail('exhausted classification allocated accounting'))
    with pytest.raises(HeldCorpusHeld):read(p,classification_limits=replace(BOUNDS,max_records=1))
    assert inventory(world[1])==before and p[3].wait_for_drain(0)

def test_actual_original_deadline_cannot_be_renewed(world,publication_case):
    p=prepared(world,publication_case);before=inventory(world[1])
    with pytest.raises(HeldCorpusHeld):read(p,deadline_ns=monotonic_ns()-1)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)
