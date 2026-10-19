"""Actual local held purpose accounting; synthetic published history, no rights proof."""
from time import monotonic_ns
from uuid import UUID,uuid4
import pytest
from test_access_lifecycle import world,repository_factory,publication_case as publication_fixture
from test_owner_accounting_review_store import prepared,inventory
from proofpack.evidence.runtime_context import RuntimeContextLimits
from proofpack.evidence.purpose_history import PurposeHistoryLimits
from proofpack.evidence.purpose_corpus import PurposeCorpusLimits
from proofpack.evidence.ownership_classification import ClassificationLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.purposes import DataPurposes,PurposeRequest
from proofpack.runtime.control import RuntimeControl

RUNTIME=RuntimeContextLimits(2000,8_000_000,400000,8_000_000)
PURPOSE=PurposeCorpusLimits(20,PurposeHistoryLimits(100,1_000_000,1000,10000,1_000_000),400000,8_000_000)


@pytest.fixture
def complete_publication(world,recipe,request,monkeypatch):
    """Replace only the known legacy seed with actual purpose creation, retaining all rows."""
    import proofpack.evidence.purposes as purpose_writer
    original=world[1].transact;replacements=[]
    def transact(writes,checks=()):
        if (len(writes)==1 and writes[0].key.resource.startswith('purpose#') and writes[0].expected_revision is None
                and set(writes[0].data)=={'allowed_uses','withdrawn','expires_at_ms'}):
            seed=writes[0];runtime=RuntimeControl(world[0],instance_id=str(uuid4()),artifact_sha256='a'*64,
                controls_sha256='b'*64,environment='test');runtime.start()
            service=DataPurposes(world[0],runtime,max_lifetime_ms=100000);notice=world[0].operational_notice(world[5])
            document=PurposeRequest(notice_version=notice['version'],notice_sha256=notice['sha256'],
                source_permission_reference='synthetic-publication-source',operational_use_acknowledged=True,
                expires_at_ms=int(seed.data['expires_at_ms']))
            with monkeypatch.context() as m:
                m.setattr(purpose_writer,'uuid4',lambda:UUID(seed.key.resource.split('#')[1]))
                result=service.create(world[5],request=document,idempotency_key='publication-purpose')
            assert result['id']==seed.key.resource.split('#')[1];replacements.append(seed.key)
            return None
        return original(writes,checks)
    monkeypatch.setattr(world[1],'transact',transact)
    generator=publication_fixture.__wrapped__(world,recipe,request)
    case=next(generator)
    try:
        assert len(replacements)==1
        yield case
    finally:
        next(generator,None)


def read(p,**changes):
    return p[2].read_purpose_accounting(**(dict(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
        runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE)|changes))


def test_actual_selected_purpose_histories_reduce_unknowns_without_mutation(world,complete_publication,monkeypatch):
    p=prepared(world,complete_publication);before=inventory(world[1])
    old=p[2].read_runtime_accounting(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,runtime_context_limits=RUNTIME)
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('purpose context wrote business metadata'))
    result=read(p);families=result.corpus.purposes
    assert families.family_count>0 and families.records
    old_unknown=dict(old.accounting.counts)['UNRESOLVED'];new_unknown=dict(result.accounting.counts)['UNRESOLVED']
    assert 0<new_unknown<old_unknown
    changes=[(a,b) for a,b in zip(old.accounting.entries,result.accounting.entries) if a!=b]
    allowed={r.key for r in families.records}
    assert all(a.reference==b.reference and a.reference.key in allowed and b.disposition=='CONTEXT'
        and a.disposition in {'UNRESOLVED','CONTEXT'} and not b.inspection_ids for a,b in changes)
    assert sum(a.disposition=='UNRESOLVED' for a,b in changes)==old_unknown-new_unknown
    with pytest.raises(HeldCorpusHeld):
        p[2].read_purpose_classification(request_id=p[4]['id'],inspection_ids=(p[5],),
            deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
            runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE,
            classification_limits=ClassificationLimits(2000,10000,800000,8_000_000))
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_actual_original_deadline_cannot_be_renewed(world,complete_publication):
    p=prepared(world,complete_publication);before=inventory(world[1])
    with pytest.raises(HeldCorpusHeld):read(p,deadline_ns=monotonic_ns()-1)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_original_legacy_seed_has_no_history_and_cannot_be_promoted(world,publication_fixture):
    p=prepared(world,publication_fixture);before=inventory(world[1])
    with pytest.raises(HeldCorpusHeld):read(p)
    assert inventory(world[1])==before and p[3].wait_for_drain(0)
