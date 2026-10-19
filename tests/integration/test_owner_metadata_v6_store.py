"""Owned DynamoDB Local and actual CV publication; synthetic identity/intercepted S3."""
from dataclasses import replace
from time import monotonic_ns
from uuid import uuid4
import pytest

from test_access_lifecycle import repository_factory
from test_purpose_context_store import world,complete_publication,PURPOSE,RUNTIME
from test_access_context_store import ACCESS
from test_auth_history_consumption_store import AUTH
from test_owner_accounting_review_store import prepared,inventory
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview,AuthReviewLimits
from proofpack.evidence.owner_metadata_http import MetadataReviewResult,MetadataPolicyObligationsResult
from proofpack.evidence.metadata_history import MetadataHistoryLimits
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import Key,Write

METADATA=MetadataHistoryLimits(2000,8_000_000,10000,800000,8_000_000,10,20)


def configured(p):
    service=OwnerMetadataReview(p[1],p[2],accounting_limits=p[0].accounting_limits,max_response_bytes=8192,
        auth_review=AuthReviewLimits(RUNTIME,ACCESS,AUTH,PURPOSE),metadata_review=METADATA)
    return (service,*p[1:])


def read(p,actor,explain=False):
    method=p[0].read_policy_obligations if explain else p[0].read
    r=p[4]
    return method(actor,ident=r['id'],expected_request_version=r['state_version'],
        expected_gate_version=r['gate_version'],expected_control_version=r['control_version'])


def private(p):
    return p[2].read_metadata_accounting(request_id=p[4]['id'],inspection_ids=(p[5],),
        deadline_ns=monotonic_ns()+20_000_000_000,accounting_limits=p[0].accounting_limits,
        runtime_context_limits=RUNTIME,purpose_corpus_limits=PURPOSE,access_context_limits=ACCESS,
        auth_history_limits=AUTH,metadata_history_limits=METADATA,metadata_configuration_sha256=p[1]._configuration)


def test_actual_stored_owner_v6_review_and_explanation_do_not_write_or_authorize(world,complete_publication,monkeypatch):
    p=configured(prepared(world,complete_publication));before=inventory(world[1])
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('owner history read wrote stored rows'))
    review=read(p,world[5]);explanation=read(p,world[5],True)
    assert MetadataReviewResult.model_validate(review).model_dump()==review
    assert MetadataPolicyObligationsResult.model_validate(explanation).model_dump()==explanation
    assert review['accounting_policy']=='conservative-family-accounting-v6'
    assert explanation['policy']=='privacy-policy-obligations-v2' and explanation['validated_metadata_records']==4
    assert all(explanation[k] is False for k in ['auth_history_policy_resolved','historical_auth_authority_proven',
        'metadata_history_policy_resolved','historical_metadata_authority_proven','can_confirm_cleanup','erasure_complete','request_fulfilled'])
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_actual_quota_rollover_preserves_full_revision_chain_without_refund(world,complete_publication):
    p=configured(prepared(world,complete_publication));request=p[4];initial_minute=world[2].value//60000
    world[2].value=(initial_minute+1)*60000
    p[1].cancel(world[5],ident=request['id'],confirmed_scope_sha256=request['scope_sha256'],
        expected_request_version=request['state_version'],expected_gate_version=request['gate_version'],
        expected_control_version=request['control_version'],no_erasure_acknowledged=True,idempotency_key='native-v6-rollover-cancel')
    context=p[1].context(world[5])
    current=p[1].create(world[5],inspection_ids=(p[5],),expected_gate_version=context['gate_version'],
        expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='native-v6-rollover-create')
    p=(*p[:4],current,p[5]);before=inventory(world[1]);result=private(p)
    quota=next(row for row in before if row.key.resource.startswith('metadata-owner-quota#'))
    assert quota.revision==3 and quota.data=={'minute':initial_minute+1,'count':2}
    assert len(result.corpus.metadata_history.records)==9 and result.corpus.metadata_history.historical_dependencies_unavailable>0
    assert result.corpus.metadata_history.policy_resolved is False and result.corpus.metadata_history.can_confirm_cleanup is False
    assert inventory(world[1])==before and p[3].wait_for_drain(0)


def test_actual_post_derivation_source_change_is_held_before_owner_delivery(world,complete_publication,monkeypatch):
    p=configured(prepared(world,complete_publication));original=p[2].read_metadata_accounting;changed=[]
    def alter(**kwargs):
        result=original(**kwargs)
        key=Key('state','unknown-metadata-source#'+str(uuid4()))
        world[1].transact((Write(key,None,{'synthetic':True}),));changed.append(key)
        return result
    monkeypatch.setattr(p[2],'read_metadata_accounting',alter)
    with pytest.raises(HeldCorpusHeld):read(p,world[5],True)
    assert len(changed)==1 and world[1].snapshot(tuple(changed))[changed[0]] is not None
    assert p[3].wait_for_drain(0)
