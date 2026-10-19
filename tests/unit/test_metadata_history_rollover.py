"""Minute boundaries with genuine auth/request/quota writers in an isolated model."""
from copy import deepcopy
import pytest
from test_access_context import complete
from test_owner_auth_review_host import bounds
from test_owner_metadata_v6 import read
from test_owner_metadata import cancel,create,no_sdk
from test_metadata_history_consumption import limits
from test_capture_lineage import uid
from test_corpus_accounting import LIMITS
from proofpack.auth.service import IdentityProof
from proofpack.auth.policy import Denied
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits,AdmissionHeld,GATE,REGISTRY
from proofpack.evidence.held_corpus import HeldCorpusReader
from proofpack.runtime.ownership import ResourceOwner


def configured(monkeypatch,start):
    previous,_,repo,data,_=complete(monkeypatch);access=previous.admission.runtime.access;runtime=previous.admission.runtime
    clock=[start];access.clock_ms=lambda:clock[0]
    # Genuine fresh login extends the short original synthetic provider proof;
    # no session payload or expiry is patched to bypass authentication.
    credentials=access.login(IdentityProof(access.config.issuer,'synthetic-origin','origin@example.test',
        True,True,start,start+3_600_000,'Synthetic owner'))
    actor=access.resolve(credentials.cookie)
    del data[GATE],data[REGISTRY]  # Only the known pre-created hold in this isolated new model.
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(8,20000),clock_ms=access.now);admission.initialize('a'*64)
    owner=ResourceOwner();requests=OwnerMetadataRequests(access,admission,owner,
        limits=OwnerMetadataLimits(10,20,100,20000),tick_ns=previous.tick)
    context=requests.context(actor)
    intent=dict(inspection_ids=(uid(1),),expected_gate_version=context['gate_version'],
        expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='rollover-original-create')
    original=requests.create(actor,**intent)
    reader=HeldCorpusReader(admission,owner,inventory_limits=previous.inventory_limits,limits=previous.limits,tick=previous.tick)
    service=OwnerMetadataReview(requests,reader,accounting_limits=LIMITS,max_response_bytes=8192,
        auth_review=bounds(),metadata_review=limits())
    return (service,requests,reader,actor,repo,data,None,original,owner),clock,intent


@pytest.mark.parametrize('start,next_time,expected_count',[(59999,60000,2),(60000,60001,3),(59999,120001,2)])
def test_exact_boundary_same_minute_and_skipped_minute_preserve_history(monkeypatch,start,next_time,expected_count):
    w,clock,_=configured(monkeypatch,start);clock[0]=next_time
    cancel(w[1],w[3],w[7]);current=create(w[1],w[3],idempotency_key='rollover-next-request')
    w=(*w[:7],current,w[8]);before=deepcopy(w[5]);result=read(w,True)
    quota=next(row for key,row in before.items() if key.resource.startswith('metadata-owner-quota#'))
    assert quota.revision==3 and quota.data=={'minute':next_time//60000,'count':expected_count}
    assert result['validated_metadata_records']==9 and result['metadata_historical_dependencies_unavailable']>0
    assert result['metadata_history_policy_resolved'] is False and not result['can_confirm_cleanup']
    assert w[5]==before and w[-1].wait_for_drain(0)


def test_original_creation_retry_after_rollover_cannot_refund_or_reopen(monkeypatch):
    w,clock,intent=configured(monkeypatch,59999);clock[0]=60000
    cancel(w[1],w[3],w[7]);create(w[1],w[3],idempotency_key='rollover-new-held')
    before=deepcopy(w[5]);replayed=w[1].create(w[3],**intent)
    assert replayed['id']==w[7]['id'] and replayed['status']=='cancelled' and replayed['replayed']
    assert not replayed['current_hold'] and w[5]==before and w[-1].wait_for_drain(0)


def test_backward_wall_clock_does_not_reset_quota_or_cancel_current_hold(monkeypatch):
    # Keep the genuine login older than the reversed clock, so this exercises
    # the maintenance/quota clock guard rather than the prior session guard.
    w,clock,_=configured(monkeypatch,59998);clock[0]=60000
    cancel(w[1],w[3],w[7],idempotency_key='backward-prior-cancel')
    current=create(w[1],w[3],idempotency_key='backward-current-held')
    w=(*w[:7],current,w[8]);clock[0]=59999;before=deepcopy(w[5])
    with pytest.raises(AdmissionHeld):cancel(w[1],w[3],w[7])
    assert w[5]==before and w[-1].wait_for_drain(0)


def test_clock_before_genuine_login_keeps_original_authentication_denial(monkeypatch):
    w,clock,_=configured(monkeypatch,60000);clock[0]=59999;before=deepcopy(w[5])
    with pytest.raises(Denied,match='current session required'):cancel(w[1],w[3],w[7])
    assert w[5]==before and w[-1].wait_for_drain(0)
