"""Current owner policy explanations over genuine writers in an isolated model."""
from copy import deepcopy
from dataclasses import replace
import pytest
from test_owner_accounting_review import world,no_sdk
from test_owner_auth_review_host import bounds
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
from proofpack.evidence.auth_history import FAMILIES
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import StoreConflict
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits,GATE,REGISTRY
from proofpack.evidence.held_corpus import HeldCorpusReader
from proofpack.runtime.ownership import ResourceOwner
from test_access_context import complete
from test_capture_lineage import uid
from test_corpus_accounting import LIMITS
from proofpack.evidence.inventory import _encoded
from proofpack.auth.policy import Denied

def configured(monkeypatch):
    previous,_,repo,data,cookie=complete(monkeypatch)
    access=previous.admission.runtime.access;runtime=previous.admission.runtime
    # The copied capture closes at100; its creation at10 must precede review.
    # Original login remains live until400. Pin this clock before owner creation.
    access.clock_ms=lambda:100
    # Replace only this new isolated model's pre-created hold. Keep genuine auth,
    # capture and runtime writers mutually consistent; no production-state reset.
    del data[GATE],data[REGISTRY]
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(8,20000),clock_ms=access.now)
    admission.initialize('a'*64);owner=ResourceOwner();actor=access._resolve_key(cookie)
    requests=OwnerMetadataRequests(access,admission,owner,limits=OwnerMetadataLimits(10,20,100,20000),tick_ns=previous.tick)
    context=requests.context(actor)
    original=requests.create(actor,inspection_ids=(uid(1),),expected_gate_version=context['gate_version'],
        expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='policy-owner-create')
    reader=HeldCorpusReader(admission,owner,inventory_limits=previous.inventory_limits,limits=previous.limits,tick=previous.tick)
    service=OwnerMetadataReview(requests,reader,accounting_limits=LIMITS,
        max_response_bytes=8192,auth_review=bounds())
    return service,requests,reader,actor,repo,data,None,original,owner

def read(w,**changes):
    return w[0].read_policy_obligations(w[3],ident=w[7]['id'],**(dict(
        expected_request_version=w[7]['state_version'],expected_gate_version=w[7]['gate_version'],
        expected_control_version=w[7]['control_version'])|changes))

def test_genuine_model_counts_are_minimized_and_cannot_resolve_business_policy(monkeypatch):
    w=configured(monkeypatch);before=deepcopy(w[5]);result=read(w)
    assert result['policy']=='auth-policy-obligations-v1'
    assert result['accounting_policy']=='conservative-family-accounting-v5'
    assert set(result['family_counts'])==FAMILIES
    assert 0<sum(result['family_counts'].values())==result['validated_auth_records']<=result['source_records']
    assert result['source_records']==len(before)
    assert result['next_step']=='OWNER_D11_POLICY_DECISION_REQUIRED'
    assert result['historical'] is result['read_only'] is True
    assert all(result[k] is False for k in ['auth_history_policy_resolved','historical_auth_authority_proven','can_confirm_cleanup','erasure_complete','request_fulfilled'])
    assert w[5]==before and w[-1].wait_for_drain(0)
    assert not any(x in repr(result) for x in ['cookie#','session#','member#','example.invalid','family_digests','PRIVATE-PAYLOAD'])

@pytest.mark.parametrize('field',['expected_request_version','expected_gate_version','expected_control_version'])
def test_stale_policy_review_denied_before_private_inventory(monkeypatch,field):
    w=configured(monkeypatch)
    monkeypatch.setattr(w[2],'read_auth_accounting',lambda **k:pytest.fail('stale policy review reached inventory'))
    with pytest.raises(StoreConflict):read(w,**{field:999})
    assert w[-1].wait_for_drain(0)

def test_unconfigured_auth_history_cannot_silently_use_v1(monkeypatch):
    w=world(monkeypatch)
    monkeypatch.setattr(w[2],'read_accounting',lambda **k:pytest.fail('v1 fallback'))
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[-1].wait_for_drain(0)

@pytest.mark.parametrize('one_below',[False,True])
def test_policy_output_obeys_original_exact_response_byte_budget(monkeypatch,one_below):
    w=configured(monkeypatch);value=read(w);size=len(_encoded(value))
    s=OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=size-int(one_below),auth_review=bounds())
    if one_below:
        with pytest.raises(HeldCorpusHeld):read((s,*w[1:]))
    else:assert read((s,*w[1:]))==value
    assert w[-1].wait_for_drain(0)

@pytest.mark.parametrize('one_below',[False,True])
def test_category_projection_is_charged_to_original_auth_work_allowance(monkeypatch,one_below):
    w=configured(monkeypatch);captured=[];original=w[2].read_auth_accounting
    def observe(**kwargs):
        result=original(**kwargs);captured.append(result.corpus.auth_history);return result
    monkeypatch.setattr(w[2],'read_auth_accounting',observe);read(w)
    auth=captured[-1];maximum=auth.work+len(auth.records)+len(FAMILIES)-int(one_below)
    group=replace(bounds(),auth=replace(bounds().auth,max_work=maximum))
    s=OwnerMetadataReview(w[1],w[2],accounting_limits=LIMITS,max_response_bytes=8192,auth_review=group)
    if one_below:
        with pytest.raises(HeldCorpusHeld):read((s,*w[1:]))
    else:assert read((s,*w[1:]))['next_step']=='OWNER_D11_POLICY_DECISION_REQUIRED'
    assert w[-1].wait_for_drain(0)

def test_final_source_mutation_cannot_deliver_a_policy_snapshot(monkeypatch):
    w=configured(monkeypatch);original=w[2].read_auth_accounting
    def change(**kwargs):
        result=original(**kwargs);row=w[5][w[3].member.key]
        w[5][row.key]=replace(row,revision=row.revision+1,data={**row.data,'enabled':False})
        return result
    monkeypatch.setattr(w[2],'read_auth_accounting',change)
    with pytest.raises(Denied):read(w)
    assert w[-1].wait_for_drain(0)
