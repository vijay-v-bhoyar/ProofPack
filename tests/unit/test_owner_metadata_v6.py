"""Current owner/MFA/version boundary over genuine private v6 model history."""
from copy import deepcopy
from dataclasses import replace
import pytest
from test_owner_policy_obligations import configured as previous,no_sdk
from test_owner_auth_review_host import bounds
from test_metadata_history_consumption import limits
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
from proofpack.evidence.owner_metadata_http import MetadataReviewResult,MetadataPolicyObligationsResult
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import StoreConflict
from proofpack.evidence.inventory import _encoded


def configured(monkeypatch,**changes):
    w=previous(monkeypatch)
    service=OwnerMetadataReview(w[1],w[2],**(dict(accounting_limits=w[0].accounting_limits,
        max_response_bytes=8192,auth_review=bounds(),metadata_review=limits())|changes))
    return (service,*w[1:])


def read(w,explain=False,**changes):
    method=w[0].read_policy_obligations if explain else w[0].read
    return method(w[3],ident=w[7]['id'],**(dict(expected_request_version=w[7]['state_version'],
        expected_gate_version=w[7]['gate_version'],expected_control_version=w[7]['control_version'])|changes))


@pytest.mark.parametrize('explain',[False,True])
def test_genuine_v6_owner_read_is_minimized_bound_and_non_authorizing(monkeypatch,explain):
    w=configured(monkeypatch);before=deepcopy(w[5]);value=read(w,explain)
    model=MetadataPolicyObligationsResult if explain else MetadataReviewResult
    assert model.model_validate(value).model_dump()==value
    assert value['accounting_policy']=='conservative-family-accounting-v6'
    assert value['id']==w[7]['id'] and value['scope_sha256']==w[7]['scope_sha256']
    assert all(value[k] is False for k in ['auth_history_policy_resolved','historical_auth_authority_proven',
        'metadata_history_policy_resolved','historical_metadata_authority_proven','can_confirm_cleanup','erasure_complete','request_fulfilled'])
    if explain:
        assert value['policy']=='privacy-policy-obligations-v2' and value['validated_metadata_records']==4
        assert sum(value['metadata_family_counts'].values())==4
        assert value['validated_auth_records']+4<=value['source_records']
        assert value['next_step']=='OWNER_D11_POLICY_DECISION_REQUIRED'
    assert w[5]==before and w[-1].wait_for_drain(0)
    assert not any(s in repr(value) for s in ['idempotency#','metadata-request#','metadata-owner-quota#','cookie#','PRIVATE-PAYLOAD'])


@pytest.mark.parametrize('field',['expected_request_version','expected_gate_version','expected_control_version'])
def test_stale_owner_read_stops_before_metadata_inventory(monkeypatch,field):
    w=configured(monkeypatch)
    monkeypatch.setattr(w[2],'read_metadata_accounting',lambda **k:pytest.fail('stale read reached inventory'))
    with pytest.raises(StoreConflict):read(w,True,**{field:100})
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['auth','scope','quota'])
def test_direct_configuration_requires_auth_and_exact_original_writer_profile(monkeypatch,fault):
    changes=({'auth_review':None} if fault=='auth' else
        {'metadata_review':replace(limits(),**({'max_inspections':9} if fault=='scope' else {'writes_per_minute':19}))})
    with pytest.raises(ValueError):configured(monkeypatch,**changes)


def test_metadata_projection_reserves_original_work_budget(monkeypatch):
    w=configured(monkeypatch);captured=[];original=w[2].read_metadata_accounting
    def observe(**k):
        result=original(**k);captured.append(result.corpus.metadata_history);return result
    monkeypatch.setattr(w[2],'read_metadata_accounting',observe)
    expected=read(w,True);history=captured[-1];exact=history.work+len(history.records)+4
    for budget,accept in [(exact,True),(exact-1,False)]:
        service=OwnerMetadataReview(w[1],w[2],accounting_limits=w[0].accounting_limits,max_response_bytes=8192,
            auth_review=bounds(),metadata_review=replace(limits(),max_work=budget))
        current=(service,*w[1:])
        if accept:assert read(current,True)==expected
        else:
            with pytest.raises(HeldCorpusHeld):read(current,True)
    assert w[-1].wait_for_drain(0)


def test_original_response_byte_bound_is_not_extended(monkeypatch):
    w=configured(monkeypatch);value=read(w,True);size=len(_encoded(value))
    for capacity,accept in [(size,True),(size-1,False)]:
        service=OwnerMetadataReview(w[1],w[2],accounting_limits=w[0].accounting_limits,max_response_bytes=capacity,
            auth_review=bounds(),metadata_review=limits())
        if accept:assert read((service,*w[1:]),True)==value
        else:
            with pytest.raises(HeldCorpusHeld):read((service,*w[1:]),True)
    assert w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['replacement','limits','policy-flag'])
def test_late_original_configuration_or_private_result_drift_holds(monkeypatch,fault):
    w=configured(monkeypatch);original=w[2].read_metadata_accounting
    def changed(**k):
        result=original(**k)
        if fault=='replacement':w[0].metadata_review=replace(w[0].metadata_review)
        elif fault=='limits':object.__setattr__(w[0].metadata_review,'max_work',w[0].metadata_review.max_work+1)
        else:object.__setattr__(result.corpus.metadata_history,'policy_resolved',True)
        return result
    monkeypatch.setattr(w[2],'read_metadata_accounting',changed)
    with pytest.raises(HeldCorpusHeld):read(w,True)
    assert w[-1].wait_for_drain(0)
