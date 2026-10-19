"""Strict handoff intent and finite resource policy; no participant evidence."""
from dataclasses import replace
import pytest
from pydantic import ValidationError
from proofpack.stations.handoffs import HandoffLimits, HandoffRequest, HandoffResponse


def limits():return HandoffLimits(4,3600000,60,5000,20,30*86400000)


@pytest.mark.parametrize('name,value',[('max_requests',0),('max_requests',17),('max_requests',True),('lifetime_ms',999),
    ('lifetime_ms',3600001),('reads_per_minute',121),('read_window_ms',5001),('page_size',21),('metadata_retention_ms',30*86400000+1)])
def test_invalid_or_unbounded_resource_policy_is_rejected(name,value):
    with pytest.raises(ValueError):replace(limits(),**{name:value})


def test_request_lifetime_cannot_outlive_its_metadata_retention():
    with pytest.raises(ValueError):replace(limits(),metadata_retention_ms=1000)


@pytest.mark.parametrize('patch',[{'recipient_user_id':'not-a-uuid'},{'expected_epoch':True},{'expected_epoch':1.0},
    {'expected_epoch':2**63},
    {'reason_code':'send email to everyone'},{'stop_acknowledged':False},{'stop_acknowledged':1},{'message':'private unbounded text'}])
def test_request_needs_strict_explicit_stop_and_bounded_reason(patch):
    values={'recipient_user_id':'a0000000-0000-4000-8000-000000000001','expected_epoch':1,'reason_code':'support_needed','stop_acknowledged':True,**patch}
    with pytest.raises(ValidationError):HandoffRequest(**values)


@pytest.mark.parametrize('patch',[{'decision':'force_pass'},{'request_sha256':'invalid'},{'expected_inspection_version':True},
    {'expected_inspection_version':2**63},
    {'acknowledge_no_capture_transfer':False},{'acknowledge_no_capture_transfer':1}])
def test_response_cannot_assert_kit_or_capture_authority(patch):
    with pytest.raises(ValidationError):HandoffResponse(**{'decision':'accepted','request_sha256':'a'*64,'expected_inspection_version':2,
        'acknowledge_no_capture_transfer':True,**patch})
