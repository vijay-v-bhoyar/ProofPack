"""Original retention is an explicit independent, strictly typed notice choice."""
from uuid import uuid4

import pytest
from pydantic import ValidationError

from proofpack.evidence.originals import ORIGINAL_NOTICE_SHA256,original_asset_id
from proofpack.evidence.purposes import PurposeRequest


def purpose(**changes):
    return PurposeRequest(notice_version='test-v1',notice_sha256='a'*64,
        source_permission_reference='source-1',operational_use_acknowledged=True,expires_at_ms=10000,**changes)


def test_retaining_an_original_requires_its_exact_separate_notice():
    assert purpose().original_capture_retention_acknowledged is False
    assert purpose().original_capture_notice_sha256 is None
    assert purpose(original_capture_retention_acknowledged=True,original_capture_notice_sha256=ORIGINAL_NOTICE_SHA256).original_capture_retention_acknowledged is True


@pytest.mark.parametrize('changes',[
    {'original_capture_retention_acknowledged':True},
    {'original_capture_retention_acknowledged':True,'original_capture_notice_sha256':'f'*64},
    {'original_capture_notice_sha256':ORIGINAL_NOTICE_SHA256},
    {'original_capture_retention_acknowledged':1},
    {'original_capture_retention_acknowledged':'true'},
    {'original_capture_retention_acknowledged':None},
])
def test_ambiguous_or_unacknowledged_original_scope_is_rejected(changes):
    with pytest.raises(ValidationError):purpose(**changes)


def test_original_identity_is_stable_and_distinct_from_crop_and_other_observations():
    first=str(uuid4());other=str(uuid4())
    assert original_asset_id(first)==original_asset_id(first)
    assert original_asset_id(first)!=first
    assert original_asset_id(first)!=original_asset_id(other)
    with pytest.raises(ValueError):original_asset_id('not-an-observation')
