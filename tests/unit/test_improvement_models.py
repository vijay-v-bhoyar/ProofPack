from dataclasses import replace
from uuid import uuid4
import pytest
from pydantic import ValidationError
from proofpack.evidence.improvement import ImprovementConfig, ImprovementPreview, ImprovementConfirmation


@pytest.mark.parametrize('changes',[{'notice_version':''},{'notice_text':''},{'notice_text':' '*5},
    {'max_lifetime_ms':0},{'max_lifetime_ms':31536000001},{'review_ms':True},{'review_ms':60001},
    {'writes_per_minute':0},{'writes_per_minute':101}])
def test_required_separate_notice_and_bounds(changes):
    config=ImprovementConfig('test-v1','Separate optional-use notice.',60000,8,30000)
    with pytest.raises(ValueError):replace(config,**changes)


@pytest.mark.parametrize('assets',[[],['invalid'],[str(uuid4())]*2,[str(uuid4()) for _ in range(17)]])
def test_distinct_bounded_asset_ids(assets):
    import json
    with pytest.raises(ValidationError):ImprovementPreview.model_validate_json(json.dumps({'asset_ids':assets}))


@pytest.mark.parametrize('changes',[{'optional_improvement_acknowledged':1},{'limitations_acknowledged':'true'},
    {'optional_publicity':True},{'independence_verified':True},{'documented_permission_reference':'https://example.invalid/consent'},
    {'expires_at_ms':True},{'expires_at_ms':9007199254740992},{'derived_review_metadata_acknowledged':'true'}])
def test_no_coerced_acknowledgments_or_client_certification(changes):
    body=dict(preview_id=str(uuid4()),confirmed_scope_sha256='a'*64,documented_permission_reference='record-1',
        notice_version='test-v1',notice_sha256='b'*64,optional_improvement_acknowledged=True,limitations_acknowledged=True,expires_at_ms=1000)
    body.update(changes)
    with pytest.raises(ValidationError):ImprovementConfirmation(**body)
