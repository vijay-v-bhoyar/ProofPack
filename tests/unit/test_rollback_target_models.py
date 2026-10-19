import pytest
from pydantic import ValidationError
from proofpack.planner.rollback import RollbackTarget


BASE={'active_version':2,'activation_id':'11111111-1111-4111-8111-111111111111',
    'predecessor_activation_id':'22222222-2222-4222-8222-222222222222'}


def test_exact_rollback_target_is_closed_and_roundtrips():
    assert RollbackTarget.model_validate(BASE).model_dump(mode='json')==BASE


@pytest.mark.parametrize('patch',[{'active_version':0},{'active_version':True},{'active_version':'2'},
    {'active_version':9007199254740992},{'activation_id':'untrusted'},{'predecessor_activation_id':None},
    {'allow_stale':True},{'consumed':True}])
def test_rollback_target_rejects_invalid_or_client_authority_fields(patch):
    with pytest.raises(ValidationError):RollbackTarget.model_validate({**BASE,**patch})


@pytest.mark.parametrize('kind',['evaluation','qualification'])
def test_absent_rollback_intent_preserves_previous_canonical_request_and_hash(kind):
    from proofpack.calibrations.dependencies import canonical,digest
    from proofpack.review.evaluation_models import EvaluationRequest
    from proofpack.review.policy_qualification import QualificationRequest
    shared={'policy_id':BASE['activation_id'],'policy_revision':1,'policy_state_version':1,'policy_revision_sha256':'a'*64}
    if kind=='evaluation':
        model=EvaluationRequest
        old={**shared,'runner':'decision_replay_v1','manifest_id':BASE['predecessor_activation_id'],
            'manifest_sha256':'b'*64,'historical_diagnostic_acknowledged':True,'frozen_holdout_acknowledged':False}
    else:
        model=QualificationRequest
        old={**shared,'mode':'installed_default','preparation_id':None,'preparation_state_version':None,
            'preparation_report_sha256':None,'synthetic_demo_acknowledged':True}
    for body in (old,{**old,'rollback_target':None}):
        parsed=model.model_validate(body)
        assert canonical(parsed.model_dump(mode='json'))==canonical(old)
        assert digest(parsed.model_dump(mode='json'))==digest(old)
    targeted=model.model_validate({**old,'rollback_target':BASE})
    assert targeted.model_dump(mode='json')['rollback_target']==BASE
    assert digest(targeted.model_dump(mode='json'))!=digest(old)
