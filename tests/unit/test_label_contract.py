"""Impossible review intents are rejected before any store or source request."""
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from proofpack.review.labels import LabelRequest,OutcomeLabels


def body():
    return {'before_observation_id':str(uuid4()),'source_context_sha256':'a'*64,'data_epoch':1,'outcome':'unresolved',
        'ground_truth_counts':[{'part_class':'washer','count':1}],'method':'synthetic_fixture','duration_ms':500,
        'independence_declared':False,'note':'Synthetic fixture check'}


@pytest.mark.parametrize('changes',[
    {'outcome':'resolved'}, {'action_id':str(uuid4())}, {'after_observation_id':str(uuid4())},
    {'ground_truth_counts':[{'part_class':'washer','count':1},{'part_class':'washer','count':2}]},
    {'ground_truth_counts':[{'part_class':'washer','count':20},{'part_class':'nut','count':20}]},
    {'independence_verified':True}, {'duration_ms':0}, {'duration_ms':3600001}, {'note':'  '}, {'note':'private\nline'},
])
def test_impossible_or_self_certifying_label_intent_is_rejected(changes):
    with pytest.raises(ValidationError):LabelRequest.model_validate_json(json.dumps({**body(),**changes}))


@pytest.mark.parametrize('bounds',[
    {'writes_per_minute':0,'max_duration_ms':1000,'review_validity_ms':1000},
    {'writes_per_minute':1,'max_duration_ms':0,'review_validity_ms':1000},
    {'writes_per_minute':1,'max_duration_ms':1000,'review_validity_ms':60001},
])
def test_missing_safe_review_bounds_cannot_configure_service(bounds):
    with pytest.raises(ValueError):OutcomeLabels(None,**bounds)
