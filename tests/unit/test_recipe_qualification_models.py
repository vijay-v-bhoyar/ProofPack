import copy
import json
import pytest
from pydantic import ValidationError
from proofpack.recipes.qualification_models import RecipeQualificationRequest


def body():
    return {'cases':[{'asset_id':f'10000000-0000-4000-8000-{i:012d}','kind':kind,'expected_findings':[finding],'expected_counts':[count]}
        for i,(kind,finding,count) in enumerate([('complete','SATISFIED',1),('incorrect','VIOLATED',0),('challenge','UNOBSERVABLE',1)],1)]}


def test_declared_case_contract_retains_uncertain_truth_without_certification():
    value=RecipeQualificationRequest.model_validate_json(json.dumps(body()))
    assert len(value.cases)==3 and value.cases[-1].expected_counts==(1,)


@pytest.mark.parametrize('fault',['short','long','duplicate','flag','boolean_count','negative','large','bad_finding','wrong_complete','missing_kind','wrong_order_length'])
def test_invalid_or_self_certified_case_batches_are_rejected(fault):
    value=copy.deepcopy(body())
    if fault=='short':value['cases'].pop()
    elif fault=='long':value['cases']*=3
    elif fault=='duplicate':value['cases'][1]['asset_id']=value['cases'][0]['asset_id']
    elif fault=='flag':value['passed']=True
    elif fault=='boolean_count':value['cases'][0]['expected_counts']=[True]
    elif fault=='negative':value['cases'][0]['expected_counts']=[-1]
    elif fault=='large':value['cases'][0]['expected_counts']=[31]
    elif fault=='bad_finding':value['cases'][0]['expected_findings']=['PASSED_CURRENT']
    elif fault=='wrong_complete':value['cases'][0]['expected_findings']=['VIOLATED']
    elif fault=='missing_kind':value['cases'][2]['kind']='incorrect';value['cases'][2]['expected_findings']=['VIOLATED']
    else:value['cases'][0]['expected_counts']=[1,2]
    with pytest.raises(ValidationError):RecipeQualificationRequest.model_validate_json(json.dumps(value))
