"""Geometry, image/source binding and legacy abstention are independent checks."""
from copy import deepcopy
import json
from types import SimpleNamespace
import pytest
from pydantic import ValidationError
from proofpack.vision.worker_result import WorkerResult
from proofpack.vision.correction import basis, verified_reference, target_indices, validate_measurement
from proofpack.recipes.models import Recipe


def result():
    return WorkerResult.model_validate_json(json.dumps({'candidates':[{'part_class':None,'box':[10,20,30,40],
        'dimension_interval_mm':[7.,9.],'correction_reason':'overlap'}], 'findings':['UNOBSERVABLE'],
        'reason_codes':['unknown_or_overlap','overlap'],'quality_ok':True,'unknown_regions':1,
        'scene_generation':3,'scene_changed':True,'source_sha256':'a'*64,'calibration_hash':'b'*64,'rectified_size':[600,300]}))


def records():
    text=result().model_dump_json(); value,signature=basis(text,'c'*64)
    asset={'id':'crop','derivation':'rectified_roi_jpeg','observation_id':'observation','sha256':'c'*64,
        'input_sha256':'a'*64,'correction_basis_sha256':signature}
    observation={'id':'observation','result_json':text,'source_sha256':'a'*64,'correction_basis_sha256':signature}
    return asset,observation,value


def test_exact_geometry_and_target_are_bound_to_the_retained_crop():
    asset,observation,expected=records(); value=verified_reference(asset,observation)
    assert value=={**expected,'observation_id':'observation'}
    assert value['coordinate_space']=='rectified_crop_v1' and value['regions'][0]['box']==[10,20,30,40]
    assert target_indices(value,'SEPARATE_REGION')==[0]
    assert target_indices(value,'PLACE_FLAT')==[] and target_indices(value,'REVIEW')==[]


@pytest.mark.parametrize('change',['result','crop','source','asset_basis','observation_basis','missing_asset','missing_observation','missing_both'])
def test_modified_or_incomplete_reference_never_emits_geometry(change):
    asset,observation,_=records()
    if change=='result':
        raw=json.loads(observation['result_json']);raw['candidates'][0]['box'][0]+=1
        observation['result_json']=json.dumps(raw)
    elif change=='crop':asset['sha256']='d'*64
    elif change=='source':observation['source_sha256']='d'*64
    elif change=='asset_basis':asset['correction_basis_sha256']='d'*64
    elif change=='observation_basis':observation['correction_basis_sha256']='d'*64
    else:
        if change in {'missing_asset','missing_both'}:asset.pop('correction_basis_sha256')
        if change in {'missing_observation','missing_both'}:observation.pop('correction_basis_sha256')
    with pytest.raises(ValueError):verified_reference(asset,observation)


def test_crop_geometry_never_leaks_onto_an_original_image_or_legacy_record():
    asset,observation,_=records();asset['derivation']='original_transmitted_frame'
    with pytest.raises(ValueError):verified_reference(asset,observation)
    asset.pop('correction_basis_sha256');assert verified_reference(asset,observation) is None
    asset,observation,_=records();asset.pop('correction_basis_sha256');observation.pop('correction_basis_sha256')
    raw=json.loads(observation['result_json']);raw['candidates'][0].pop('correction_reason');raw.pop('rectified_size')
    observation['result_json']=json.dumps(raw)
    assert verified_reference(asset,observation) is None


@pytest.mark.parametrize('change',['outside','missing_size','wrong_reason','wrong_class','positive_finding'])
def test_untrusted_worker_target_contract_stays_closed(change):
    raw=json.loads(result().model_dump_json())
    if change=='outside':raw['candidates'][0]['box']=[599,20,30,40]
    elif change=='missing_size':raw.pop('rectified_size')
    elif change=='wrong_reason':raw['reason_codes']=[]
    elif change=='wrong_class':raw['candidates'][0]['part_class']='bolt'
    else:raw['findings']=['SATISFIED']
    if change!='positive_finding':
        with pytest.raises(ValidationError):WorkerResult.model_validate_json(json.dumps(raw))
    else:
        from test_measured_correction_cues import recipe
        with pytest.raises(ValueError):validate_measurement(WorkerResult.model_validate_json(json.dumps(raw)),recipe('washer'),SimpleNamespace(output_width=600,output_height=300))


def test_worker_cannot_omit_required_flat_projection_and_assert_satisfaction():
    from test_measured_correction_cues import recipe
    raw=json.loads(result().model_dump_json())
    raw['candidates'][0]={'part_class':'bolt','box':[10,20,70,20],'dimension_interval_mm':[10.,15.]}
    raw['reason_codes']=[];raw['unknown_regions']=0;raw['findings']=['SATISFIED'];raw.pop('rectified_size')
    with pytest.raises(ValueError):
        validate_measurement(WorkerResult.model_validate_json(json.dumps(raw)),recipe('bolt',flat=(4.5,7.5)),SimpleNamespace(output_width=600,output_height=300))
