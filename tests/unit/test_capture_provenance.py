"""Pure canonical context compatibility; no qualification or user evidence."""
from decimal import Decimal
import json
import pytest
from proofpack.capture.provenance import inspection_context,POLICY_FIELDS
from proofpack.calibrations.dependencies import digest


def context():
    return {'id':'inspection','station_id':'station','station_epoch':Decimal(1),'recipe_id':'recipe','recipe_active_version':Decimal(1),
        'calibration_state_version':Decimal(1),'policy_state_version':Decimal(1),'runtime_epoch':Decimal(1),
        'runtime_instance_id':'instance','control_version':Decimal(3),'data_epoch':Decimal(1),
        'originating_session_id':'session','originating_access_version':Decimal(1)}


def provenance():
    return {'policy_id':'00000000-0000-4000-8000-000000000001','policy_revision':Decimal(1),'policy_revision_sha256':'a'*64,
        'behavior_sha256':'b'*64,'activation_id':'00000000-0000-4000-8000-000000000002','activation_sha256':'c'*64,
        'qualification_id':'00000000-0000-4000-8000-000000000003','qualification_report_sha256':'d'*64}


def test_legacy_history_keeps_original_digest_without_acquiring_live_provenance():
    data=context();expected={k:int(v) if isinstance(v,Decimal) else v for k,v in data.items()};expected['sequence']=1
    result=inspection_context(data,Decimal(1),{})
    assert digest(result)==digest(expected) and 'policy_provenance' not in result


def test_new_context_binds_exact_policy_and_is_plain_json_after_decimal_persistence():
    data={**context(),'policy_provenance':provenance()}
    result=inspection_context(data,Decimal(1),{'policy_provenance':provenance()})
    assert json.loads(json.dumps(result))==result and type(result['policy_provenance']['policy_revision']) is int
    assert set(result['policy_provenance'])==set(POLICY_FIELDS)
    other={**data,'policy_provenance':{**provenance(),'activation_sha256':'e'*64}}
    assert digest(inspection_context(other,1))!=digest(result)


@pytest.mark.parametrize('change',['work_missing','observation_missing','different','partial','extra','boolean_revision','bad_hash','bad_id'])
def test_partial_changed_or_malformed_policy_provenance_is_rejected(change):
    data={**context(),'policy_provenance':provenance()};observation={'policy_provenance':provenance()}
    if change=='work_missing':data.pop('policy_provenance')
    elif change=='observation_missing':observation.pop('policy_provenance')
    elif change=='different':observation['policy_provenance']['activation_sha256']='e'*64
    elif change=='partial':data['policy_provenance'].pop('activation_id')
    elif change=='extra':data['policy_provenance']['unapproved']='value'
    elif change=='boolean_revision':data['policy_provenance']['policy_revision']=True
    elif change=='bad_hash':data['policy_provenance']['activation_sha256']='invalid'
    else:data['policy_provenance']['activation_id']='invalid'
    with pytest.raises((ValueError,KeyError)):inspection_context(data,1,observation)
