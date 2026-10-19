"""Private historical metadata parsing never restores media read authority."""
from copy import deepcopy
from dataclasses import replace
import pytest
from proofpack.evidence.repository import Key,Row,ErasureMarker,StoreUnavailable
from proofpack.evidence.originals import original_asset_id,validate_original_source
from proofpack.vision.worker_result import WorkerResult
from proofpack.verifier.core import Finding

OBS='11111111-1111-4111-8111-111111111111'
JOB='22222222-2222-4222-8222-222222222222'

def records(crop_state='active',original_state='active'):
    result=WorkerResult(candidates=(),findings=(Finding.SATISFIED,),reason_codes=(),quality_ok=True,
        unknown_regions=0,scene_generation=1,scene_changed=False,source_sha256='a'*64,calibration_hash='b'*64)
    oid=original_asset_id(OBS)
    ob=Row(Key('state','observation#'+OBS),3,{'id':OBS,'status':'completed','retain_original_frame':True,
        'asset_id':OBS,'original_asset_id':oid,'source_sha256':'a'*64,'original_evidence_sha256':'a'*64,
        'evidence_sha256':'c'*64,'context_sha256':'d'*64,'byte_length':200,'content_type':'image/png',
        'accepted_at_ms':10,'result_json':result.model_dump_json()})
    common={'status':'committed','read_denied':False,'purpose_id':JOB,'data_origin':'SYNTHETIC',
        'input_sha256':'a'*64,'context_sha256':'d'*64,'observation_id':OBS,'expires_at_ms':100}
    crop=Row(Key('state','asset#'+OBS),2,{**common,'id':OBS,'derivation':'rectified_roi_jpeg','sha256':'c'*64})
    original=Row(Key('state','asset#'+oid),2,{**common,'id':oid,'derivation':'original_transmitted_frame',
        'sha256':'a'*64,'calibration_sha256':'b'*64,'byte_length':200,'content_type':'image/png'})
    def state(row,kind):
        data=deepcopy(row.data)
        if kind!='active':data.update(read_denied=True,deletion_job_id=JOB,denied_at_ms=20)
        if kind=='deleted':data.update(status='deleted',live_versions_checked_at_ms=30)
        return replace(row,data=data)
    return state(original,original_state),ob,state(crop,crop_state)

@pytest.mark.parametrize('crop_state',['active','denied','deleted'])
@pytest.mark.parametrize('original_state',['active','denied','deleted'])
def test_valid_historical_media_metadata_preserves_all_supported_lifecycle_combinations(crop_state,original_state):
    original,ob,crop=records(crop_state,original_state);before=deepcopy((original,ob,crop))
    result=validate_original_source(original,ob,crop,metadata_only=True)
    assert result.source_sha256=='a'*64 and (original,ob,crop)==before

@pytest.mark.parametrize('crop_state',['denied','deleted'])
def test_metadata_mode_does_not_change_default_crop_read_rejection(crop_state):
    original,ob,crop=records(crop_state)
    with pytest.raises(StoreUnavailable):validate_original_source(original,ob,crop)
    assert validate_original_source(original,ob,crop,metadata_only=True).calibration_hash=='b'*64

@pytest.mark.parametrize('mode',[None,0,1,'true',[],{}])
def test_private_mode_requires_exact_boolean(mode):
    with pytest.raises(ValueError):validate_original_source(*records(),metadata_only=mode)

def test_ordinary_intact_source_keeps_default_behavior():
    assert validate_original_source(*records()).source_sha256=='a'*64

@pytest.mark.parametrize('which',['original','crop','observation'])
@pytest.mark.parametrize('fault',['key','revision_zero','revision_bool','revision_overflow'])
def test_private_metadata_requires_exact_stored_identity_and_revision(which,fault):
    rows=list(records());i={'original':0,'observation':1,'crop':2}[which];row=rows[i]
    rows[i]=replace(row,key=Key('events',row.key.resource)) if fault=='key' else replace(row,revision={'revision_zero':0,'revision_bool':True,'revision_overflow':2**63}[fault])
    with pytest.raises(StoreUnavailable):validate_original_source(*rows,metadata_only=True)

@pytest.mark.parametrize('which',[0,2])
@pytest.mark.parametrize('fault',[
    {'status':'unknown'},{'read_denied':1},{'status':'deleted','read_denied':False},
    {'deletion_job_id':JOB},{'denied_at_ms':20},{'live_versions_checked_at_ms':30},
    {'read_denied':True},{'read_denied':True,'deletion_job_id':'bad','denied_at_ms':20},
    {'read_denied':True,'deletion_job_id':JOB,'denied_at_ms':True},
    {'read_denied':True,'deletion_job_id':JOB,'denied_at_ms':2**63},
    {'status':'deleted','read_denied':True,'deletion_job_id':JOB,'denied_at_ms':20},
    {'status':'deleted','read_denied':True,'deletion_job_id':JOB,'denied_at_ms':20,'live_versions_checked_at_ms':19},
    {'status':'committed','read_denied':True,'deletion_job_id':JOB,'denied_at_ms':20,'live_versions_checked_at_ms':30},
])
def test_private_mode_holds_malformed_or_contradictory_lifecycle(which,fault):
    rows=list(records());rows[which]=replace(rows[which],data={**rows[which].data,**fault})
    with pytest.raises(StoreUnavailable):validate_original_source(*rows,metadata_only=True)

@pytest.mark.parametrize('which,field,value',[(0,'purpose_id','foreign'),(0,'sha256','e'*64),
    (0,'calibration_sha256','e'*64),(0,'content_type','text/plain'),(0,'byte_length',201),
    (0,'expires_at_ms',8*86400000),(2,'context_sha256','e'*64),(2,'sha256','e'*64),
    (1,'retain_original_frame',False),(1,'result_json','{}'),(1,'status','processing')])
def test_denied_metadata_keeps_original_completed_provenance_guards(which,field,value):
    rows=list(records('deleted','deleted'));rows[which]=replace(rows[which],data={**rows[which].data,field:value})
    with pytest.raises(StoreUnavailable):validate_original_source(*rows,metadata_only=True)

@pytest.mark.parametrize('which',[0,1,2])
@pytest.mark.parametrize('missing',['absent','erased'])
def test_missing_or_scrubbed_records_require_separate_reconciliation(which,missing):
    rows=list(records());row=rows[which]
    rows[which]=None if missing=='absent' else ErasureMarker(row.key,row.revision+1,'a'*64,'b'*64)
    with pytest.raises(StoreUnavailable):validate_original_source(*rows,metadata_only=True)
