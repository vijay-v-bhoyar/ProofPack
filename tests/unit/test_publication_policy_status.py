"""Synthetic unit probe: qualification assumed current; challenge observation integrity."""
import json
from types import SimpleNamespace as NS
from proofpack.capture.publication import ObservationPublication,asset_key
from proofpack.capture.service import observation_key
from proofpack.stations.service import inspection_key
from proofpack.evidence.repository import Key,Row

def test_current_status_rejects_observation_with_different_policy_provenance():
    iid='00000000-0000-4000-8000-000000000001';oid='00000000-0000-4000-8000-000000000002';pid='00000000-0000-4000-8000-000000000003'
    provenance={'policy_id':iid,'policy_revision':1,'policy_revision_sha256':'a'*64,'behavior_sha256':'b'*64,'activation_id':iid,'activation_sha256':'c'*64,'qualification_id':oid,'qualification_report_sha256':'d'*64}
    work=Row(inspection_key(iid),1,{'id':iid,'station_id':iid,'state':'PASSED_CURRENT','latest_observation_id':oid,'verified_sequence':1,'station_epoch':1,'runtime_instance_id':iid,'deadline_tick_ns':10000000000,'policy_state_version':1,'policy_provenance':provenance})
    result={'candidates':[],'findings':['SATISFIED'],'reason_codes':[],'quality_ok':True,'unknown_regions':0,'scene_generation':1,'scene_changed':False,'source_sha256':'a'*64,'calibration_hash':'d'*64,'evidence_jpeg_base64':None,'evidence_sha256':None}
    observation=Row(observation_key(oid),1,{'status':'completed','sequence':1,'asset_id':oid,'evidence_sha256':'b'*64,'source_sha256':'a'*64,'context_sha256':'c'*64,'accepted_at_ms':1000,'result_json':json.dumps(result),'policy_provenance':{}})
    asset=Row(asset_key(oid),1,{'id':oid,'status':'committed','read_denied':False,'sha256':'b'*64,'input_sha256':'a'*64,'context_sha256':'c'*64,'purpose_id':pid,'expires_at_ms':2000,'object_key':'synthetic/asset.jpg','object_version':'v1','byte_length':10,'content_type':'image/jpeg'})
    purpose=Row(Key('state','purpose#'+pid),1,{})
    rows={r.key:r for r in (work,observation,asset,purpose)};actor=NS(rows=())
    reader=ObservationPublication.__new__(ObservationPublication);reader.access=NS(_fresh=lambda who,*args:who,now=lambda:1000)
    reader.repository=NS(snapshot=lambda keys:{k:rows.get(k) for k in keys});reader.capture=NS(tick=lambda:5000000000)
    reader.stations=NS(inspection_authority=lambda who,ident:(who,work,(work,),None,None,2000),guard_policy=lambda *args:None)
    reader.service=NS(registry=NS(guard=lambda *args:True));reader.objects=NS(validate=lambda receipt:None)
    reader.purpose_key=purpose.key;reader.purpose_snapshot=lambda:((purpose,),2000)
    status=reader.status(actor,iid)
    assert status['effective_state']=='INVALIDATED' and status['remaining_lease_ms']==0
