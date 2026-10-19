from dataclasses import asdict,replace
import json
import pytest
from test_host import host_files,forbidden
from test_owner_review_host import configuration,install
from test_owner_collateral_review import BOUNDS
from proofpack.runtime.host import load_configuration,HostConfigurationError
from proofpack.evidence.collateral_scope import CollateralLimits

def configure(document):
 install(document);document['owner_metadata_review']['collateral_limits']=asdict(BOUNDS)
def test_explicit_collateral_host_configuration_roundtrips_without_sdk(host_files,monkeypatch):
 config,secret,document,_=host_files;configure(document);config.write_text(json.dumps(document))
 monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
 r=load_configuration(config,secret).config.owner_metadata_review
 assert type(r.collateral_limits) is CollateralLimits and r.collateral_limits==BOUNDS
@pytest.mark.parametrize('field',['max_records','max_memberships','max_scope','max_work'])
@pytest.mark.parametrize('bad',[True,0,1.0,'1'])
def test_every_collateral_field_is_strict_positive_before_io(host_files,monkeypatch,field,bad):
 config,secret,document,_=host_files;configure(document);document['owner_metadata_review']['collateral_limits'][field]=bad;config.write_text(json.dumps(document))
 monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
 with pytest.raises(HostConfigurationError):load_configuration(config,secret)
@pytest.mark.parametrize('fault',['scope','extra','missing','owner','admission'])
def test_collateral_configuration_rejects_unsupported_or_unpaired_values(host_files,fault):
 config,secret,document,_=host_files;configure(document);v=document['owner_metadata_review']['collateral_limits']
 if fault=='scope':v['max_scope']=11
 if fault=='extra':v['cleanup']=True
 if fault=='missing':v.pop('max_work')
 if fault=='owner':document.pop('owner_metadata')
 if fault=='admission':document.pop('metadata_admission')
 config.write_text(json.dumps(document))
 with pytest.raises(HostConfigurationError):load_configuration(config,secret)
