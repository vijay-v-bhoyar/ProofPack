"""Explicit private-file v6 profile; no AWS client or service start."""
from dataclasses import asdict
import json
import pytest
from test_host import host_files,forbidden
from test_owner_auth_review_host import configure
from test_metadata_history_consumption import limits
from test_admission_factory_wiring import factory_model,build,prohibit_sdk
from test_owner_review_host import configuration
from test_owner_auth_review_host import bounds
from dataclasses import replace
from proofpack.evidence.owner_metadata import OwnerMetadataLimits
from proofpack.runtime.host import load_configuration,HostConfigurationError


def install(document):
    configure(document)
    profile=asdict(limits())
    profile.update(max_inspections=document['owner_metadata']['max_inspections'],writes_per_minute=document['owner_metadata']['writes_per_minute'])
    document['owner_metadata_review']['metadata_review']=profile
    return profile


def test_v6_opt_in_roundtrips_and_absence_keeps_legacy_default(host_files,monkeypatch):
    config,secret,document,_=host_files
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    configure(document);config.write_text(json.dumps(document))
    assert load_configuration(config,secret).config.owner_metadata_review.metadata_review is None
    expected=install(document);config.write_text(json.dumps(document))
    loaded=load_configuration(config,secret).config
    assert asdict(loaded.owner_metadata_review.metadata_review)==expected
    assert loaded.owner_metadata_review.auth_review is not None


@pytest.mark.parametrize('field',list(asdict(limits())))
@pytest.mark.parametrize('bad',[True,0,1.0,'10',2**63])
def test_invalid_v6_budget_is_rejected_before_any_external_initialization(host_files,monkeypatch,field,bad):
    config,secret,document,_=host_files;install(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    document['owner_metadata_review']['metadata_review'][field]=bad;config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


@pytest.mark.parametrize('fault',['auth','scope','quota','unknown'])
def test_incomplete_or_mismatched_profile_cannot_reach_composition(host_files,monkeypatch,fault):
    config,secret,document,_=host_files;install(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    profile=document['owner_metadata_review']['metadata_review']
    if fault=='auth':document['owner_metadata_review']['auth_review']=None
    elif fault=='scope':profile['max_inspections']=profile['max_inspections']+1
    elif fault=='quota':profile['writes_per_minute']=profile['writes_per_minute']+1
    else:profile['cleanup_authorized']=True
    config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


def test_actual_factory_passes_exact_metadata_and_auth_groups_without_initialization(factory_model):
    settings,clients,repo,closed=factory_model
    metadata=limits();auth=bounds();review=replace(configuration(),auth_review=auth,metadata_review=metadata)
    settings=replace(settings,owner_metadata=OwnerMetadataLimits(10,20,100,20000),owner_metadata_review=review)
    app=build((settings,clients,repo,closed));service=app.state.owner_metadata_review_service
    assert service.metadata_review is metadata and service.auth_review is auth
    assert service.requests is app.state.owner_metadata_service
    assert service.reader.admission is app.state.metadata_admission and service.reader.resource_owner is app.state.resource_owner
    assert not repo.rows and not closed
