"""Configured auth-review admission; synthetic configuration, no provider proof."""
from dataclasses import asdict,replace
import json
import pytest
from test_host import host_files,forbidden
from test_owner_review_host import configuration,install
from test_runtime_context import limits as runtime_limits
from test_access_context import limits as access_limits
from test_auth_history_consumption import limits as auth_limits
from test_owner_accounting_review import world,read,no_sdk
from proofpack.runtime.host import load_configuration,HostConfigurationError
from proofpack.evidence.owner_metadata_review import AuthReviewLimits,OwnerMetadataReview
from proofpack.evidence.held_corpus import HeldCorpusHeld


def bounds():return AuthReviewLimits(runtime_limits(),access_limits(),auth_limits())


def configure(document):
    install(document)
    document['owner_metadata_review']['auth_review']=asdict(bounds())


def test_explicit_auth_group_roundtrips_without_initialization_io(host_files,monkeypatch):
    config,secret,document,_=host_files
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    install(document);config.write_text(json.dumps(document))
    assert load_configuration(config,secret).config.owner_metadata_review.auth_review is None
    configure(document);config.write_text(json.dumps(document))
    actual=load_configuration(config,secret).config.owner_metadata_review.auth_review
    assert type(actual) is AuthReviewLimits and actual==bounds()


@pytest.mark.parametrize('path',[
    'runtime.max_records','runtime.max_payload_bytes','runtime.max_work','runtime.max_summary_bytes',
    'access.max_records','access.max_payload_bytes','access.max_work','access.max_summary_bytes',
    'auth.max_records','auth.max_payload_bytes','auth.max_dependencies','auth.max_work','auth.max_summary_bytes'])
@pytest.mark.parametrize('bad',[True,0,1.0,'1',2**63])
def test_auth_budget_types_are_exact_positive_and_finite_before_io(host_files,monkeypatch,path,bad):
    config,secret,document,_=host_files;configure(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    family,field=path.split('.')
    document['owner_metadata_review']['auth_review'][family][field]=bad
    config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


@pytest.mark.parametrize('missing',['runtime','access','auth'])
def test_partial_auth_group_never_silently_downgrades(host_files,monkeypatch,missing):
    config,secret,document,_=host_files;configure(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    del document['owner_metadata_review']['auth_review'][missing]
    config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


def test_auth_configuration_cannot_grant_retention_or_cleanup(host_files,monkeypatch):
    config,secret,document,_=host_files;configure(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    document['owner_metadata_review']['auth_review']['allow_cleanup']=True
    config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


@pytest.mark.parametrize('field',['runtime','access','auth'])
def test_typed_group_rejects_raw_budget_maps(field):
    original=bounds()
    with pytest.raises(ValueError):replace(original,**{field:asdict(getattr(original,field))})


def test_swapped_service_group_is_denied_before_private_read(monkeypatch):
    w=world(monkeypatch)
    service=OwnerMetadataReview(w[1],w[2],accounting_limits=w[0].accounting_limits,
        max_response_bytes=8192,auth_review=bounds())
    service.auth_review=replace(service.auth_review,auth=auth_limits(max_work=1))
    monkeypatch.setattr(w[2],'read_auth_accounting',lambda **kw:pytest.fail('changed group reached reader'))
    with pytest.raises(HeldCorpusHeld):read((service,*w[1:]))
    assert w[-1].wait_for_drain(0)


def test_optional_purpose_group_is_explicit_and_remains_separate_from_business_policy(host_files,monkeypatch):
    from proofpack.evidence.purpose_history import PurposeHistoryLimits
    from proofpack.evidence.purpose_corpus import PurposeCorpusLimits
    config,secret,document,_=host_files;configure(document)
    purpose=PurposeCorpusLimits(20,PurposeHistoryLimits(100,1000000,1000,10000,1000000),400000,8000000)
    document['owner_metadata_review']['auth_review']['purposes']=asdict(purpose)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    config.write_text(json.dumps(document))
    actual=load_configuration(config,secret).config.owner_metadata_review.auth_review
    assert actual.purposes==purpose
    assert not hasattr(actual,'retention_days') and not hasattr(actual,'allow_cleanup')
