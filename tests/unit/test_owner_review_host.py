"""Explicit configured review schema and dependencies; no SDK/server proof."""
from copy import deepcopy
from dataclasses import asdict,replace
import json
import pytest
from test_host import host_files,forbidden
from test_owner_metadata_host import settings
from test_held_corpus import INV,BOUNDS
from test_corpus_accounting import LIMITS
from proofpack.runtime.host import load_configuration,HostConfigurationError
from proofpack.evidence.owner_metadata_review import OwnerReviewConfiguration


def configuration():return OwnerReviewConfiguration(INV,BOUNDS,LIMITS,8192)


def install(document):
    settings(document);document['owner_metadata_review']=asdict(configuration())


def test_explicit_nested_configuration_roundtrips_without_sdk_or_server(host_files,monkeypatch):
    config,secret,document,_=host_files
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    assert load_configuration(config,secret).config.owner_metadata_review is None
    install(document);config.write_text(json.dumps(document))
    loaded=load_configuration(config,secret).config
    assert type(loaded.owner_metadata_review) is OwnerReviewConfiguration
    assert loaded.owner_metadata_review==configuration()
    assert loaded.owner_metadata.max_inspections<=loaded.owner_metadata_review.accounting.max_scope


@pytest.mark.parametrize('path',[
    'max_response_bytes','inventory.max_snapshot_batches','inventory.max_payload_bytes',
    'inventory.inventory.page_size','inventory.inventory.max_pages','inventory.inventory.max_records','inventory.inventory.max_summary_bytes',
    'corpus.max_total_snapshot_batches','corpus.max_total_payload_bytes','corpus.max_binding_bytes',
    'corpus.analysis.max_replays','corpus.analysis.max_transaction_events',
    'corpus.analysis.dataset.max_datasets','corpus.analysis.dataset.max_groups',
    'corpus.analysis.dataset.family_max_records','corpus.analysis.dataset.family_max_payload_bytes',
    'corpus.analysis.dataset.corpus.max_records','corpus.analysis.dataset.corpus.max_payload_bytes',
    'corpus.analysis.dataset.corpus.max_inspections','corpus.analysis.dataset.corpus.max_work',
    'corpus.references.max_references','corpus.references.max_work','corpus.references.max_summary_bytes',
    'corpus.references.family.max_records','corpus.references.family.max_payload_bytes','corpus.references.family.max_dependencies','corpus.references.family.max_work',
    'accounting.max_records','accounting.max_scope','accounting.max_relationships','accounting.max_work','accounting.max_summary_bytes'])
@pytest.mark.parametrize('value',[True,0,1.0,'1'])
def test_every_nested_limit_is_exact_and_positive_before_io(host_files,monkeypatch,path,value):
    config,secret,document,_=host_files;install(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    target=document['owner_metadata_review'];parts=path.split('.')
    for part in parts[:-1]:target=target[part]
    target[parts[-1]]=value;config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


@pytest.mark.parametrize('fault',['owner','admission','lease','scope','accounting_scope','snapshot','payload','page','response','extra','missing','nested_extra','untyped'])
def test_configured_review_denies_unsupported_unpaired_and_incomplete_limits(host_files,monkeypatch,fault):
    config,secret,document,_=host_files;install(document);v=document['owner_metadata_review']
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    if fault=='owner':document.pop('owner_metadata')
    elif fault=='admission':document.pop('metadata_admission')
    elif fault=='lease':document['metadata_admission']['http_lease_ms']=19999
    elif fault=='scope':v['corpus']['analysis']['dataset']['corpus']['max_inspections']=9
    elif fault=='accounting_scope':v['accounting']['max_scope']=9
    elif fault=='snapshot':v['corpus']['max_total_snapshot_batches']=v['inventory']['max_snapshot_batches']*2-1
    elif fault=='payload':v['corpus']['max_total_payload_bytes']=v['inventory']['max_payload_bytes']*2-1
    elif fault=='page':v['inventory']['inventory']['page_size']=101
    elif fault=='response':v['max_response_bytes']=65537
    elif fault=='extra':v['allow_cleanup']=True
    elif fault=='missing':v.pop('accounting')
    elif fault=='nested_extra':v['corpus']['analysis']['dataset']['corpus']['allow_unknown']=True
    else:document['owner_metadata_review']=True
    config.write_text(json.dumps(document))
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


def test_typed_configuration_rejects_foreign_raw_limits_and_insufficient_cumulative_bounds():
    good=configuration()
    with pytest.raises(ValueError):replace(good,inventory=asdict(INV))
    with pytest.raises(ValueError):replace(good,corpus=asdict(BOUNDS))
    with pytest.raises(ValueError):replace(good,accounting=asdict(LIMITS))
    with pytest.raises(ValueError):replace(good,max_response_bytes=True)
    with pytest.raises(ValueError):replace(good,corpus=replace(BOUNDS,max_total_snapshot_batches=INV.max_snapshot_batches*2-1))
