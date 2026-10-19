"""Configured consumer transitions on a synthetic SDK store, no AWS release proof."""
import asyncio
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
import json
import pytest

from test_host import host_files, forbidden
from test_restore_http import call, scope, setup as boundary_setup
from restore_consumer_model import factory_world, seed_admission
from proofpack.runtime.host import load_configuration, HostConfigurationError, main
from proofpack.runtime.composition import ConfiguredStartupUnavailable
from proofpack.runtime.control import RUNTIME
from proofpack.runtime.ownership import ResourceOwner
from proofpack.auth.session_schema import LEGACY_FIELDS, session_generation


@pytest.mark.parametrize('fault',['missing','null','unknown','bool_sequence','bool_window','same_ids',
    'wrong_account','wrong_region','primary_overlap','lease','second_artifact','no_admission'])
def test_non_test_host_configuration_requires_closed_paired_restore_binding_before_io(host_files,fault):
    config,secret,document,keys=host_files
    if fault=='missing':document.pop('restore_fence')
    elif fault=='null':document['restore_fence']=None
    elif fault=='unknown':document['restore_fence']['assume_released']=True
    elif fault=='bool_sequence':document['restore_fence']['checkpoint']['sequence']=False
    elif fault=='bool_window':document['restore_fence']['max_check_ms']=True
    elif fault=='same_ids':document['restore_fence']['target_table_ids']['state']=document['restore_fence']['target_table_ids']['events']
    elif fault=='wrong_account':document['restore_fence']['journal_arn']=document['restore_fence']['journal_arn'].replace('000000000000','111111111111')
    elif fault=='wrong_region':document['restore_fence']['journal_arn']=document['restore_fence']['journal_arn'].replace('us-east-1','us-west-2')
    elif fault=='primary_overlap':
        document['restore_fence']['journal_table']=document['aws']['state_table']
        document['restore_fence']['journal_arn']='arn:aws:dynamodb:us-east-1:000000000000:table/'+document['aws']['state_table']
    elif fault=='lease':document['restore_fence']['max_check_ms']=document['metadata_admission']['http_lease_ms']+1
    elif fault=='second_artifact':document['restore_fence']['artifact_sha256']='f'*64
    else:document.pop('metadata_admission')
    config.write_text(json.dumps(document),encoding='utf-8')
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==2


def test_valid_host_syntax_derives_one_artifact_without_sdk_or_release_approval(host_files):
    loaded=load_configuration(*host_files[:2]).config
    assert loaded.restore_fence.artifact_sha256==loaded.artifact_sha256
    assert main(['check-config','--config',str(host_files[0]),'--secrets-file',str(host_files[1])],session_factory=forbidden,run_server=forbidden)==0


def test_unfenced_factory_configuration_is_only_an_explicit_loopback_test(host_files):
    config=load_configuration(*host_files[:2]).config
    for fields in [dict(restore_fence=None),dict(restore_fence=None,environment='test'),
                   dict(restore_fence=None,environment='test',local_database_endpoint='https://remote.invalid')]:
        with pytest.raises(ValueError):replace(config,**fields)
    local=replace(config,restore_fence=None,environment='test',local_database_endpoint='http://127.0.0.1:8001')
    assert local.restore_fence is None


def test_factory_shares_exact_fence_across_data_admission_and_outer_transport_without_io(host_files):
    app,config,clients,identities,closed=factory_world(host_files)
    assert clients.dynamodb.calls==[] and not closed
    fence=app.state.data_fence;repo=app.state.access_service.repository
    assert repo.data_fence is fence and app.state.runtime_control.repository is repo
    assert app.state.maintenance_driver.repository is repo
    assert app.state.metadata_admission.repository is repo
    assert [m.cls.__name__ for m in app.user_middleware[:3]]==['OAuthQueryBoundary','RestoreDataBoundary','MetadataAdmissionBoundary']
    assert app.user_middleware[1].kwargs['resource_owner'] is app.state.resource_owner
    # Construct-only fixture cleanup, no app incarnation or target was started.
    app.state.reference_service.close();app.state.reference_service.registry.close()


def test_startup_missing_protected_release_denies_before_first_runtime_write_and_closes_clients(host_files):
    app,config,clients,identities,closed=factory_world(host_files)
    del clients.dynamodb.items[identities[2]];before=deepcopy(clients.dynamodb.items)
    async def run():
        with pytest.raises(ConfiguredStartupUnavailable,match='Protected restore admission'):
            async with app.router.lifespan_context(app):pytest.fail('missing release started application')
    asyncio.run(run())
    assert clients.dynamodb.items==before and app.state.runtime_control.handle is None
    assert not any(name=='transact_write_items' for name,kw in clients.dynamodb.calls)
    assert not app.state.maintenance_driver._started and sorted(closed)==['dynamodb','s3','sts']


def test_started_factory_uses_shared_enrollment_and_blocks_worker_and_http_after_revocation(host_files):
    app,config,clients,identities,closed=factory_world(host_files);seed_admission(app,config)
    async def run():
        async with app.router.lifespan_context(app):
            assert app.state.composition_status=='started' and app.state.runtime_control.handle is not None
            clients.dynamodb.calls.clear()
            live=await call(app,scope('/health/live'))
            assert live[0]['status']==200 and clients.dynamodb.calls==[]
            del clients.dynamodb.items[identities[2]]
            driver=app.state.maintenance_driver;driver.enabled=True
            assert await asyncio.to_thread(driver.poll_once) is False
            assert not any(name in {'query','transact_write_items'} for name,kw in clients.dynamodb.calls)
            for path in ['/','/api/v1/me','/api/v1/auth/login','/health/ready']:
                result=await call(app,scope(path));assert result[0]['status']==503
            driver.enabled=False
    asyncio.run(run())
    assert sorted(closed)==['dynamodb','s3','sts'] and app.state.composition_status=='closed'


def test_mid_check_transport_owner_substitution_releases_only_original_ownership():
    async def forbidden(*args):pytest.fail('changed owner reached downstream')
    boundary,client,identities,original=boundary_setup(forbidden)
    replacement=ResourceOwner()
    def changed(parameters,result):boundary.resource_owner=replacement
    client.after_get=changed
    result=asyncio.run(call(boundary,scope('/api/v1/me')))
    assert result[0]['status']==503 and original.wait_for_drain(0) and replacement.wait_for_drain(0)


@pytest.mark.parametrize('number',[2,Decimal('2'),Decimal('2.0')])
def test_stored_session_version_two_is_lossless_across_dynamodb_number_encoding(number):
    body={k:None for k in LEGACY_FIELDS};body.update(session_schema_version=number,restore_generation_sha256='a'*64)
    assert session_generation(body)=='a'*64


@pytest.mark.parametrize('number',[2.0,Decimal('2.5'),Decimal('NaN'),Decimal('sNaN'),Decimal('Infinity')])
def test_nonintegral_nonfinite_or_float_session_versions_cannot_claim_version_two(number):
    body={k:None for k in LEGACY_FIELDS};body.update(session_schema_version=number,restore_generation_sha256='a'*64)
    with pytest.raises(ValueError):session_generation(body)
