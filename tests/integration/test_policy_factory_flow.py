"""Configured factory + HTTP + actual worker; target metadata/identity are intercepted.

This is owned local DynamoDB with synthetic login proofs and analytic images,
not AWS target identity, Cognito, physical qualification or beta evidence.
"""
from dataclasses import replace
from types import SimpleNamespace
import time
from fastapi.testclient import TestClient
from test_composition import composition_case,identity
from test_access_lifecycle import repository_factory,proof,invite_and_join
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Role
from proofpack.auth.service import BootstrapApproval
from proofpack.runtime.composition import ApplicationClients,create_configured_app
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.review.policy_qualification import QualificationConfig,installed_qualification_registry_sha256
from proofpack.review.vision_replay import VisionReplayConfig
from proofpack.planner.activation import ActivationConfig
from proofpack.planner.contract_suite import ContractSuiteConfig
from test_policy_delivery import headers,ORIGIN,BASE


class LocalDynamoWithInterceptedProviderMetadata:
    def __init__(self,client,config):
        self.client=client;self.config=config
        self.meta=SimpleNamespace(config=client.meta.config,region_name=client.meta.region_name,
            service_model=client.meta.service_model,endpoint_url='https://dynamodb.'+config.objects.region+'.amazonaws.com')
    def __getattr__(self,name):return getattr(self.client,name)
    def describe_table(self,**kwargs):
        result=self.client.describe_table(**kwargs)
        result['Table']['TableArn']='arn:aws:dynamodb:'+self.config.objects.region+':'+self.config.objects.account_id+':table/'+kwargs['TableName']
        return result


def test_configured_genuine_default_http_shared_worker_and_owner_activation(composition_case,monkeypatch):
    repo,base,clients,stub,clock=composition_case;jobs=EvaluationConfig(20,120,120,3600000,15000,3000)
    config=replace(base,environment='synthetic_demo',local_database_endpoint=None,vision_replay=VisionReplayConfig(),
        auth=replace(base.auth,initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64),
        qualification_preparation=jobs,policy_contract_suite=ContractSuiteConfig(256,15000,8192,1048576),
        policy_qualification=QualificationConfig(jobs,2000,5000),
        policy_activation=ActivationConfig(20,120,60000,80,installed_qualification_registry_sha256()),maintenance_enabled=True)
    intercepted=ApplicationClients(LocalDynamoWithInterceptedProviderMetadata(clients.dynamodb,config),clients.s3,clients.sts)
    identity(stub);app=create_configured_app(config,intercepted,clock_ms=clock)
    with TestClient(app,base_url=ORIGIN) as client:
        access=app.state.access_service
        owner_id=access.bootstrap(BootstrapApproval(config.auth.issuer,'owner','a'*64),proof(clock))
        owner_credentials=access.login(proof(clock));owner=access.resolve(owner_credentials.cookie)
        world=(access,repo,clock,owner_id,owner_credentials,owner)
        _,review_credentials,reviewer,*_=invite_and_join(world,'factory-policy-reviewer',roles=(Role.REVIEWER,))
        client.cookies.set(COOKIE,review_credentials.cookie)
        draft={'name':'Configured default','algorithm':'reason_priority_v1','priority':['SEPARATE_REGION','PLACE_FLAT','RECAPTURE']}
        candidate=client.post('/api/v1/policies',json=draft,headers=headers(review_credentials,'candidate')).json()
        request={'mode':'installed_default','policy_id':candidate['id'],'policy_revision':candidate['revision'],
            'policy_state_version':candidate['state_version'],'policy_revision_sha256':candidate['revision_sha256'],
            'synthetic_demo_acknowledged':True}
        response=client.post(BASE,json=request,headers=headers(review_credentials,'qualification'));assert response.status_code==201,response.text
        job=response.json();deadline=time.monotonic()+45
        while job['status'] in {'queued','processing'} and time.monotonic()<deadline:
            time.sleep(.5);response=client.get(BASE+'/'+job['id']);assert response.status_code==200,response.text;job=response.json()
        assert job['status']=='completed' and job['qualification_status']=='qualified' and job['required_cases']==182
        assert not job['beta_eligible'] and not job['physical_truth_verified']
        assert app.state.maintenance_driver.services['policy_qualification'] is app.state.policy_qualification_service
        client.cookies.set(COOKIE,owner_credentials.cookie)
        context=client.get('/api/v1/policies/active',params={'scope':'owner'}).json()
        request={'operation':'bootstrap','policy_id':candidate['id'],'policy_revision':candidate['revision'],
            'policy_state_version':candidate['state_version'],'policy_revision_sha256':candidate['revision_sha256'],
            'qualification_id':job['id'],'qualification_report_sha256':job['report_sha256'],'expected_active_version':context['active_version'],
            'expected_control_version':context['control_version'],'invalidation_acknowledged':True}
        response=client.post('/api/v1/policies/'+candidate['id']+'/bootstrap',json=request,headers=headers(owner_credentials,'activate',candidate['state_version']))
        assert response.status_code==200,response.text
        current=client.get('/api/v1/policies/active',params={'scope':'owner'}).json()
        assert current['current'] and not current['inspection_enabled'] and not current['inspection_enablement_granted']
        assert app.state.station_service.policy_reader is app.state.active_policy_reader
    assert app.state.composition_status=='closed' and not app.state.maintenance_driver._thread.is_alive()
