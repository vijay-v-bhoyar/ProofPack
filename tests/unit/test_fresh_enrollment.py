"""Fresh-install protocol models; role/creation IDs are synthetic, never IAM proof."""
from copy import deepcopy
from dataclasses import replace
import importlib
import json
from types import SimpleNamespace

import pytest

from test_host import host_files
from test_restore_fence import Client,canonical
from proofpack.runtime import host
from proofpack.evidence.journal_anchors import AnchorCheckpoint
from proofpack.evidence.restore_fence import RestoreDataFence,PROOFS
from proofpack.evidence.repository import DynamoRepository
from proofpack.auth.service import AccessService
from proofpack.runtime.control import RuntimeControl,RUNTIME
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits

OP='00000000-0000-4000-8000-000000000011'
INSTANCE='00000000-0000-4000-8000-000000000012'
ROLE='arn:aws:iam::000000000000:role/ProofPackEnrollment'


def fresh():return importlib.import_module('proofpack.runtime.enrollment')


def world(host_files):
    mod=fresh();path,secret,document,keys=host_files
    import hashlib
    fence=document['restore_fence'];fence.update(release_kind='initial-data-release',journal_table_id='journal-creation-1')
    root={'schema':1,'kind':'journal_root','genesis':fence['genesis_sha256'],'sequence':0,'previous':'0'*64}
    fence['checkpoint']={'sequence':0,'digest':hashlib.sha256(canonical(['sealed-journal-history/v1',document['deployment'],fence['journal_arn'],root]).encode()).hexdigest()}
    fence['release_sha256']='0'*64
    path.write_text(json.dumps(document));loaded=host.load_configuration(path,secret)
    client=Client();client.ids={document['aws'][k+'_table']:fence['target_table_ids'][k] for k in ('state','events')}
    closed=[];discovery=[];identity=[];clock=[1001]
    def metadata(service):return SimpleNamespace(service_model=SimpleNamespace(service_name=service),region_name='us-east-1',endpoint_url='https://'+service+'.us-east-1.amazonaws.com',config=SimpleNamespace(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1}))
    client.meta=metadata('dynamodb');client.close=lambda:closed.append('dynamodb')
    def scan(**kwargs):
        client.calls.append(('scan',deepcopy(kwargs)))
        values=[deepcopy(v) for (table,pk,sk),v in client.items.items() if table==kwargs['TableName']]
        return {'Items':values[:1],'Count':min(1,len(values)),'ScannedCount':min(1,len(values))}
    client.scan=scan
    def sts_identity():
        identity.append(True);return {'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/ProofPackEnrollment/synthetic-session'}
    sts=SimpleNamespace(meta=metadata('sts'),get_caller_identity=sts_identity,close=lambda:closed.append('sts'))
    s3=SimpleNamespace(meta=metadata('s3'),close=lambda:closed.append('s3'))
    class Session:
        def __init__(self,**kwargs):discovery.append(kwargs)
        def get_credentials(self):return SimpleNamespace(method='iam-role')
        def client(self,service,**kwargs):return {'dynamodb':client,'s3':s3,'sts':sts}[service]
    intent=mod.EnrollmentIntent(OP,INSTANCE,ROLE,1000,301000)
    return SimpleNamespace(mod=mod,path=path,secret=secret,document=document,loaded=loaded,client=client,
        closed=closed,discovery=discovery,identity=identity,clock=clock,Session=Session,intent=intent,sts=sts,s3=s3)


def run(w,*,commit=False,loaded=None,intent=None,**kwargs):
    return w.mod.run_enrollment(loaded or w.loaded,intent or w.intent,commit=commit,
        session_factory=w.Session,clock_ms=lambda:w.clock[0],**kwargs)


def approve_candidate(w,candidate):
    # TEST-INJECTED approval; no real owner, policy, IAM or deployment approval.
    w.document['restore_fence']['release_sha256']=candidate['release_sha256']
    w.path.write_text(json.dumps(w.document));w.loaded=host.load_configuration(w.path,w.secret)


def test_prepare_is_read_only_and_candidate_does_not_grant_release_or_readiness(host_files):
    w=world(host_files);before=deepcopy(w.client.items);result=run(w)
    assert result['status']=='ENROLLMENT_PREPARED' and result['operation_id']==OP
    assert not result['readiness_approved'] and not result['inspection_enablement_granted'] and not result['request_fulfilled']
    assert result['authority']=='none' and w.client.items==before
    assert not any(n=='transact_write_items' for n,_ in w.client.calls)
    scans=[k for n,k in w.client.calls if n=='scan']
    assert len(scans)==6 and all(k['ConsistentRead'] is True and k['Limit']==1 and set(k)=={'TableName','Limit','ConsistentRead'} for k in scans)
    assert sorted(w.closed)==['dynamodb','s3','sts']


def test_approved_commit_is_atomic_disabled_and_consumed_by_real_canonical_services(host_files):
    w=world(host_files);proposal=run(w);approve_candidate(w,proposal);w.closed.clear()
    result=run(w,commit=True)
    assert result['status']=='ENROLLMENT_COMMITTED' and result['release_sha256']==proposal['release_sha256']
    calls=[kw for name,kw in w.client.calls if name=='transact_write_items']
    assert len(calls)==1 and len(calls[0]['TransactItems'])==10
    assert all(x['Put']['ConditionExpression'].startswith('attribute_not_exists') for x in calls[0]['TransactItems'])
    assert len(w.client.items)==10 and sorted(w.closed)==['dynamodb','s3','sts']
    config=w.loaded.config
    fence=RestoreDataFence(w.client,deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table,config=config.restore_fence,tick=lambda:1)
    fence.verify_target()
    repository=DynamoRepository(w.client,deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table,data_fence=fence)
    access=AccessService(repository,config.auth,clock_ms=lambda:w.clock[0])
    runtime=RuntimeControl(access,instance_id=INSTANCE,artifact_sha256=config.artifact_sha256,controls_sha256=config.controls_sha256,environment=config.environment)
    observed=runtime.observe_startup();assert observed.runtime_epoch==observed.data_epoch==1
    runtime.start();bounds=config.metadata_admission
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(bounds.max_active,bounds.max_lease_ms),clock_ms=lambda:w.clock[0])
    admission.require_enrollment(bounds.enrollment_sha256)
    assert repository.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
    body=json.loads(next(v['body']['S'] for (_,_,sk),v in w.client.items.items() if sk.startswith('restore-admission#')))
    assert body['kind']=='initial-data-release' and not (set(body)&(PROOFS-{'runtime_generation_sha256'}))


def test_lost_reply_is_reconciled_without_a_second_effect_and_exact_retry_after_expiry_is_read_only(host_files):
    w=world(host_files);approve_candidate(w,run(w));w.client.lost_reply=True
    assert run(w,commit=True)['status']=='ENROLLMENT_COMMITTED'
    before=deepcopy(w.client.items);w.clock[0]=301001
    assert run(w,commit=True)['status']=='ENROLLMENT_COMMITTED'
    assert w.client.items==before and len([1 for n,k in w.client.calls if n=='transact_write_items'])==1


@pytest.mark.parametrize('table_role',['state','events','journal'])
def test_any_existing_data_even_an_unrelated_deployment_blocks_bootstrap(host_files,table_role):
    w=world(host_files);cfg=w.loaded.config
    table=cfg.restore_fence.journal_table if table_role=='journal' else cfg.state_table if table_role=='state' else cfg.events_table
    w.client.items[(table,'deployment#someone-else','foreign')]={'pk':{'S':'deployment#someone-else'},'sk':{'S':'foreign'}}
    before=deepcopy(w.client.items)
    with pytest.raises(host.HostConfigurationError):run(w)
    assert w.client.items==before and not any(n=='transact_write_items' for n,k in w.client.calls)


@pytest.mark.parametrize('fault',['expected-digest','purpose','expired','changed-intent','wrong-role'])
def test_invalid_or_unapproved_commit_never_writes(host_files,fault):
    w=world(host_files)
    if fault!='expected-digest':approve_candidate(w,run(w))
    intent=w.intent
    if fault=='purpose':
        w.document['application']['operation_purpose_id']='00000000-0000-4000-8000-000000000099';w.path.write_text(json.dumps(w.document));w.loaded=host.load_configuration(w.path,w.secret)
    elif fault=='expired':w.clock[0]=301000
    elif fault=='changed-intent':intent=replace(intent,instance_id='00000000-0000-4000-8000-000000000013')
    elif fault=='wrong-role':w.sts.get_caller_identity=lambda:{'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/OrdinaryApp/synthetic'}
    before=deepcopy(w.client.items)
    with pytest.raises(host.HostConfigurationError):run(w,commit=True,intent=intent)
    assert w.client.items==before and not any(n=='transact_write_items' for n,k in w.client.calls)


def test_missing_creation_identity_holds_before_any_primary_data_or_effect(host_files):
    w=world(host_files);original=w.client.describe_table
    def missing(**kwargs):
        result=original(**kwargs);result['Table'].pop('TableId');return result
    w.client.describe_table=missing
    with pytest.raises(host.HostConfigurationError):run(w)
    assert [n for n,k in w.client.calls]==['describe_table'] and w.client.items=={}
