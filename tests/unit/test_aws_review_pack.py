"""Offline deployment-tool contracts; not provider/IAM/CloudFormation acceptance."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import hashlib
import importlib
import json

import pytest

CATEGORIES=('compute','ebs_snapshots','alb','nat','public_ipv4','dynamodb','s3','cognito','kms','logs_monitoring','cloudtrail','secrets','transfer')


def mod():return importlib.import_module('prepare_aws_review')


def config():
    costs={region:{k:'1.00' for k in CATEGORIES} for region in ('us-east-1','us-east-2')}
    costs['us-east-2']['compute']='2.00'
    return {'schema_version':1,'account_id':'000000000000','region':'us-east-1','stack_slug':'synthetic-review',
        'deployment':'synthetic-deployment','environment':'synthetic_demo','app_origin':'https://proofpack.example.invalid',
        'certificate_arn':'arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-4000-8000-000000000001',
        'ami_id':'ami-00000000000000000','ami_evidence_sha256':'a'*64,'artifact_sha256':'b'*64,'instance_type':'c8g.large',
        'vpc_cidr':'10.24.0.0/16','public_a_cidr':'10.24.0.0/24','public_b_cidr':'10.24.1.0/24','private_cidr':'10.24.2.0/24',
        'az_a':'us-east-1a','az_b':'us-east-1b','allowed_client_cidr':'203.0.113.0/24',
        'cloudtrail_arn':'arn:aws:cloudtrail:us-east-1:000000000000:trail/synthetic',
        'log_retention_days':14,'root_volume_gib':30,'service_memory_bytes':2147483648,'service_stop_seconds':60,
        'region_reason':'Synthetic comparison only; no real target or pricing evidence.',
        'costs':{'currency':'USD','as_of':date.today().isoformat(),'basis':'Synthetic fake dollars only; include idle ALB/NAT/IP and all retained resources.',
            'evidence_urls':{r:'https://calculator.aws/#/estimate?id=synthetic-'+r for r in costs},
            'regions':costs,'spend_limit_usd':'100.00'}}


def resources(pack):return pack['stack.template.json']['Resources']


def statements(role):return [s for p in role['Properties']['Policies'] for s in p['PolicyDocument']['Statement']]


def refs(value):
    found=set()
    if isinstance(value,dict):
        if set(value)=={'Ref'}:found.add(value['Ref'])
        if set(value)=={'Fn::GetAtt'}:found.add(value['Fn::GetAtt'][0])
        for item in value.values():found|=refs(item)
    elif isinstance(value,list):
        for item in value:found|=refs(item)
    return found


def test_complete_pack_is_deterministic_and_cannot_assert_authority():
    cfg=config();before=deepcopy(cfg);pack=mod().prepare(cfg)
    assert cfg==before and pack==mod().prepare(cfg)
    assert set(pack)=={'stack.template.json','deployment-review.json','cost-comparison.json','host.service','operator-handoff.md'}
    review=pack['deployment-review.json']
    assert review['deploy_authorized'] is review['application_started'] is review['aws_resources_created'] is False
    assert review['beta_decision']=='NO_GO' and review['provider_schema_validation']=='NOT_RUN' and review['iam_simulation']=='NOT_RUN'
    assert review['runtime_inputs']['ingress']=={'mode':'alb','trusted_proxy_cidrs':[cfg['public_a_cidr'],cfg['public_b_cidr']]}
    assert 'TableId' not in json.dumps(pack['stack.template.json']['Outputs'])
    assert 'actual creation IDs' in pack['operator-handoff.md']


def test_all_resources_and_outputs_are_gated_to_exact_account_and_region():
    cfg=config();template=mod().prepare(cfg)['stack.template.json']
    assert template['Conditions']['TargetAccount']=={'Fn::Equals':[{'Ref':'AWS::AccountId'},cfg['account_id']]}
    assert template['Conditions']['TargetRegion']=={'Fn::Equals':[{'Ref':'AWS::Region'},cfg['region']]}
    assert all(r['Condition']=='TargetMatches' for r in template['Resources'].values())
    assert all(o['Condition']=='TargetMatches' for o in template['Outputs'].values())
    assert template['Conditions']['TargetMatches']=={'Fn::And':[{'Condition':'TargetAccount'},{'Condition':'TargetRegion'}]}


def test_template_references_exist_and_resource_dependency_graph_is_acyclic():
    template=mod().prepare(config())['stack.template.json'];rs=template['Resources'];pseudo={'AWS::AccountId','AWS::Region','AWS::Partition'}
    assert refs(template)<=set(rs)|pseudo
    edges={name:refs(value)-pseudo for name,value in rs.items()}
    for name,value in rs.items():
        depends=value.get('DependsOn',[]);edges[name]|={depends} if isinstance(depends,str) else set(depends)
    visited=set();active=set()
    def visit(name):
        assert name not in active,'CloudFormation resource cycle'
        if name in visited:return
        active.add(name)
        for target in edges[name]:assert target in rs;visit(target)
        active.remove(name);visited.add(name)
    for name in rs:visit(name)


def test_private_host_has_no_public_ip_ssh_bootstrap_or_implicit_proxy_trust():
    cfg=config();pack=mod().prepare(cfg);rs=resources(pack)
    lt=rs['HostLaunchTemplate']['Properties']['LaunchTemplateData']
    assert lt['ImageId']==cfg['ami_id'] and lt['InstanceType']==cfg['instance_type']
    assert lt['MetadataOptions']['HttpTokens']=='required' and lt['MetadataOptions']['HttpPutResponseHopLimit']==1
    assert lt['NetworkInterfaces'][0]['AssociatePublicIpAddress'] is False and 'KeyName' not in lt and 'UserData' not in lt
    assert lt['NetworkInterfaces'][0]['SubnetId']=={'Ref':'PrivateSubnet'}
    assert rs['ApplicationIngress']['Properties']['SourceSecurityGroupId']=={'Fn::GetAtt':['AlbSecurityGroup','GroupId']}
    assert rs['ApplicationIngress']['Properties']['FromPort']==rs['ApplicationIngress']['Properties']['ToPort']==8080
    assert rs['AlbSecurityGroup']['Properties']['SecurityGroupIngress'][0]['FromPort']==443
    assert rs['ApplicationSecurityGroup']['Properties']['SecurityGroupEgress']==[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'CidrIp':'0.0.0.0/0'}]
    listener=rs['HttpsListener']['Properties'];assert listener['Protocol']=='HTTPS' and listener['Port']==443
    assert rs['ApplicationTargetGroup']['Properties']['HealthCheckPath']=='/health/live'
    assert rs['ApplicationTargetGroup']['Properties']['Protocol']=='HTTP'
    attrs={x['Key']:x['Value'] for x in rs['LoadBalancer']['Properties']['LoadBalancerAttributes']}
    assert attrs['routing.http.preserve_host_header.enabled']=='true'


def test_primary_journal_roles_support_fence_reads_without_giving_app_journal_writes():
    cfg=config();rs=resources(mod().prepare(cfg));app=statements(rs['ApplicationRole']);enroll=statements(rs['EnrollmentRole'])
    assert not any('dynamodb:Transact' in json.dumps(s) for s in app+enroll)
    deny=[s for s in app if s['Effect']=='Deny' and s['Resource']=={'Fn::GetAtt':['JournalTable','Arn']}]
    assert len(deny)==1 and 'dynamodb:ConditionCheckItem' in deny[0]['NotAction']
    assert 'dynamodb:PutItem' not in deny[0]['NotAction'] and 'dynamodb:UpdateTimeToLive' not in deny[0]['NotAction']
    journal_allow=[s for s in app if s['Effect']=='Allow' and s.get('Resource')==[{'Fn::GetAtt':['JournalTable','Arn']}] and 'dynamodb:ConditionCheckItem' in s['Action']]
    assert len(journal_allow)==1
    primary=[s for s in app if s['Effect']=='Allow' and 'dynamodb:PutItem' in s['Action']]
    assert len(primary)==1 and primary[0]['Resource']==[{'Fn::GetAtt':['StateTable','Arn']},{'Fn::GetAtt':['EventsTable','Arn']}]
    assert primary[0]['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys']==['deployment#'+cfg['deployment']]
    assert primary[0]['Condition']['Null']['dynamodb:LeadingKeys']=='false'
    assert not any('iam:' in json.dumps(s) or 'sts:AssumeRole' in json.dumps(s) for s in app)
    assert rs['HostLaunchTemplate']['Properties']['LaunchTemplateData']['IamInstanceProfile']=={'Arn':{'Fn::GetAtt':['ApplicationProfile','Arn']}}
    assert rs['EnrollmentProfile']['Properties']['Roles']==[{'Ref':'EnrollmentRole'}]
    assert any('dynamodb:PutItem' in s['Action'] and {'Fn::GetAtt':['JournalTable','Arn']} in s['Resource'] for s in enroll)


def test_data_identity_and_logs_retain_without_invented_erasure_policy():
    rs=resources(mod().prepare(config()))
    for name in ('StateTable','EventsTable','JournalTable','EvidenceBucket','DataKey','UserPool','ApplicationLogs'):
        assert rs[name]['DeletionPolicy']==rs[name]['UpdateReplacePolicy']=='Retain'
    for name in ('StateTable','EventsTable','JournalTable'):
        p=rs[name]['Properties'];assert p['DeletionProtectionEnabled'] is True and p['PointInTimeRecoverySpecification']['PointInTimeRecoveryEnabled'] is True
        assert p['SSESpecification']['SSEEnabled'] is True and 'TimeToLiveSpecification' not in p
        assert p['KeySchema']==[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}]
    p=rs['EvidenceBucket']['Properties'];assert p['VersioningConfiguration']['Status']=='Enabled' and all(p['PublicAccessBlockConfiguration'].values())
    assert p['OwnershipControls']['Rules']==[{'ObjectOwnership':'BucketOwnerEnforced'}]
    assert 'LifecycleConfiguration' not in p


def test_cognito_is_admin_provisioned_public_pkce_with_no_owner_or_federated_role_grant():
    cfg=config();rs=resources(mod().prepare(cfg));pool=rs['UserPool']['Properties'];client=rs['UserPoolClient']['Properties']
    assert pool['AdminCreateUserConfig']['AllowAdminCreateUserOnly'] is True
    assert client['GenerateSecret'] is False and client['AllowedOAuthFlowsUserPoolClient'] is True and client['AllowedOAuthFlows']==['code']
    assert client['CallbackURLs']==[cfg['app_origin']+'/api/v1/auth/callback']
    assert client['SupportedIdentityProviders']==['COGNITO']
    assert client['EnableTokenRevocation'] is True
    assert not any(r['Type'] in {'AWS::Cognito::UserPoolUser','AWS::Cognito::UserPoolGroup','AWS::Lambda::Function','AWS::CloudFormation::CustomResource'} for r in rs.values())


def test_service_is_disabled_nonroot_and_has_no_retry_or_secret_values():
    cfg=config();service=mod().prepare(cfg)['host.service']
    for expected in ('User=proofpack','Group=proofpack','Restart=no','NoNewPrivileges=yes','ProtectSystem=strict','UMask=0077','--bind 0.0.0.0 --port 8080'):
        assert expected in service
    assert 'MemoryMax='+str(cfg['service_memory_bytes']) in service
    assert 'TimeoutStopSec='+str(cfg['service_stop_seconds']) in service
    assert 'SendSIGKILL=no' in service and 'check-config' in service
    for private in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','FORWARDED_ALLOW_IPS','systemctl enable','pip install','curl '):assert private not in service


def test_declared_cost_comparison_is_exact_and_not_a_verified_price_or_cap():
    report=mod().prepare(config())['cost-comparison.json']
    assert report['declared_totals_usd']=={'us-east-1':'13.00','us-east-2':'14.00'}
    assert report['lower_declared_cost_region']=='us-east-1' and report['selected_region']=='us-east-1'
    assert report['pricing_verified'] is report['spending_cap_guaranteed'] is False


@pytest.mark.parametrize('field,value',[
    ('schema_version',True),('account_id','123'),('region','eu-west-1'),('stack_slug','bad/name'),('deployment','bad#scope'),
    ('environment','production'),('app_origin','http://proofpack.example.invalid'),('app_origin','https://proofpack.example.invalid/path'),
    ('app_origin','https://proofpack.example.invalid:443'),('certificate_arn','arn:aws:acm:us-east-2:000000000000:certificate/00000000-0000-4000-8000-000000000001'),
    ('certificate_arn','arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-4000-8000-000000000001'),
    ('ami_id','ami-latest'),('ami_evidence_sha256','missing'),('artifact_sha256','B'*64),('instance_type','c7i.large'),
    ('public_a_cidr','10.24.0.7/24'),('public_b_cidr','10.24.0.0/24'),('private_cidr','10.25.2.0/24'),('vpc_cidr','0.0.0.0/0'),
    ('az_b','us-east-1a'),('az_a','us-east-2a'),('allowed_client_cidr','*'),('log_retention_days',True),('root_volume_gib',True),
    ('service_memory_bytes',True),('service_memory_bytes',4294967296),('service_stop_seconds',0),
])
def test_invalid_or_expanding_plan_is_rejected(field,value):
    cfg=config();cfg[field]=value
    with pytest.raises(ValueError):mod().prepare(cfg)


@pytest.mark.parametrize('change',['missing','unknown','credentials','approval','incomplete-costs','float-cost','negative-cost','currency','overspend','credential-url','future-date'])
def test_missing_authority_or_cost_inputs_never_create_an_approved_pack(change):
    cfg=config()
    if change=='missing':cfg.pop('account_id')
    elif change=='unknown':cfg['resources']={'ApplicationRole':'admin'}
    elif change=='credentials':cfg['aws_access_key_id']='do-not-echo'
    elif change=='approval':cfg['approved']=True
    elif change=='incomplete-costs':cfg['costs']['regions']['us-east-2'].pop('nat')
    elif change=='float-cost':cfg['costs']['regions']['us-east-1']['compute']=1.5
    elif change=='negative-cost':cfg['costs']['regions']['us-east-1']['compute']='-1.00'
    elif change=='currency':cfg['costs']['currency']='EUR'
    elif change=='overspend':cfg['costs']['spend_limit_usd']='12.99'
    elif change=='credential-url':cfg['costs']['evidence_urls']['us-east-1']='https://user:secret@calculator.aws/'
    else:cfg['costs']['as_of']='2099-01-01'
    with pytest.raises(ValueError):mod().prepare(cfg)


def test_cli_writes_complete_hashed_pack_and_never_overwrites(tmp_path,monkeypatch,capsys):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path)
    source=tmp_path/'input.json';source.write_text(json.dumps(config()));out=tmp_path/'review'
    assert module.main(['--config',str(source),'--output',str(out)])==0
    result=json.loads(capsys.readouterr().out);assert result['deploy_authorized'] is False and result['beta_decision']=='NO_GO'
    manifest=json.loads((out/'manifest.json').read_text());assert manifest['status']=='PREPARED_REVIEW_DRAFT'
    assert set(manifest['files'])=={p.name for p in out.iterdir()}-{'manifest.json'}
    for name,digest in manifest['files'].items():assert hashlib.sha256((out/name).read_bytes()).hexdigest()==digest
    before={p.name:p.read_bytes() for p in out.iterdir()}
    assert module.main(['--config',str(source),'--output',str(out)])==2
    assert {p.name:p.read_bytes() for p in out.iterdir()}==before


def test_outside_workspace_and_partial_write_do_not_get_completion_manifest(tmp_path,monkeypatch):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path)
    outside=tmp_path.parent/(tmp_path.name+'-escape')
    with pytest.raises(ValueError):module.write_pack(config(),outside)
    assert not outside.exists()
    original=module._write_new
    def fail(path,payload):
        if path.name=='cost-comparison.json':raise OSError('synthetic write failure')
        return original(path,payload)
    monkeypatch.setattr(module,'_write_new',fail);out=tmp_path/'partial'
    with pytest.raises(OSError):module.write_pack(config(),out)
    assert out.exists() and not (out/'manifest.json').exists()


@pytest.mark.parametrize('raw',['{"schema_version":1,"schema_version":1}','{"schema_version":NaN}','{"schema_version":Infinity}','{"aws_secret_access_key":"do-not-echo"}'])
def test_cli_rejects_malformed_or_secret_input_without_echo(tmp_path,monkeypatch,capsys,raw):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path);source=tmp_path/'input.json';source.write_text(raw)
    assert module.main(['--config',str(source),'--output',str(tmp_path/'out')])==2
    result=capsys.readouterr();assert result.out=='' and 'do-not-echo' not in result.err and not (tmp_path/'out').exists()
