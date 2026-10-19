"""Offline PP12 review drafts. No SDK, network, provisioning or approval action."""
import argparse
from copy import deepcopy
from datetime import date
from decimal import Decimal
import hashlib
from ipaddress import IPv4Network
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from uuid import UUID

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
from proofpack.runtime.ingress import IngressConfig

REGIONS=('us-east-1','us-east-2')
CATEGORIES=('compute','ebs_snapshots','alb','nat','public_ipv4','dynamodb','s3','cognito','kms','logs_monitoring','cloudtrail','secrets','transfer')
FIELDS=set('schema_version account_id region stack_slug deployment environment app_origin certificate_arn ami_id ami_evidence_sha256 artifact_sha256 instance_type vpc_cidr public_a_cidr public_b_cidr private_cidr az_a az_b allowed_client_cidr cloudtrail_arn log_retention_days root_volume_gib service_memory_bytes service_stop_seconds costs region_reason'.split())
MEMORY={'c8g.large':4*1024**3,'c8g.xlarge':8*1024**3}
PRIVATE=tuple(IPv4Network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def _closed(value,fields):
    if type(value) is not dict or set(value)!=set(fields):raise ValueError('closed explicit review fields required')


def _text(value,limit=256):
    if (type(value) is not str or not 1<=len(value)<=limit or value.strip()!=value
            or any(not 32<=ord(c)<127 for c in value)):raise ValueError('bounded explicit text required')
    return value


def _pattern(value,pattern):
    if re.fullmatch(pattern,_text(value)) is None:raise ValueError('explicit canonical identifier required')
    return value


def _number(value,low,high):
    if type(value) is not int or not low<=value<=high:raise ValueError('finite explicit integer bound required')


def _network(value):
    net=IPv4Network(_text(value),strict=True)
    if str(net)!=value:raise ValueError('canonical IPv4 CIDR required')
    return net


def _amount(value):
    if type(value) is not str or re.fullmatch(r'(?:0|[1-9][0-9]{0,5})\.[0-9]{2}',value) is None:
        raise ValueError('bounded exact USD decimal string required')
    return Decimal(value)


def _costs(c,region):
    _closed(c,{'currency','as_of','basis','evidence_urls','regions','spend_limit_usd'})
    if c['currency']!='USD':raise ValueError('explicit USD comparison required')
    day=date.fromisoformat(_text(c['as_of']))
    if day.isoformat()!=c['as_of'] or day>date.today():raise ValueError('nonfuture canonical quote date required')
    _text(c['basis'],2048);_closed(c['regions'],REGIONS);_closed(c['evidence_urls'],REGIONS)
    totals={}
    for name in REGIONS:
        url=urlsplit(_text(c['evidence_urls'][name],2048))
        if (url.scheme!='https' or url.netloc!='calculator.aws' or url.path!='/' or url.query
                or re.fullmatch(r'/estimate\?id=[A-Za-z0-9-]{1,128}',url.fragment) is None):
            raise ValueError('explicit calculator estimate reference required')
        _closed(c['regions'][name],CATEGORIES)
        total=sum((_amount(c['regions'][name][kind]) for kind in CATEGORIES),Decimal(0))
        if total<=0:raise ValueError('positive declared gross total required')
        totals[name]=total
    limit=_amount(c['spend_limit_usd'])
    if limit<=0 or totals[region]>limit:raise ValueError('selected declared cost exceeds explicit limit')
    low=min(totals.values());lowest=[r for r in REGIONS if totals[r]==low]
    return {'currency':'USD','as_of':c['as_of'],'basis':c['basis'],'evidence_urls':c['evidence_urls'],
        'declared_items_usd':c['regions'],'declared_totals_usd':{k:format(v,'.2f') for k,v in totals.items()},
        'lower_declared_cost_region':lowest[0] if len(lowest)==1 else 'TIE','selected_region':region,
        'declared_spend_limit_usd':c['spend_limit_usd'],'pricing_verified':False,'spending_cap_guaranteed':False,
        'limits':['Caller declarations are not verified quotes or owner approval.',
            'Review idle ALB/NAT/public IPv4, retained storage/snapshots/logs, requests, transfer, taxes and gross cost before uncertain credits.',
            'Actual price/SKU/workload/quota/alerts and chosen-region tradeoffs require independent review; no global-cheapest claim.']}


def _validate(value):
    try:
        c=deepcopy(value);_closed(c,FIELDS)
        if type(c['schema_version']) is not int or c['schema_version']!=1:raise ValueError()
        account=_pattern(c['account_id'],r'[0-9]{12}');region=c['region']
        if region not in REGIONS or c['environment'] not in {'synthetic_demo','beta'}:raise ValueError()
        _pattern(c['stack_slug'],r'[a-z](?:[a-z0-9-]{0,18}[a-z0-9])?');_pattern(c['deployment'],r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}')
        origin=_text(c['app_origin'],512);url=urlsplit(origin)
        if (url.scheme!='https' or not url.hostname or url.netloc!=url.hostname or url.path or url.query or url.fragment
                or re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',url.hostname) is None):raise ValueError()
        prefix='arn:aws:acm:'+region+':'+account+':certificate/'
        arn=_text(c['certificate_arn'])
        if not arn.startswith(prefix) or str(UUID(arn[len(prefix):]))!=arn[len(prefix):]:raise ValueError()
        _pattern(c['ami_id'],r'ami-[0-9a-f]{17}')
        for k in ('ami_evidence_sha256','artifact_sha256'):_pattern(c[k],r'[a-f0-9]{64}')
        if c['instance_type'] not in MEMORY:raise ValueError()
        vpc=_network(c['vpc_cidr'])
        if not 16<=vpc.prefixlen<=28 or not any(vpc.subnet_of(p) for p in PRIVATE):raise ValueError()
        IngressConfig('alb',(c['public_a_cidr'],c['public_b_cidr']))
        subnets=[_network(c[k]) for k in ('public_a_cidr','public_b_cidr','private_cidr')]
        if any(not n.subnet_of(vpc) or not 16<=n.prefixlen<=28 for n in subnets):raise ValueError()
        if any(a.overlaps(b) for i,a in enumerate(subnets) for b in subnets[i+1:]):raise ValueError()
        for k in ('az_a','az_b'):_pattern(c[k],re.escape(region)+r'[a-z]')
        if c['az_a']==c['az_b']:raise ValueError()
        _network(c['allowed_client_cidr'])
        _pattern(c['cloudtrail_arn'],r'arn:aws:cloudtrail:[a-z]{2}-[a-z]+-[0-9]:'+account+r':trail/[A-Za-z0-9._-]{1,128}')
        if type(c['log_retention_days']) is not int or c['log_retention_days'] not in {7,14,30,60,90,180,365}:raise ValueError()
        _number(c['root_volume_gib'],20,200)
        _number(c['service_memory_bytes'],1536*1024**2,MEMORY[c['instance_type']]-512*1024**2)
        _number(c['service_stop_seconds'],1,600);_text(c['region_reason'],1024)
        costs=_costs(c['costs'],region)
        # Freeze only validated primitive fields; callers cannot mutate the plan
        # midway through generation by retaining a nested input dictionary.
        return c,costs
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError,OverflowError,RuntimeError):
        raise ValueError('deployment review inputs failed closed validation') from None


def _ref(name):return {'Ref':name}
def _arn(name):return {'Fn::GetAtt':[name,'Arn']}
def _join(*values):return {'Fn::Join':['',list(values)]}


def _template(c):
    rs={};tags=[{'Key':'proofpack:deployment','Value':c['deployment']},{'Key':'proofpack:environment','Value':c['environment']}]
    def add(name,kind,props,*,retain=False,depends=None,tagged=False):
        props=dict(props)
        if tagged:props['Tags']=tags
        row={'Type':kind,'Condition':'TargetMatches','Properties':props}
        if retain:row.update(DeletionPolicy='Retain',UpdateReplacePolicy='Retain')
        if depends:row['DependsOn']=depends
        rs[name]=row
    add('Vpc','AWS::EC2::VPC',{'CidrBlock':c['vpc_cidr'],'EnableDnsSupport':True,'EnableDnsHostnames':True},tagged=True)
    add('InternetGateway','AWS::EC2::InternetGateway',{},tagged=True)
    add('GatewayAttachment','AWS::EC2::VPCGatewayAttachment',{'VpcId':_ref('Vpc'),'InternetGatewayId':_ref('InternetGateway')})
    for suffix,key,az in [('A','public_a_cidr','az_a'),('B','public_b_cidr','az_b')]:
        add('PublicSubnet'+suffix,'AWS::EC2::Subnet',{'VpcId':_ref('Vpc'),'CidrBlock':c[key],'AvailabilityZone':c[az],'MapPublicIpOnLaunch':False},tagged=True)
        add('PublicRoutes'+suffix,'AWS::EC2::RouteTable',{'VpcId':_ref('Vpc')},tagged=True)
        add('PublicAssociation'+suffix,'AWS::EC2::SubnetRouteTableAssociation',{'SubnetId':_ref('PublicSubnet'+suffix),'RouteTableId':_ref('PublicRoutes'+suffix)})
        add('PublicDefaultRoute'+suffix,'AWS::EC2::Route',{'RouteTableId':_ref('PublicRoutes'+suffix),'DestinationCidrBlock':'0.0.0.0/0','GatewayId':_ref('InternetGateway')},depends='GatewayAttachment')
    add('PrivateSubnet','AWS::EC2::Subnet',{'VpcId':_ref('Vpc'),'CidrBlock':c['private_cidr'],'AvailabilityZone':c['az_a'],'MapPublicIpOnLaunch':False},tagged=True)
    add('NatAddress','AWS::EC2::EIP',{'Domain':'vpc'},depends='GatewayAttachment',tagged=True)
    add('NatGateway','AWS::EC2::NatGateway',{'AllocationId':{'Fn::GetAtt':['NatAddress','AllocationId']},'SubnetId':_ref('PublicSubnetA')},depends='PublicDefaultRouteA',tagged=True)
    add('PrivateRoutes','AWS::EC2::RouteTable',{'VpcId':_ref('Vpc')},tagged=True)
    add('PrivateAssociation','AWS::EC2::SubnetRouteTableAssociation',{'SubnetId':_ref('PrivateSubnet'),'RouteTableId':_ref('PrivateRoutes')})
    add('PrivateDefaultRoute','AWS::EC2::Route',{'RouteTableId':_ref('PrivateRoutes'),'DestinationCidrBlock':'0.0.0.0/0','NatGatewayId':_ref('NatGateway')})
    add('ApplicationSecurityGroup','AWS::EC2::SecurityGroup',{'VpcId':_ref('Vpc'),'GroupDescription':'Private application; only ALB ingress',
        'SecurityGroupIngress':[],'SecurityGroupEgress':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'CidrIp':'0.0.0.0/0'}]},tagged=True)
    # One-way embedded dependency, with the reverse ingress in its own resource:
    # this removes default all-egress without a security-group reference cycle.
    add('AlbSecurityGroup','AWS::EC2::SecurityGroup',{'VpcId':_ref('Vpc'),'GroupDescription':'HTTPS ingress; only private application egress',
        'SecurityGroupIngress':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'CidrIp':c['allowed_client_cidr']}],
        'SecurityGroupEgress':[{'IpProtocol':'tcp','FromPort':8080,'ToPort':8080,'DestinationSecurityGroupId':{'Fn::GetAtt':['ApplicationSecurityGroup','GroupId']}}]},tagged=True)
    add('ApplicationIngress','AWS::EC2::SecurityGroupIngress',{'GroupId':{'Fn::GetAtt':['ApplicationSecurityGroup','GroupId']},
        'SourceSecurityGroupId':{'Fn::GetAtt':['AlbSecurityGroup','GroupId']},'IpProtocol':'tcp','FromPort':8080,'ToPort':8080})
    add('DataKey','AWS::KMS::Key',{'Description':'ProofPack declared deployment data key','EnableKeyRotation':True,
        'KeyPolicy':{'Version':'2012-10-17','Statement':[{'Sid':'AccountIAMAdministration','Effect':'Allow',
            'Principal':{'AWS':'arn:aws:iam::'+c['account_id']+':root'},'Action':'kms:*','Resource':'*'}]}},retain=True,tagged=True)
    for name,suffix in [('StateTable','state'),('EventsTable','events'),('JournalTable','journal')]:
        add(name,'AWS::DynamoDB::Table',{'TableName':'ppf-'+c['stack_slug']+'-'+suffix,'BillingMode':'PAY_PER_REQUEST',
            'KeySchema':[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
            'AttributeDefinitions':[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}],
            'SSESpecification':{'SSEEnabled':True,'SSEType':'KMS','KMSMasterKeyId':_arn('DataKey')},
            'PointInTimeRecoverySpecification':{'PointInTimeRecoveryEnabled':True},'DeletionProtectionEnabled':True},retain=True,tagged=True)
    bucket='ppf-'+c['account_id']+'-'+c['region']+'-'+c['stack_slug']+'-evidence'
    add('EvidenceBucket','AWS::S3::Bucket',{'BucketName':bucket,'VersioningConfiguration':{'Status':'Enabled'},
        'OwnershipControls':{'Rules':[{'ObjectOwnership':'BucketOwnerEnforced'}]},
        'PublicAccessBlockConfiguration':{k:True for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')},
        'BucketEncryption':{'ServerSideEncryptionConfiguration':[{'ServerSideEncryptionByDefault':{'SSEAlgorithm':'aws:kms','KMSMasterKeyID':_arn('DataKey')},'BucketKeyEnabled':True}]}},retain=True,tagged=True)
    add('BucketTransportPolicy','AWS::S3::BucketPolicy',{'Bucket':_ref('EvidenceBucket'),'PolicyDocument':{'Version':'2012-10-17','Statement':[
        {'Effect':'Deny','Principal':'*','Action':'s3:*','Resource':[_arn('EvidenceBucket'),_join(_arn('EvidenceBucket'),'/*')],'Condition':{'Bool':{'aws:SecureTransport':'false'}}}]}})
    add('ApplicationLogs','AWS::Logs::LogGroup',{'LogGroupName':'/proofpack/'+c['stack_slug']+'/application','RetentionInDays':c['log_retention_days']},retain=True,tagged=True)
    primary=[_arn('StateTable'),_arn('EventsTable')];all_tables=primary+[_arn('JournalTable')]
    keyed={'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':['deployment#'+c['deployment']]},'Null':{'dynamodb:LeadingKeys':'false'}}
    metadata={'Sid':'ExactTableMetadata','Effect':'Allow','Action':['dynamodb:DescribeTable','dynamodb:DescribeTimeToLive'],'Resource':all_tables}
    caller={'Sid':'CallerIdentity','Effect':'Allow','Action':['sts:GetCallerIdentity'],'Resource':'*'}
    journal_reads=['dynamodb:GetItem','dynamodb:Query','dynamodb:ConditionCheckItem']
    namespaces=['deployments/'+c['deployment']+'/'+kind+'/' for kind in ('frames','references')]
    app=[metadata,caller,
        {'Sid':'PrimaryDeploymentRows','Effect':'Allow','Action':['dynamodb:GetItem','dynamodb:Query','dynamodb:PutItem','dynamodb:UpdateItem','dynamodb:DeleteItem','dynamodb:ConditionCheckItem'],'Resource':primary,'Condition':keyed},
        {'Sid':'ProtectedJournalConditions','Effect':'Allow','Action':journal_reads,'Resource':[_arn('JournalTable')],'Condition':keyed},
        {'Sid':'NeverWriteProtectedJournal','Effect':'Deny','NotAction':journal_reads+['dynamodb:DescribeTable','dynamodb:DescribeTimeToLive'],'Resource':_arn('JournalTable')},
        {'Sid':'ExactEvidenceNamespaces','Effect':'Allow','Action':['s3:GetObject','s3:GetObjectVersion','s3:PutObject','s3:DeleteObject','s3:DeleteObjectVersion'],
            'Resource':[_join(_arn('EvidenceBucket'),'/'+prefix+'*') for prefix in namespaces]},
        {'Sid':'ScopedVersionListing','Effect':'Allow','Action':['s3:ListBucket','s3:ListBucketVersions'],'Resource':_arn('EvidenceBucket'),'Condition':{'StringLike':{'s3:prefix':[p+'*' for p in namespaces]}}},
        {'Sid':'BucketMetadata','Effect':'Allow','Action':['s3:GetBucketVersioning','s3:GetBucketLocation','s3:GetEncryptionConfiguration'],'Resource':_arn('EvidenceBucket')},
        {'Sid':'DataKeyViaStorageOnly','Effect':'Allow','Action':['kms:Decrypt','kms:Encrypt','kms:GenerateDataKey'],'Resource':_arn('DataKey'),
            'Condition':{'StringEquals':{'kms:ViaService':['s3.'+c['region']+'.amazonaws.com','dynamodb.'+c['region']+'.amazonaws.com']}}},
        {'Sid':'ApplicationLogStream','Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],'Resource':_join(_arn('ApplicationLogs'),':*')},
        {'Sid':'ManagedHostAgent','Effect':'Allow','Action':['ssm:UpdateInstanceInformation','ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],'Resource':'*'}]
    enrollment=[metadata,caller,
        {'Sid':'WholeEmptyTableRead','Effect':'Allow','Action':['dynamodb:Scan'],'Resource':all_tables},
        {'Sid':'InitialDeploymentSeed','Effect':'Allow','Action':['dynamodb:GetItem','dynamodb:PutItem','dynamodb:ConditionCheckItem'],'Resource':all_tables,'Condition':keyed},
        {'Sid':'DataKeyViaDynamoDB','Effect':'Allow','Action':['kms:Decrypt','kms:GenerateDataKey'],'Resource':_arn('DataKey'),
            'Condition':{'StringEquals':{'kms:ViaService':'dynamodb.'+c['region']+'.amazonaws.com'}}}]
    trust={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'ec2.amazonaws.com'},'Action':'sts:AssumeRole'}]}
    for name,policy in [('ApplicationRole',app),('EnrollmentRole',enrollment)]:
        add(name,'AWS::IAM::Role',{'AssumeRolePolicyDocument':trust,'MaxSessionDuration':3600,
            'Policies':[{'PolicyName':'ProofPackScopedAccess','PolicyDocument':{'Version':'2012-10-17','Statement':policy}}]},tagged=True)
    add('ApplicationProfile','AWS::IAM::InstanceProfile',{'Roles':[_ref('ApplicationRole')]})
    add('EnrollmentProfile','AWS::IAM::InstanceProfile',{'Roles':[_ref('EnrollmentRole')]})
    add('HostLaunchTemplate','AWS::EC2::LaunchTemplate',{'VersionDescription':'Declared artifact '+c['artifact_sha256'],
        'LaunchTemplateData':{'ImageId':c['ami_id'],'InstanceType':c['instance_type'],'IamInstanceProfile':{'Arn':_arn('ApplicationProfile')},
            'MetadataOptions':{'HttpEndpoint':'enabled','HttpTokens':'required','HttpPutResponseHopLimit':1,'HttpProtocolIpv6':'disabled'},
            'NetworkInterfaces':[{'DeviceIndex':0,'SubnetId':_ref('PrivateSubnet'),'Groups':[{'Fn::GetAtt':['ApplicationSecurityGroup','GroupId']}],'AssociatePublicIpAddress':False,'DeleteOnTermination':True}],
            'BlockDeviceMappings':[{'DeviceName':'/dev/xvda','Ebs':{'VolumeSize':c['root_volume_gib'],'VolumeType':'gp3','Encrypted':True,'DeleteOnTermination':True}}],
            'TagSpecifications':[{'ResourceType':'instance','Tags':tags},{'ResourceType':'volume','Tags':tags}]}},tagged=False)
    add('ApplicationHost','AWS::EC2::Instance',{'LaunchTemplate':{'LaunchTemplateId':_ref('HostLaunchTemplate'),'Version':{'Fn::GetAtt':['HostLaunchTemplate','LatestVersionNumber']}}},depends=['PrivateDefaultRoute','ApplicationIngress'],tagged=True)
    add('LoadBalancer','AWS::ElasticLoadBalancingV2::LoadBalancer',{'Scheme':'internet-facing','Type':'application','IpAddressType':'ipv4',
        'Subnets':[_ref('PublicSubnetA'),_ref('PublicSubnetB')],'SecurityGroups':[{'Fn::GetAtt':['AlbSecurityGroup','GroupId']}],
        'LoadBalancerAttributes':[{'Key':'routing.http.preserve_host_header.enabled','Value':'true'},
            {'Key':'routing.http.drop_invalid_header_fields.enabled','Value':'true'},{'Key':'routing.http.desync_mitigation_mode','Value':'strictest'},
            {'Key':'deletion_protection.enabled','Value':'true'}]},depends=['PublicDefaultRouteA','PublicDefaultRouteB'],tagged=True)
    add('ApplicationTargetGroup','AWS::ElasticLoadBalancingV2::TargetGroup',{'VpcId':_ref('Vpc'),'Protocol':'HTTP','Port':8080,'TargetType':'instance',
        'HealthCheckPath':'/health/live','HealthCheckProtocol':'HTTP','Matcher':{'HttpCode':'200'},'Targets':[{'Id':_ref('ApplicationHost'),'Port':8080}]},tagged=True)
    add('HttpsListener','AWS::ElasticLoadBalancingV2::Listener',{'LoadBalancerArn':_ref('LoadBalancer'),'Protocol':'HTTPS','Port':443,
        'Certificates':[{'CertificateArn':c['certificate_arn']}],'SslPolicy':'ELBSecurityPolicy-TLS13-1-2-2021-06',
        'DefaultActions':[{'Type':'forward','TargetGroupArn':_ref('ApplicationTargetGroup')}]})
    add('UserPool','AWS::Cognito::UserPool',{'UserPoolName':'ppf-'+c['stack_slug'],'AdminCreateUserConfig':{'AllowAdminCreateUserOnly':True},
        'UsernameAttributes':['email'],'UsernameConfiguration':{'CaseSensitive':True},'AutoVerifiedAttributes':['email'],
        'MfaConfiguration':'OPTIONAL','EnabledMfas':['SOFTWARE_TOKEN_MFA'],'DeletionProtection':'ACTIVE',
        'Policies':{'PasswordPolicy':{'MinimumLength':14,'RequireLowercase':True,'RequireUppercase':True,'RequireNumbers':True,'RequireSymbols':True}},
        'UserPoolTags':{t['Key']:t['Value'] for t in tags}},retain=True)
    add('UserPoolClient','AWS::Cognito::UserPoolClient',{'UserPoolId':_ref('UserPool'),'ClientName':'proofpack-bff','GenerateSecret':False,
        'AllowedOAuthFlowsUserPoolClient':True,'AllowedOAuthFlows':['code'],'AllowedOAuthScopes':['openid','email','profile'],
        'CallbackURLs':[c['app_origin']+'/api/v1/auth/callback'],'LogoutURLs':[c['app_origin']+'/'],
        'SupportedIdentityProviders':['COGNITO'],'EnableTokenRevocation':True,'PreventUserExistenceErrors':'ENABLED',
        'ExplicitAuthFlows':['ALLOW_USER_SRP_AUTH','ALLOW_REFRESH_TOKEN_AUTH'],'ReadAttributes':['email','email_verified','name']})
    add('UserPoolDomain','AWS::Cognito::UserPoolDomain',{'UserPoolId':_ref('UserPool'),'Domain':'ppf-'+c['account_id']+'-'+c['region']+'-'+c['stack_slug']})
    output_values={'StateTableName':_ref('StateTable'),'EventsTableName':_ref('EventsTable'),'JournalTableName':_ref('JournalTable'),
        'JournalArn':_arn('JournalTable'),'EvidenceBucketName':_ref('EvidenceBucket'),'DataKeyArn':_arn('DataKey'),
        'ApplicationRoleArn':_arn('ApplicationRole'),'EnrollmentRoleArn':_arn('EnrollmentRole'),'EnrollmentProfileArn':_arn('EnrollmentProfile'),
        'InstanceId':_ref('ApplicationHost'),'AlbDnsName':{'Fn::GetAtt':['LoadBalancer','DNSName']},'UserPoolId':_ref('UserPool'),'ClientId':_ref('UserPoolClient'),
        'Issuer':_join('https://cognito-idp.',_ref('AWS::Region'),'.amazonaws.com/',_ref('UserPool')),
        'ProviderOrigin':_join('https://',_ref('UserPoolDomain'),'.auth.',_ref('AWS::Region'),'.amazoncognito.com')}
    return {'AWSTemplateFormatVersion':'2010-09-09','Description':'ProofPack new-stack review draft only; no deployment, update or readiness authority',
        'Metadata':{'ProofPackReview':{'DeclaredAccount':c['account_id'],'DeclaredRegion':c['region'],'DeclaredArtifactSHA256':c['artifact_sha256'],
            'DeclaredAMIEvidenceSHA256':c['ami_evidence_sha256'],'ExistingAuditTrail':c['cloudtrail_arn'],'ApplicationStartup':'NOT_CONFIGURED',
            'ChangeSetKind':'CREATE_ONLY_DRAFT','UpdatesSupported':False,'SupportedAMIRootDevice':'/dev/xvda',
            'PhysicalCreationIdentity':'Requires actual DescribeTable after separately authorized provisioning'}},
        'Conditions':{'TargetAccount':{'Fn::Equals':[_ref('AWS::AccountId'),c['account_id']]},'TargetRegion':{'Fn::Equals':[_ref('AWS::Region'),c['region']]},
            'TargetMatches':{'Fn::And':[{'Condition':'TargetAccount'},{'Condition':'TargetRegion'}]}},
        'Resources':rs,'Outputs':{k:{'Condition':'TargetMatches','Value':v} for k,v in output_values.items()}}


def _service(c):
    return '''# Review draft only. Install/enable/start are separately authorized operations.
[Unit]
Description=ProofPack reviewed local installation
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=proofpack
Group=proofpack
WorkingDirectory=/opt/proofpack
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
ExecStartPre=/opt/proofpack/venv/bin/proofpack check-config --config /etc/proofpack/host.private.json --secrets-file /etc/proofpack/keys.private.json
ExecStart=/opt/proofpack/venv/bin/proofpack serve --config /etc/proofpack/host.private.json --secrets-file /etc/proofpack/keys.private.json --bind 0.0.0.0 --port 8080
Restart=no
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
RuntimeDirectory=proofpack
ReadWritePaths=/run/proofpack
LimitCORE=0
KillMode=control-group
SendSIGKILL=no
MemoryMax='''+str(c['service_memory_bytes'])+'\nTimeoutStopSec='+str(c['service_stop_seconds'])+'''

[Install]
WantedBy=multi-user.target
'''


def prepare(value):
    c,costs=_validate(value);template=_template(c)
    if len(_json(template))>49152:raise ValueError('review template exceeds bounded local size')
    review={'schema_version':1,'status':'PREPARED_REVIEW_DRAFT','deploy_authorized':False,'aws_resources_created':False,'application_started':False,
        'change_set_kind':'CREATE_ONLY_DRAFT','updates_supported':False,'supported_ami_root_device':'/dev/xvda','ami_root_device_verified':False,
        'beta_decision':'NO_GO','provider_schema_validation':'NOT_RUN','iam_simulation':'NOT_RUN','prices_and_evidence':'CALLER_DECLARED_NOT_VERIFIED',
        'target':{k:c[k] for k in ('account_id','region','stack_slug','deployment','environment','app_origin')},
        'declared_artifact_sha256':c['artifact_sha256'],'declared_ami_evidence_sha256':c['ami_evidence_sha256'],
        'existing_audit_trail':c['cloudtrail_arn'],'region_reason':c['region_reason'],'required_capabilities':['CAPABILITY_IAM'],
        'runtime_inputs':{'ingress':{'mode':'alb','trusted_proxy_cidrs':[c['public_a_cidr'],c['public_b_cidr']]},'operation_purpose_id':None},
        'required_before_apply':['Actual account/region/change-set authority, IAM review and cost/budget/alert recipient approval',
            'AMI owner/arm64/root device/dependencies/patches/license and Graviton availability proof',
            'Certificate/domain/TLS policy, subnet availability and exclusive ALB-SG ingress proof',
            'Provider code/PKCE/native MFA and actual initial owner/notice approval; pool settings do not attest MFA',
            'Actual existing CloudTrail regional coverage and private log/data/config/key retention D11',
            'CloudFormation schema validation, IAM simulation and exact reviewed CREATE change set; this draft cannot safely update an existing stack',
            'Separate reviewed host installer/config/key delivery; no UserData or auto service startup',
            'Quarantine/role transition, original enrollment packet and external candidate approval; creation IDs must be read',
            'Full restore/erasure writer roles and actual recovery/cleanup/requester/media coordinator remain incomplete'],
        'limits':['Wrong account/region makes every resource/output conditional false for creation; an empty stack is not successful deployment. Changing conditions in an existing stack can delete resources, so updates are unsupported.',
            'Only the declared arm64 AMI layout with root device /dev/xvda is supported; its actual identity/layout/encryption/dependencies are not verified.',
            'One private host and one NAT are not high availability; idle/retained resources still cost money.',
            'Retain/deletion protection prevents automatic teardown; it is not a D11 retention or erasure policy.',
            'IAM cannot prove quarantine or enforce exact conditional bootstrap contents; app cannot write journal.',
            'Service draft is disabled, has no automatic retries and does not guarantee successful drain/physical stop.']}
    handoff='''# Operator handoff — review draft only

No deployment, spend, contact, user creation, install or service start is authorized by these files.
An incomplete directory without manifest.json is not a complete review pack. Digests are consistency checks, not independent approval.
This is a CREATE-only draft: changing conditions on an existing stack can delete resources. Never use it to update an existing stack; that needs a separately implemented actual-state diff and exact approval.
Hold if the actual AMI root device differs from /dev/xvda. This v1 layout is not an automatic AMI/architecture/root-volume attestation; choose a genuinely verified compatible image or revise the contract/tool before proceeding.

1. P01/P05 confirm actual target/region/budget/domain/AMI/audit coverage and real gross quotes for both regions; inspect every proposed resource and IAM statement. Native/schema/IAM/provider checks are NOT_RUN.
2. Obtain exact reviewed change-set authority before any CloudFormation action. Wrong account/region yields no resources; stack completion alone is not application readiness. Do not apply synthetic examples.
3. After authorized provisioning, read actual creation IDs, ARNs, TTL-disabled tables, versioned/encrypted bucket, role profiles and network/certificate metadata. No template output substitutes for TableId or verified SG/TLS/IAM behavior.
4. Keep host disabled/quarantined. Verify approved arm64 AMI/root-device mapping, dependencies, SSM agent policy/connection, non-root account, approved wheel SHA/site, private configuration and separately delivered keys/permissions. The generator creates no installer and fetches no artifact or secret. Do not enable host.service yet.
5. P05 must separately authorize temporary enrollment profile use, establish stopped old writers/quarantine, prepare with original intent, obtain independent candidate approval and enroll. Retire enrollment access and prove ordinary role cannot write protected journal. The template attaches only ApplicationProfile to the host; it never swaps profiles or creates an owner.
6. Bind real output metadata to the private closed host document and exact original release/artifact. Use the explicit two-subnet ingress and private8080 SG path. Install/start the service only through approved host actions; preserve original STARTUP_REFERENCE privately. Confirm disabled readiness, then actual provider/owner/notice/invitation journeys. No inspection starts without separate purpose/qualification/readiness/owner enablement.
7. Rehearse stop/drain, uncertain outcome readback, rollback and isolated restore under actual authority. Restart=no does not retry a failed incarnation. SendSIGKILL=no may leave a stuck process; timeout never proves physical stop or completed privacy obligations. Preserve unknown outcomes and have the authorized operator investigate; never reopen admission to force progress.
8. Teardown needs its own exact approval after accepted drain/data/copy obligations. Stateful resources are retained and tables/ALB have deletion protection; never disable protection or delete keys/bucket versions as an incidental stack cleanup. Retained ALB/NAT/IP/storage/log resources may keep costing money. Actual retention/erasure/backup/media/identity duties require D11 and the unfinished full coordinator.

P06 verifies actual source/ARM/hosted behavior; P08 evaluates uncoached participant outcomes. All five features,9personas/78operations and full test/release gates remain required. Beta NO_GO.
'''
    return {'stack.template.json':template,'deployment-review.json':review,'cost-comparison.json':costs,'host.service':_service(c),'operator-handoff.md':handoff}


def _json(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode()


def _write_new(path,payload):
    with path.open('xb') as stream:
        stream.write(payload);stream.flush();os.fsync(stream.fileno())


def write_pack(config,output):
    frozen,_=_validate(config);plan_sha=hashlib.sha256(_json(frozen)).hexdigest()
    pack=prepare(frozen);raw=Path(output)
    if raw.exists() or raw.is_symlink():raise FileExistsError('new review directory required')
    target=raw.resolve();root=ROOT.resolve()
    if target==root or not target.is_relative_to(root):raise ValueError('review output must stay inside the checkout')
    target.mkdir(mode=0o700,parents=False,exist_ok=False)
    payloads={name:value.encode() if isinstance(value,str) else _json(value) for name,value in pack.items()}
    files={}
    for name,payload in payloads.items():
        _write_new(target/name,payload)
        actual=(target/name).read_bytes()
        if actual!=payload:raise OSError('review file changed during preparation')
        files[name]=hashlib.sha256(actual).hexdigest()
    def verify_files():
        if any((target/name).read_bytes()!=expected for name,expected in payloads.items()):
            raise OSError('review files changed before completion')
    verify_files()
    manifest={'schema_version':1,'status':'PREPARED_REVIEW_DRAFT','files':files,'plan_sha256':plan_sha,
        'deploy_authorized':False,'beta_decision':'NO_GO','provider_schema_validation':'NOT_RUN','iam_simulation':'NOT_RUN'}
    marker=target/'manifest.json';encoded=_json(manifest)
    try:
        _write_new(marker,encoded)
        if marker.read_bytes()!=encoded:raise OSError('review manifest changed before completion')
        verify_files()
    except BaseException:
        # Remove only this operation's new completion marker, never payloads or
        # an existing pack. Partial files remain available for investigation.
        marker.unlink(missing_ok=True)
        raise
    return manifest


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON field')
        result[key]=value
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description='Prepare an offline deployment review draft; never applies AWS changes.')
    parser.add_argument('--config',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        with Path(args.config).open('rb') as stream:raw=stream.read(65537)
        if len(raw)>65536:raise ValueError('bounded plan required')
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,
            parse_constant=lambda _:(_ for _ in ()).throw(ValueError('finite JSON required')))
        manifest=write_pack(data,args.output)
        print(json.dumps({'status':manifest['status'],'files':len(manifest['files'])+1,'deploy_authorized':False,'beta_decision':'NO_GO'}))
        return 0
    except (OSError,ValueError,TypeError,KeyError,RecursionError):
        print('Deployment review preparation failed. No AWS action was performed.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
