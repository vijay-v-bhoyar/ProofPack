"""Private first-install prepare/commit; never restore, enable or erase authority."""
from copy import deepcopy
from dataclasses import asdict,dataclass
import hashlib
import json
import re
from time import monotonic_ns,time_ns
from uuid import UUID,uuid5

from botocore.exceptions import BotoCoreError,ClientError

from proofpack.auth.service import AccessService
from proofpack.evidence.initial_release import EnrollmentIntent,ROLE
from proofpack.evidence.journal_anchors import ZERO,_json
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits,GATE,REGISTRY
from proofpack.evidence.repository import DynamoRepository,Key,Write
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.evidence.restore_fence import RestoreFenceConfig
from proofpack.runtime.control import RuntimeControl,RUNTIME,DATA,ALLOCATION
from proofpack.runtime.installation import verify_installation


def _sha(value):return hashlib.sha256(_json(value).encode()).hexdigest()


def _configuration(loaded,intent):
    def encode(value):
        if type(value) is bytes:return {'private_bytes_sha256':hashlib.sha256(value).hexdigest()}
        raise ValueError('unsupported first-install configuration')
    return hashlib.sha256(json.dumps([asdict(loaded),asdict(intent)],sort_keys=True,separators=(',',':'),default=encode,allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class _Plan:
    release_sha256:str
    encoded_items:str
    encoded_reads:str
    encoded_expected:str


def _plan(loaded,intent):
    from proofpack.runtime.host import LoadedConfiguration,enrollment_configuration_sha256
    from proofpack.runtime.composition import ApplicationConfig
    if (type(loaded) is not LoadedConfiguration or type(loaded.config) is not ApplicationConfig
            or type(intent) is not EnrollmentIntent):raise ValueError('original typed first-install inputs required')
    EnrollmentIntent(**asdict(intent));config=loaded.config;fence=config.restore_fence
    if (type(fence) is not RestoreFenceConfig or fence.release_kind!='initial-data-release'
            or config.local_database_endpoint is not None or config.environment not in {'beta','synthetic_demo'}
            or config.metadata_admission is None or config.operation_purpose_id is not None
            or type(loaded.enrollment_configuration_sha256) is not str
            or enrollment_configuration_sha256(config)!=loaded.enrollment_configuration_sha256
            or fence.initial_configuration_sha256!=loaded.enrollment_configuration_sha256
            or type(loaded.configuration_sha256) is not str or re.fullmatch('[a-f0-9]{64}',loaded.configuration_sha256) is None
            or ROLE.fullmatch(intent.role_arn).group(1)!=config.objects.account_id):
        raise ValueError('exact fresh metadata-only host configuration and named account role required')
    root={'schema':1,'kind':'journal_root','genesis':fence.genesis_sha256,'sequence':0,'previous':ZERO}
    root_sha=_sha(['sealed-journal-history/v1',config.auth.deployment,fence.journal_arn,root])
    if fence.checkpoint.sequence!=0 or fence.checkpoint.digest!=root_sha:raise ValueError('exact fresh genesis checkpoint required')
    head={'schema':1,'kind':'journal_head','genesis':fence.genesis_sha256,'sequence':0,'digest':root_sha}
    tables={'state':config.state_table,'events':config.events_table}
    generation=_sha(['initial-runtime-generation/v1',loaded.enrollment_configuration_sha256,asdict(intent)])
    at=intent.created_at_ms
    runtime={'runtime_epoch':1,'control_version':1,'inspection_enabled':False,'instance_id':intent.instance_id,
        'artifact_sha256':config.artifact_sha256,'controls_sha256':config.controls_sha256,'started_at_ms':at,
        'environment':config.environment,'enable_receipt_id':None,'enable_expires_at_ms':None,'reason':'runtime_started'}
    marker={'runtime_epoch':1,'artifact_sha256':config.artifact_sha256,'controls_sha256':config.controls_sha256,
        'environment':config.environment,'startup_schema_version':2,'restore_generation_sha256':generation,
        'previous_data_epoch':0,'data_epoch':1}
    event=Key('events','runtime#'+str(uuid5(UUID(intent.operation_id),'initial-runtime-started/v1')))
    writes,checks=prepare_linked(config.auth.deployment,'runtime_started',(
        Write(RUNTIME,None,runtime),Write(Key('state','runtime-start#'+intent.instance_id),None,marker),
        Write(event,None,{'kind':'runtime_started','instance_id':intent.instance_id,'runtime_epoch':1,'control_version':1,'at_ms':at}),
        Write(ALLOCATION,None,{'slots':{}}),Write(DATA,None,{'epoch':1,'changed_at_ms':at})),())
    if checks:raise ValueError('fresh bootstrap cannot inherit prior rows')
    # Use the real coordinator's configuration identity, not a parallel hash recipe.
    repository=DynamoRepository(None,deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table)
    access=AccessService(repository,config.auth,clock_ms=lambda:at)
    control=RuntimeControl(access,instance_id=intent.instance_id,artifact_sha256=config.artifact_sha256,
        controls_sha256=config.controls_sha256,environment=config.environment)
    bounds=config.metadata_admission
    admission=PersistentAdmission(control,limits=AdmissionLimits(bounds.max_active,bounds.max_lease_ms),clock_ms=lambda:at)
    writes+= (Write(GATE,None,{'schema_version':1,'epoch':1,'phase':'OPEN','configuration_sha256':admission._configuration,
        'enrollment_sha256':bounds.enrollment_sha256,'created_at_ms':at}),
        Write(REGISTRY,None,{'schema_version':1,'gate_epoch':1,'active':{}}))
    business=[]
    for write in writes:
        item={**repository.key(write.key),'revision':{'N':'1'},'data':repository.serialize.serialize(write.data)}
        business.append({'Put':{'TableName':tables[write.key.table],'Item':item,
            'ConditionExpression':'attribute_not_exists(#pk)','ExpressionAttributeNames':{'#pk':'pk'}}})
    empty=_sha(['empty-first-install/v1',config.auth.deployment,tuple(sorted(tables.items())),fence.target_table_ids,
        fence.journal_arn,fence.journal_table_id])
    body={'schema_version':1,'kind':'initial-data-release','deployment':config.auth.deployment,'target_tables':tables,
        'target_table_ids':dict(fence.target_table_ids),'journal_arn':fence.journal_arn,'journal_table_id':fence.journal_table_id,
        'genesis_sha256':fence.genesis_sha256,'checkpoint':asdict(fence.checkpoint),'artifact_sha256':config.artifact_sha256,
        'writer_protocol':'metadata-payload-erasure/v1','runtime_generation_sha256':generation,
        'controls_sha256':config.controls_sha256,'configuration_sha256':loaded.enrollment_configuration_sha256,
        'empty_inventory_sha256':empty,'enrollment_sha256':bounds.enrollment_sha256,
        'admission_configuration_sha256':admission._configuration,'initial_state_sha256':_sha(business),
        'operation_id':intent.operation_id,'instance_id':intent.instance_id,'enrollment_role_arn':intent.role_arn,
        'created_at_ms':intent.created_at_ms,'expires_at_ms':intent.expires_at_ms}
    release_sha=_sha(['initial-data-release/v1',config.auth.deployment,fence.journal_arn,body])
    target_sha=_sha(['restored-target/v1',config.auth.deployment,tuple(sorted(tables.items())),fence.target_table_ids,fence.journal_arn])
    protected=[]
    for name,value,digest in [('anchor-root',root,root_sha),('anchor-head',head,_sha(['sealed-journal-history/v1',config.auth.deployment,fence.journal_arn,head])),
            ('restore-admission#'+target_sha,body,release_sha)]:
        protected.append({'Put':{'TableName':fence.journal_table,'Item':{'pk':{'S':'deployment#'+config.auth.deployment},
            'sk':{'S':name},'body':{'S':_json(value)},'sha256':{'S':digest}},
            'ConditionExpression':'attribute_not_exists(#pk)','ExpressionAttributeNames':{'#pk':'pk'}}})
    original=protected+[entry for entry in business if entry['Put']['Item']['sk']['S'] in {'runtime-start#'+intent.instance_id,event.resource}]
    reads=[{'Get':{'TableName':entry['Put']['TableName'],'Key':{k:entry['Put']['Item'][k] for k in ('pk','sk')}}} for entry in original]
    items=protected+business
    if len(items)!=10 or len(original)!=5 or len(_json(items).encode())>131072:raise ValueError('bounded exact bootstrap transaction required')
    return _Plan(release_sha,_json(items),_json(reads),_json([entry['Put']['Item'] for entry in original]))


class _Operation:
    def __init__(self,loaded,intent,clients,plan,clock,tick):
        self.loaded,self.intent,self.clients,self.plan=loaded,intent,clients,plan
        self.clock,self.tick=clock,tick;self.calls=0;self.last_tick=-1;self.last_wall=-1;self.deadline=None
        self.original=(loaded,intent,clients,clock,tick)
        self.configuration=self._configuration();self.client_ids=(clients.dynamodb,clients.s3,clients.sts)
        self.check()

    def _configuration(self):
        return _configuration(self.loaded,self.intent)

    def check(self):
        now=self.tick();wall=self.clock()
        if self.deadline is None:
            if type(now) is not int or not 0<=now<2**63-1:raise ValueError('original monotonic enrollment clock required')
            self.deadline=now+self.loaded.config.metadata_admission.http_lease_ms*1000000
        if (type(now) is not int or not self.last_tick<=now<self.deadline<2**63-1
                or type(wall) is not int or not max(1,self.last_wall)<=wall<2**63-1):
            raise ValueError('original enrollment deadline or clock held')
        self.last_tick=now;self.last_wall=wall
        from proofpack.runtime.host import LoadedConfiguration
        from proofpack.runtime.composition import _client
        if (any(a is not b for a,b in zip((self.loaded,self.intent,self.clients,self.clock,self.tick),self.original))
                or self._configuration()!=self.configuration
                or any(a is not b for a,b in zip((self.clients.dynamodb,self.clients.s3,self.clients.sts),self.client_ids))
                or type(self.loaded) is not LoadedConfiguration):raise ValueError('original enrollment dependencies changed')
        region=self.loaded.config.objects.region
        for service,client in zip(('dynamodb','s3','sts'),self.client_ids):
            _client(client,service,region,'https://'+service+'.'+region+'.amazonaws.com')
        return wall

    def fresh(self):
        wall=self.check()
        if not self.intent.created_at_ms<=wall<self.intent.expires_at_ms:raise ValueError('original first-install review expired or future')

    def call(self,name,**kwargs):
        wall=self.check()
        if name=='transact_write_items' and not self.intent.created_at_ms<=wall<self.intent.expires_at_ms:
            raise ValueError('original first-install review expired at commit')
        if self.calls>=32:raise ValueError('original enrollment SDK allowance exhausted')
        self.calls+=1
        client=self.clients.sts if name=='get_caller_identity' else self.clients.dynamodb
        value=getattr(client,name)(**kwargs);self.check();return value

    def target(self):
        config=self.loaded.config;fence=config.restore_fence
        identity=self.call('get_caller_identity');match=ROLE.fullmatch(self.intent.role_arn)
        prefix='arn:aws:sts::'+config.objects.account_id+':assumed-role/'+match.group(2)+'/'
        if (type(identity) is not dict or identity.get('Account')!=config.objects.account_id
                or type(identity.get('Arn')) is not str or not identity['Arn'].startswith(prefix)
                or re.fullmatch(r'[A-Za-z0-9_+=,.@-]{2,64}',identity['Arn'][len(prefix):]) is None):
            raise ValueError('named enrollment role identity required')
        ids=dict(fence.target_table_ids);ids['journal']=fence.journal_table_id
        for role,table in (('state',config.state_table),('events',config.events_table),('journal',fence.journal_table)):
            value=self.call('describe_table',TableName=table)
            row=value.get('Table') if type(value) is dict else None
            if (type(row) is not dict or row.get('TableName')!=table or row.get('TableId')!=ids[role]
                    or row.get('TableStatus')!='ACTIVE'
                    or row.get('TableArn')!='arn:aws:dynamodb:'+config.objects.region+':'+config.objects.account_id+':table/'+table
                    or row.get('KeySchema')!=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}]
                    or sorted(row.get('AttributeDefinitions',[]),key=lambda x:str(x.get('AttributeName','')))!=[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}]):
                raise ValueError('exact active first-install physical target required')
            ttl=self.call('describe_time_to_live',TableName=table)
            if type(ttl) is not dict or ttl.get('TimeToLiveDescription')!={'TimeToLiveStatus':'DISABLED'}:
                raise ValueError('disabled target TTL required')

    def empty(self):
        config=self.loaded.config
        for table in (config.state_table,config.events_table,config.restore_fence.journal_table):
            value=self.call('scan',TableName=table,ConsistentRead=True,Limit=1)
            if (type(value) is not dict or value.get('Items')!=[] or type(value.get('Count')) is not int or value['Count']!=0
                    or type(value.get('ScannedCount')) is not int or value['ScannedCount']!=0
                    or value.get('LastEvaluatedKey') not in (None,{})):
                raise ValueError('complete quarantined empty tables required')

    def existing(self):
        value=self.call('transact_get_items',TransactItems=json.loads(self.plan.encoded_reads))
        rows=value.get('Responses') if type(value) is dict else None
        if type(rows) is not list or len(rows)!=5:raise ValueError('complete original enrollment readback required')
        if rows==[{}]*5:return False
        if rows!=[{'Item':item} for item in json.loads(self.plan.encoded_expected)]:
            raise ValueError('original protected enrollment and immutable seed records required')
        return True


def run_enrollment(loaded,intent,*,commit,session_factory=None,clock_ms=None,tick_ns=None):
    """Real SDK writer; commit selection is not a substitute for approved digest/role."""
    from proofpack.runtime.host import HostConfigurationError,_host_clients,_close_host_clients
    clients=None;operation=None
    clock=(lambda:time_ns()//1000000) if clock_ms is None else clock_ms
    tick=monotonic_ns if tick_ns is None else tick_ns
    try:
        if type(commit) is not bool or not callable(clock) or not callable(tick):raise ValueError('exact command and clock inputs required')
        plan=_plan(loaded,intent)
        original_configuration=_configuration(loaded,intent)
        if commit and plan.release_sha256!=loaded.config.restore_fence.release_sha256:raise ValueError('reviewed exact release digest required')
        # Pin the overall allowance before filesystem or credential discovery.
        started=tick();wall=clock()
        if type(started) is not int or not 0<=started<2**63-1 or type(wall) is not int or not 1<=wall<2**63-1:
            raise ValueError('original enrollment clock required')
        verify_installation(loaded.config.installation,loaded.config.artifact_sha256)
        before_discovery=tick();before_wall=clock()
        if (type(before_discovery) is not int or not started<=before_discovery<started+loaded.config.metadata_admission.http_lease_ms*1000000
                or type(before_wall) is not int or not wall<=before_wall<2**63-1
                or _configuration(loaded,intent)!=original_configuration):raise ValueError('original precredential enrollment bounds changed')
        clients=_host_clients(loaded,session_factory)
        operation=_Operation(loaded,intent,clients,plan,clock,tick)
        operation.deadline=started+loaded.config.metadata_admission.http_lease_ms*1000000
        if (operation.last_tick<before_discovery or operation.last_wall<before_wall or operation.configuration!=original_configuration):
            raise ValueError('enrollment clocks or configuration changed during initialization')
        operation.check();operation.target()
        exists=operation.existing()
        if exists:
            if not commit:raise ValueError('preparation cannot adopt a prior enrollment')
            operation.target()
            if not operation.existing():raise ValueError('original enrollment disappeared')
        else:
            operation.fresh();operation.empty();operation.target();operation.empty();operation.fresh()
            verify_installation(loaded.config.installation,loaded.config.artifact_sha256)
            operation.fresh()
            if commit:
                try:
                    operation.call('transact_write_items',TransactItems=json.loads(plan.encoded_items),ClientRequestToken=intent.operation_id)
                except (ClientError,BotoCoreError):
                    pass  # One effect attempt only; reconcile its original immutable rows.
                if not operation.existing():raise ValueError('first-install commit remains unconfirmed')
                operation.target()
                if not operation.existing():raise ValueError('first-install commit readback changed')
        operation.check()
        result={'status':'ENROLLMENT_COMMITTED' if commit else 'ENROLLMENT_PREPARED','operation_id':intent.operation_id,
            'instance_id':intent.instance_id,'release_sha256':plan.release_sha256,
            'configuration_sha256':loaded.configuration_sha256,'enrollment_configuration_sha256':loaded.enrollment_configuration_sha256,
            'authority':'none','readiness_approved':False,'inspection_enablement_granted':False,'request_fulfilled':False}
    except Exception:
        raise HostConfigurationError('First-install enrollment is held or its outcome is unknown; no readiness or recovery authority was granted.') from None
    finally:
        if clients is not None and not _close_host_clients((clients.dynamodb,clients.s3,clients.sts)):
            raise HostConfigurationError('First-install enrollment is held or its outcome is unknown; no readiness or recovery authority was granted.') from None
    try:
        operation.check()
        if not commit:operation.fresh()
    except Exception:
        raise HostConfigurationError('First-install enrollment is held or its outcome is unknown; no readiness or recovery authority was granted.') from None
    return result
