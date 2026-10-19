"""Atomic policy transitions; no HTTP installation or qualification writer.

The server qualification reader is a required, separately implemented trust
boundary. A diagnostic/preparation report cannot be supplied in its place.
"""
from dataclasses import asdict,dataclass
import json,time
from typing import Callable,Literal
from uuid import uuid4
from pydantic import Field,model_validator

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.repository import Key,Row,Write,StoreConflict,StoreUnavailable
from proofpack.planner.candidates import PolicyCandidates,PolicyDraft
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.planner.rollback import RollbackTarget,intact_policy_provenance
from proofpack.recipes.models import Contract
from proofpack.review.labels import UUIDText
from proofpack.runtime.control import DATA,integer,sha,uuid
from proofpack.stations.service import POLICY


def qualification_key(ident):return Key('state','policy-qualification#'+uuid(ident))
def qualification_head(ident,revision):return Key('state','policy-qualification-current#'+uuid(ident)+'#'+str(integer(revision)))
def activation_key(ident):return Key('state','policy-activation#'+uuid(ident))


@dataclass(frozen=True)
class ActivationConfig:
    writes_per_minute:int
    reads_per_minute:int
    review_window_ms:int
    max_qualification_rows:int
    qualification_registry_sha256:str

    def __post_init__(self):
        for value,low,high in ((self.writes_per_minute,1,20),(self.reads_per_minute,1,120),
                (self.review_window_ms,1000,60000),(self.max_qualification_rows,1,80)):
            if type(value) is not int or not low<=value<=high:raise ValueError('explicit bounded activation controls required')
        sha(self.qualification_registry_sha256)


class ActivationRequest(Contract):
    operation:Literal['bootstrap','promote','rollback']
    policy_id:UUIDText
    policy_revision:int=Field(ge=1,le=1000)
    policy_state_version:int=Field(ge=1,le=9007199254740991)
    policy_revision_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    qualification_id:UUIDText
    qualification_report_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    expected_active_version:int=Field(ge=0,le=9007199254740991)
    expected_control_version:int=Field(ge=1,le=9007199254740991)
    predecessor_activation_id:UUIDText|None=None
    invalidation_acknowledged:bool

    @model_validator(mode='after')
    def coherent(self):
        if self.invalidation_acknowledged is not True:raise ValueError('explicit invalidation acknowledgment required')
        if (self.operation=='bootstrap')!=(self.expected_active_version==0):raise ValueError('bootstrap alone requires an absent active head')
        if (self.operation=='rollback')!=(self.predecessor_activation_id is not None):raise ValueError('rollback alone names the exact predecessor')
        return self


@dataclass(frozen=True)
class QualifiedPolicySnapshot:
    qualification:Row
    dependencies:tuple[Row,...]
    expires_at_ms:int
    final_guard:Callable[[],None]


class ActivationLimited(RuntimeError):pass


class PolicyActivations:
    def __init__(self,policies,config,qualification_reader=None,*,tick_ns=None):
        if not isinstance(policies,PolicyCandidates) or not isinstance(config,ActivationConfig):raise ValueError('shared policy service and explicit activation controls required')
        if qualification_reader is not None and (qualification_reader.policies is not policies
                or qualification_reader.access is not policies.access or qualification_reader.runtime is not policies.runtime
                or qualification_reader.repository is not policies.repository or not callable(qualification_reader.read_current)):
            raise ValueError('qualification reader must share exact policy authority')
        self.policies=policies;self.access=policies.access;self.repository=policies.repository;self.runtime=policies.runtime
        self.config=config;self.reader=qualification_reader;self.tick=tick_ns or time.monotonic_ns
        self.configuration=digest(asdict(config))

    def _owner(self,actor):
        value=self.access._fresh(actor,Role.OWNER);self.access._recent_mfa(value);return value

    @staticmethod
    def _merge(rows):
        result={}
        for row in rows:
            if row is None:continue
            if not isinstance(row,Row) or type(row.revision) is not int or row.revision<1:raise StoreUnavailable('intact policy authority rows required')
            if row.key in result and result[row.key]!=row:raise StoreConflict('policy authority changed across snapshots')
            result[row.key]=Row(row.key,row.revision,json.loads(canonical(row.data)))
        return result

    def _quota(self,actor,kind):
        key=Key('state','policy-activation-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('activation quota clock reversed')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        if count>=(self.config.writes_per_minute if kind=='write' else self.config.reads_per_minute):raise ActivationLimited('policy activation allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def _intact(self,row,kind):
        return intact_policy_provenance(self.policies,row,kind)

    def _qualified(self,request,record,runtime,data,active):
        if self.reader is None:raise StoreUnavailable('trusted qualification reader is not configured')
        result=self.reader.read_current(request.qualification_id)
        if (not isinstance(result,QualifiedPolicySnapshot) or not isinstance(result.dependencies,tuple)
                or len(result.dependencies)>self.config.max_qualification_rows or type(result.expires_at_ms) is not int or not callable(result.final_guard)):
            raise StoreUnavailable('complete bounded trusted qualification snapshot required')
        checks=self._merge((result.qualification,*result.dependencies));report=checks.get(qualification_key(request.qualification_id))
        if len(checks)>self.config.max_qualification_rows:raise StoreUnavailable('complete qualification dependency capacity exceeded')
        latest=checks.get(qualification_head(request.policy_id,request.policy_revision))
        target=report.data.get('rollback_target') if report is not None else None
        if request.operation=='rollback':
            try:target=RollbackTarget.model_validate(target)
            except ValueError as exc:raise StoreConflict('fresh exact rollback-only qualification required') from exc
            if (active is None or target.active_version!=request.expected_active_version
                    or target.activation_id!=active.data['activation_id']
                    or target.predecessor_activation_id!=request.predecessor_activation_id):
                raise StoreConflict('qualification names a different rollback anchor')
        elif target is not None:raise StoreConflict('rollback-only qualification cannot promote or bootstrap')
        try:
            value=report.data
            if (report.revision!=1 or integer(value['schema_version'])!=1 or value['runner']!='policy_qualification_v1' or value['status']!='qualified'
                    or value['scope']!='synthetic_demo_only' or value['id']!=request.qualification_id
                    or value['sha256']!=request.qualification_report_sha256 or digest({k:v for k,v in value.items() if k!='sha256'})!=value['sha256']
                    or value['policy_id']!=request.policy_id or integer(value['policy_revision'])!=request.policy_revision
                    or value['policy_revision_sha256']!=record.data['sha256'] or value['behavior_sha256']!=record.data['behavior_sha256']
                    or value['installed_sha256']!=self.policies.installed_sha256 or value['registry_sha256']!=self.config.qualification_registry_sha256
                    or value['environment']!=self.runtime.environment or value['artifact_sha256']!=self.runtime.artifact_sha256 or value['controls_sha256']!=self.runtime.controls_sha256
                    or integer(value['runtime_epoch'])!=integer(runtime.data['runtime_epoch']) or integer(value['control_version'])!=integer(runtime.data['control_version'])
                    or integer(value['data_epoch'])!=integer(data.data['epoch']) or not integer(value['issued_at_ms'])<=self.access.now()<integer(value['expires_at_ms'])
                    or not 0<integer(value['required_case_count'])==integer(value['completed_case_count']) or integer(value['failed_case_count'])!=0 or integer(value['unknown_case_count'])!=0
                    or latest.data['qualification_id']!=request.qualification_id or latest.data['report_sha256']!=value['sha256'] or latest.data['status']!='qualified'
                    or result.expires_at_ms>integer(value['expires_at_ms'])):raise ValueError()
            sha(value['preparation_report_sha256']);sha(value['golden_report_sha256'])
        except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('current complete matching trusted qualification required') from exc
        return result,checks

    def transition(self,actor,*,request,idempotency_key):
        actor=self._owner(actor)
        if not isinstance(request,ActivationRequest):raise ValueError('strict policy activation request required')
        operation='policy-activation';idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,request.model_dump(mode='json'))
        if prior is not None:self._owner(actor);return json.loads(canonical(prior.data['result']))
        if self.runtime.environment!='synthetic_demo':raise Denied('beta/physical activation requires the genuine evidence path')
        started=self.tick()
        if type(started) is not int or started<0:raise StoreUnavailable('trusted activation monotonic clock required')
        configuration=self.configuration;policy_binding=json.loads(canonical(self.policies._binding()));reader=self.reader
        roots=self.repository.snapshot((RUNTIME,DATA,POLICY));runtime,data,active=(roots[k] for k in (RUNTIME,DATA,POLICY))
        if not self.runtime.matches(runtime) or data is None:raise StoreUnavailable('current runtime and data authority required')
        if integer(runtime.data['control_version'])!=request.expected_control_version:raise StoreConflict('runtime control changed')
        if (active is None)!=(request.operation=='bootstrap') or (active is not None and active.revision!=request.expected_active_version):raise StoreConflict('exact active policy head required')
        active_event=None
        if active is not None:
            self._intact(active,'active_policy');key=activation_key(active.data['activation_id']);active_event=self.repository.snapshot((key,))[key];self._intact(active_event,'policy_activation')
            if (active_event.data['sha256']!=active.data['activation_sha256']
                    or any(active_event.data[k]!=v for k,v in active.data.items() if k not in {'kind','status','mode','activation_sha256','sha256'})):
                raise StoreUnavailable('active policy differs from its immutable activation')
        head,record,candidate_rows=self.policies._load(request.policy_id,request.policy_revision)
        if (head.revision!=request.policy_state_version or record.data['sha256']!=request.policy_revision_sha256 or head.data['binding']!=self.policies._binding()
                or (request.operation!='rollback' and integer(head.data['latest_revision'])!=request.policy_revision)):raise StoreConflict('exact current candidate revision required')
        spec=PolicyDraft.model_validate_json(canonical(record.data['spec']));extra=[] if active_event is None else [active_event]
        if request.operation=='bootstrap' and spec.priority!=DEFAULT_PRIORITY:raise Denied('bootstrap requires the installed default definition')
        if request.operation=='rollback':
            if active.data['predecessor_activation_id']!=request.predecessor_activation_id:raise StoreConflict('exact predecessor rollback required')
            target=self.repository.snapshot((activation_key(request.predecessor_activation_id),))[activation_key(request.predecessor_activation_id)];self._intact(target,'policy_activation')
            if (target.data['policy_id']!=request.policy_id or integer(target.data['policy_revision'])!=request.policy_revision or target.data['policy_revision_sha256']!=request.policy_revision_sha256):raise StoreConflict('rollback target differs from predecessor')
            extra.append(target)
        qualified,qrows=self._qualified(request,record,runtime,data,active)
        deadline=min(qualified.expires_at_ms,integer(actor.session.data['expires_at_ms']),self.access.now()+self.config.review_window_ms)
        checks=self._merge((*roots.values(),*candidate_rows,*qrows.values(),*actor.rows,*extra))
        if len(checks)>90:raise StoreUnavailable('complete activation dependency capacity exceeded')
        def gate():
            qualified.final_guard();current=self._owner(actor)
            if (self.configuration!=configuration or digest(asdict(self.config))!=configuration or self.reader is not reader
                    or self.policies._binding()!=policy_binding or not self.runtime.matches(runtime)):
                raise StoreConflict('activation implementation/configuration authority changed')
            expected=self._merge((*checks.values(),*current.rows));fresh=self.repository.snapshot(tuple(expected))
            if any(fresh[k]!=v for k,v in expected.items()):raise StoreConflict('activation authority changed before commit')
            self._owner(current)
            current_tick=self.tick()
            if type(current_tick) is not int or not 0<=current_tick-started<self.config.review_window_ms*1000000 or self.access.now()>=deadline:raise StoreUnavailable('original activation window expired')
        gate();ident=str(uuid4());control=integer(runtime.data['control_version'])+1
        common={'schema_version':1,'activation_id':ident,'policy_id':request.policy_id,'policy_revision':request.policy_revision,'policy_revision_sha256':record.data['sha256'],
            'policy_state_version':request.policy_state_version,
            'behavior_sha256':record.data['behavior_sha256'],'definition':json.loads(canonical(record.data['spec'])),'qualification_id':request.qualification_id,
            'qualification_report_sha256':request.qualification_report_sha256,'registry_sha256':self.config.qualification_registry_sha256,
            'environment':self.runtime.environment,'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,
            'activation_configuration_sha256':configuration,
            'installed_sha256':self.policies.installed_sha256,'runtime_epoch':integer(runtime.data['runtime_epoch']),'control_version':control,'data_epoch':integer(data.data['epoch']),
            'issued_at_ms':self.access.now(),'expires_at_ms':qualified.expires_at_ms,'predecessor_activation_id':None if active is None else active.data['activation_id']}
        event={**common,'kind':'policy_activation','operation':request.operation,'owner_id':actor.member.data['id'],'owner_access_version':integer(actor.member.data['access_version']),
            'owner_session_id':actor.session.data['id'],'previous_active_version':request.expected_active_version,'previous_control_version':request.expected_control_version}
        event['sha256']=digest(event)
        live={**common,'kind':'active_policy','status':'approved','mode':'deterministic_policy','activation_sha256':event['sha256']};live['sha256']=digest(live)
        disabled={**runtime.data,**{k:None for k in runtime.data if k.startswith('enable_')},'control_version':control,'inspection_enabled':False,'reason':'policy_'+request.operation}
        result={'transition_id':ident,'operation':request.operation,'policy_id':request.policy_id,'policy_revision':request.policy_revision,
            'active_version':request.expected_active_version+1,'control_version':control,'activation_sha256':event['sha256'],'historical_receipt':True,'inspection_enablement_granted':False}
        writes=(Write(POLICY,None if active is None else active.revision,live),Write(activation_key(ident),None,event),Write(RUNTIME,runtime.revision,disabled),self._quota(actor,'write'))
        if len({w.key for w in writes}|set(checks)|{idem})+1>100:raise StoreUnavailable('complete activation transaction exceeds capacity')
        value=self.access._record(actor,operation,idem,body_hash,result,writes,tuple(checks.values()),before_commit=gate,
            event_details={'transition_id':ident,'operation':request.operation,'policy_id':request.policy_id,'control_version':control,'inspections_disabled':True})
        self._owner(actor);return json.loads(canonical(value))

    def current(self,actor,reader,*,owner_view=False,policy_id=None,revision=None):
        from proofpack.planner.active import ActivePolicies
        if type(owner_view) is not bool or type(reader) is not ActivePolicies or reader.activations is not self:raise ValueError('shared trusted active reader and explicit summary scope required')
        actor=self._owner(actor) if owner_view else self.access._fresh(actor)
        if policy_id is not None:policy_id=uuid(policy_id)
        if revision is not None and (policy_id is None or type(revision) is not int or not 1<=revision<=1000):
            raise ValueError('exact approved policy revision required')
        binding=(digest(asdict(self.config)),self.configuration,self.policies._binding(),self.reader,reader)
        roots=self.repository.snapshot((POLICY,RUNTIME,DATA));head=roots[POLICY];runtime=roots[RUNTIME]
        if not self.runtime.matches(runtime) or roots[DATA] is None:raise StoreUnavailable('current active-policy metadata runtime required')
        if head is not None:self._intact(head,'active_policy')
        if policy_id is not None and (head is None or head.data['policy_id']!=policy_id
                or (revision is not None and integer(head.data['policy_revision'])!=revision)):
            raise ResourceUnavailable('approved policy unavailable')
        expected=self._merge((*roots.values(),*actor.rows));snapshot=None
        if head is not None:
            try:
                snapshot=reader.read_current()
                if snapshot.policy!=head:raise StoreConflict('active head changed during summary')
                expected=self._merge((*expected.values(),*snapshot.dependencies))
            except (Denied,StoreConflict,StoreUnavailable,ResourceUnavailable):snapshot=None
        if len(expected)>95:raise StoreUnavailable('complete active summary dependencies exceed capacity')
        deadline=min(integer(actor.session.data['expires_at_ms']),self.access.now()+self.config.review_window_ms)
        if snapshot is not None:deadline=min(deadline,snapshot.expires_at_ms)
        def final_read():
            self._owner(actor) if owner_view else self.access._fresh(actor)
            if self.access.now()>=deadline:raise StoreUnavailable('active-policy read expired')
        self.access._commit_linked('active_policy_access',(self._quota(actor,'read'),Write(Key('events','active-policy-access#'+str(uuid4())),None,
            {'user_id':actor.member.data['id'],'scope':'owner' if owner_view else 'summary','at_ms':self.access.now(),
             'selected_policy_id':policy_id,'selected_revision':revision})),tuple(expected.values()),before_commit=final_read)
        fresh=self._owner(actor) if owner_view else self.access._fresh(actor)
        if snapshot is not None:snapshot.final_guard()
        expected=self._merge((*expected.values(),*fresh.rows));values=self.repository.snapshot(tuple(expected))
        if (any(values[k]!=v for k,v in expected.items()) or reader.activations is not self
                or binding!=(digest(asdict(self.config)),self.configuration,self.policies._binding(),self.reader,reader)):
            raise StoreConflict('active-policy metadata changed during final delivery')
        if self.access.now()>=deadline:raise StoreUnavailable('active-policy summary delivery expired')
        policy=None if head is None else {'id':head.data['policy_id'],'revision':integer(head.data['policy_revision']),
            'revision_sha256':head.data['policy_revision_sha256'],'behavior_sha256':head.data['behavior_sha256'],
            'name':head.data['definition']['name'],'mode':'deterministic_policy'}
        result={'policy':policy,'active_version':0 if head is None else head.revision,'current':snapshot is not None,
            'current_qualification_verified':snapshot is not None,'remaining_ms':0 if snapshot is None else max(0,deadline-self.access.now()),
            'historical_head':head is not None,'inspection_enablement_granted':False,'scope':'owner' if owner_view else 'summary'}
        if owner_view:
            result.update(control_version=integer(runtime.data['control_version']),inspection_enabled=runtime.data['inspection_enabled'],
                activation_id=None if head is None else head.data['activation_id'],activation_sha256=None if head is None else head.data['activation_sha256'],
                predecessor_activation_id=None if head is None else head.data['predecessor_activation_id'],
                qualification_id=None if head is None else head.data['qualification_id'],qualification_report_sha256=None if head is None else head.data['qualification_report_sha256'])
        return result

    def receipt(self,actor,ident):
        actor=self._owner(actor);key=activation_key(ident);row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('policy transition unavailable')
        self._intact(row,'policy_activation');quota=self._quota(actor,'read')
        self.access._commit((quota,),tuple(self._merge((row,*actor.rows)).values()))
        current=self._owner(actor);expected=self._merge((row,*actor.rows,*current.rows));fresh=self.repository.snapshot(tuple(expected))
        if any(fresh[k]!=v for k,v in expected.items()):raise StoreConflict('transition metadata changed')
        self._owner(current)
        return {'transition_id':ident,'operation':row.data['operation'],'policy_id':row.data['policy_id'],'policy_revision':integer(row.data['policy_revision']),
            'policy_revision_sha256':row.data['policy_revision_sha256'],'policy_state_version':None if 'policy_state_version' not in row.data else integer(row.data['policy_state_version']),
            'qualification_id':row.data['qualification_id'],'qualification_report_sha256':row.data['qualification_report_sha256'],
            'previous_active_version':integer(row.data['previous_active_version']),'active_version':integer(row.data['previous_active_version'])+1,
            'previous_control_version':integer(row.data['previous_control_version']),'predecessor_activation_id':row.data['predecessor_activation_id'],
            'control_version':integer(row.data['control_version']),'activation_sha256':row.data['sha256'],'historical_receipt':True,'current_qualification_verified':False,'inspection_enablement_granted':False}
