"""Genuine bounded synthetic-demo qualification, never physical/beta approval."""
from dataclasses import asdict,dataclass
import hashlib,json,time
from typing import Literal
from uuid import uuid4
from pathlib import Path
from collections import Counter
from contextlib import contextmanager
from threading import RLock
from pydantic import Field,model_validator
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.repository import Key,Row,Write,StoreConflict,StoreUnavailable
from proofpack.evidence.erasure import job_key
from proofpack.evidence.job_authority import issue,resolve
from proofpack.planner.candidates import PolicyCandidates,PolicyDraft
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.planner.consumption import consumption
from proofpack.planner.rollback import RollbackTarget,rollback_checks
from proofpack.planner import contract_registry
from proofpack.planner.contract_suite import PolicyContractSuite,ContractSuiteConfig,implementation_sha256
from proofpack.planner.activation import QualifiedPolicySnapshot,qualification_key,qualification_head
from proofpack.recipes.models import Contract
from proofpack.review.labels import UUIDText
from proofpack.review.evaluation_models import EvaluationConfig,EvaluationLimited
from proofpack.review import policy_golden
from proofpack.review.manifests import Consequence
from proofpack.runtime.control import DATA,integer,uuid
from proofpack.vision.registry import WorkerRegistry

KIND='policy_qualification'
FLAGS={'physical_truth_verified':False,'independent_benchmark_qualified':False,'operator_effort_measured':False,'beta_eligible':False}
def entry_key(ident,index):return Key('state','policy-qualification-entry#'+uuid(ident)+'#'+str(integer(index)).zfill(4))
def software_key(ident):return Key('state','policy-qualification-software#'+uuid(ident))
def software_page_key(ident,index):return Key('state','policy-qualification-software-page#'+uuid(ident)+'#'+str(integer(index)))
def golden_key(ident):return Key('state','policy-qualification-golden#'+uuid(ident))


@dataclass(frozen=True)
class QualificationConfig:
    jobs:EvaluationConfig
    max_reserved_cases:int
    golden_case_ms:int
    def __post_init__(self):
        if (not isinstance(self.jobs,EvaluationConfig) or type(self.max_reserved_cases) is not int or not 1<=self.max_reserved_cases<=10000
                or type(self.golden_case_ms) is not int or not 1000<=self.golden_case_ms<=min(15000,self.jobs.lease_ms)):
            raise ValueError('explicit qualification budgets and case window within lease required')


class QualificationRequest(Contract):
    mode:Literal['installed_default','candidate']
    policy_id:UUIDText
    policy_revision:int=Field(ge=1,le=1000)
    policy_state_version:int=Field(ge=1,le=9007199254740991)
    policy_revision_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    preparation_id:UUIDText|None=None
    preparation_state_version:int|None=Field(default=None,ge=1,le=9007199254740991)
    preparation_report_sha256:str|None=Field(default=None,pattern=r'^[a-f0-9]{64}$')
    synthetic_demo_acknowledged:bool
    rollback_target:RollbackTarget|None=Field(default=None,exclude_if=lambda value:value is None)
    @model_validator(mode='after')
    def coherent(self):
        present=(self.preparation_id is not None,self.preparation_state_version is not None,self.preparation_report_sha256 is not None)
        if (self.mode=='candidate' and not all(present)) or (self.mode=='installed_default' and any(present)) or self.synthetic_demo_acknowledged is not True:
            raise ValueError('exact plan-specific sources and explicit synthetic-only acknowledgment required')
        return self


def installed_qualification_registry_sha256(plan=None):
    plan=policy_golden.build_plan() if plan is None else plan
    return digest({'software':contract_registry.registry_record(),'golden':json.loads(plan.manifest_json)})


class PolicyQualifications:
    def __init__(self,policies,registry,config,suite_config,preparations=None,*,tick_ns=None):
        if (not isinstance(policies,PolicyCandidates) or not isinstance(registry,WorkerRegistry) or not isinstance(config,QualificationConfig)
                or not isinstance(suite_config,ContractSuiteConfig) or suite_config.max_cases<len(contract_registry.installed_cases())
                or suite_config.max_duration_ms>config.jobs.lease_ms):raise ValueError('shared services and complete bounded qualification configuration required')
        if preparations is not None and preparations.evaluations.policies is not policies:raise ValueError('preparation must share exact policies')
        self.policies=policies;self.access=policies.access;self.runtime=policies.runtime;self.repository=policies.repository
        self.registry=registry;self.config=config;self.suite_config=suite_config;self.preparations=preparations;self.tick=tick_ns or time.monotonic_ns
        self.plan=policy_golden.build_plan();self.cases=contract_registry.installed_cases();self.software_implementation=implementation_sha256()
        self.registry_sha=installed_qualification_registry_sha256(self.plan)
        self.configuration=self._configuration()
        self._metadata_lock=RLock()

    @contextmanager
    def _metadata_window(self,actor):
        budget=min(self.config.jobs.lease_ms,integer(actor.session.data['expires_at_ms'])-self.access.now())
        if budget<=0:raise Denied('current qualification session required')
        started=time.monotonic_ns()
        if not self._metadata_lock.acquire(timeout=budget/1000):raise StoreUnavailable('local qualification delivery is busy')
        try:
            if time.monotonic_ns()-started>=budget*1000000:raise StoreUnavailable('local qualification delivery wait expired')
            yield
        finally:self._metadata_lock.release()

    def _configuration(self):
        return digest({'config':asdict(self.config),'suite':asdict(self.suite_config),'registry':self.registry_sha,'software':self.software_implementation,
            'writer':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'preparation':None if self.preparations is None else self.preparations.configuration})

    @staticmethod
    def _merge(rows):
        result={}
        for row in rows:
            if row is None:continue
            if row.key in result and result[row.key]!=row:raise StoreConflict('qualification authority changed across snapshots')
            result[row.key]=row
        if len(result)>90:raise StoreUnavailable('complete qualification authority exceeds capacity')
        return result

    def _row(self,ident):
        row=self.repository.snapshot((job_key(uuid(ident)),))[job_key(ident)]
        if row is None or row.data.get('kind')!=KIND or row.data.get('id')!=ident:raise ResourceUnavailable('qualification unavailable')
        return row

    def _request(self,row):
        text=row.data['request_json']
        if len(text.encode())>8192 or hashlib.sha256(text.encode()).hexdigest()!=row.data['request_sha256']:raise StoreUnavailable('intact qualification request required')
        return QualificationRequest.model_validate_json(text)

    def _inputs(self,actor,request,*,consumed=None):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if self.runtime.environment!='synthetic_demo':raise Denied('genuine beta/physical qualification remains unavailable')
        runtime=self.policies._runtime();data=self.repository.snapshot((DATA,))[DATA]
        if data is None:raise StoreUnavailable('qualification DATA authority required')
        head,record,rows=self.policies._load(request.policy_id,request.policy_revision)
        if consumed is not None:consumption(consumed).candidate(request,head,record)
        elif head.revision!=request.policy_state_version or (request.rollback_target is None and integer(head.data['latest_revision'])!=request.policy_revision):raise StoreConflict('exact current qualification candidate required')
        if record.data['sha256']!=request.policy_revision_sha256 or head.data['binding']!=self.policies._binding():raise StoreConflict('exact qualified policy binding required')
        rollback=rollback_checks(self.policies,request,consumed=consumed)
        checks=self._merge((runtime,data,*rows,*actor.rows,*rollback.values()));source_count=0;prep_count=0;expiry=integer(actor.session.data['expires_at_ms'])
        spec=PolicyDraft.model_validate_json(canonical(record.data['spec']))
        if request.mode=='installed_default':
            if spec.priority!=DEFAULT_PRIORITY:raise Denied('cold-start qualification requires installed default priority')
        else:
            if self.preparations is None:raise StoreUnavailable('candidate qualification needs installed preparation service')
            prep=self.preparations._row(request.preparation_id)
            if prep.revision!=request.preparation_state_version or prep.data['requested_by']!=actor.member.data['id']:raise Denied('exact original preparation reviewer required')
            scope,report=self.preparations._sealed(actor,prep,consumed=consumed)
            original=self.preparations._request(prep)
            source=self.preparations.evaluations._row(original.source_evaluation_id)
            evaluated=self.preparations.evaluations._request(source)
            if (report.data['sha256']!=request.preparation_report_sha256 or original.policy_id!=request.policy_id
                    or evaluated.policy_revision!=request.policy_revision or evaluated.policy_revision_sha256!=request.policy_revision_sha256
                    or evaluated.rollback_target!=request.rollback_target):raise StoreConflict('matching current preparation report and exact transition intent required')
            checks=self._merge((*checks.values(),*scope.values(),prep,report,source));source_count=integer(prep.data['source_examples']);prep_count=integer(prep.data['example_count'])
            if not 1<=source_count<=1000:raise StoreUnavailable('complete bounded source population required')
            expiry=min(expiry,integer(report.data['expires_at_ms']))
        return actor,checks,record,source_count,prep_count,expiry

    def _guard(self,actor,row,*,consumed=None):
        actor,checks,record,sources,prepared,expiry=self._inputs(actor,self._request(row),consumed=consumed);origin=resolve(self.access,row.data)
        control=checks[RUNTIME].data['control_version'] if consumed is None else consumption(consumed).execution_control(row,checks[RUNTIME])
        headkey=qualification_head(record.data['id'],integer(record.data['revision']));head=self.repository.snapshot((headkey,))[headkey]
        if (origin.member.data['id']!=actor.member.data['id'] or actor.member.data['id']!=row.data['requested_by'] or head is None or head.data['qualification_id']!=row.data['id']
                or row.data['configuration']!=self.configuration or self._configuration()!=self.configuration
                or row.data['validation_runtime']!=asdict(self.runtime.handle) or row.data['control_version']!=control
                or row.data['data_epoch']!=checks[DATA].data['epoch'] or integer(row.data['source_examples'])!=sources or integer(row.data['preparation_count'])!=prepared
                or row.data['golden_manifest_sha256']!=self.plan.sha256 or row.data['registry_sha256']!=self.registry_sha
                or implementation_sha256()!=self.software_implementation or policy_golden.implementation_sha256()!=json.loads(self.plan.manifest_json)['implementation_sha256']
                or not integer(row.data['created_at_ms'])<=self.access.now()<min(expiry,integer(row.data['expires_at_ms']))):raise StoreConflict('original qualification scope or expiry changed')
        return actor,self._merge((*checks.values(),*origin.rows,row,head)),record

    def _quota(self,actor,kind):
        key=Key('state','policy-qualification-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('qualification quota clock reversed')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        cap=self.config.jobs.jobs_per_minute if kind in {'create','end'} else self.config.jobs.step_attempts_per_minute if kind=='step' else self.config.jobs.reads_per_minute
        if count>=cap:raise EvaluationLimited('qualification allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def create(self,actor,*,request,idempotency_key):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if not isinstance(request,QualificationRequest):raise ValueError('strict qualification request required')
        text=canonical(request.model_dump(mode='json'));idem,body_hash,prior=self.access._idempotency(actor,'policy-qualification-create',idempotency_key,request.model_dump(mode='json'))
        if prior is not None:return self.job(actor,prior.data['result']['id'])
        actor,checks,record,sources,prepared,expiry=self._inputs(actor,request);pages=(prepared+19)//20
        steps=(1 if request.mode=='installed_default' else pages+sources)+12;required=len(self.cases)+sources+12
        if len(text.encode())>8192 or steps>self.config.jobs.max_steps or required>self.config.max_reserved_cases:raise EvaluationLimited('original qualification budgets must cover every required case')
        ident=str(uuid4());now=self.access.now();expiry=min(expiry,now+self.config.jobs.lifetime_ms);headkey=qualification_head(request.policy_id,request.policy_revision);head=self.repository.snapshot((headkey,))[headkey]
        data={'id':ident,'kind':KIND,'requested_by':actor.member.data['id'],'request_json':text,'request_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'configuration':self.configuration,'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,'environment':self.runtime.environment,
            'validation_runtime':asdict(self.runtime.handle),'control_version':integer(checks[RUNTIME].data['control_version']),'data_epoch':integer(checks[DATA].data['epoch']),
            'created_at_ms':now,'expires_at_ms':expiry,'example_count':steps,'required_case_count':required,'source_examples':sources,'preparation_count':prepared,'preparation_pages':pages,
            'software_cases':len(self.cases),'golden_cases':12,'golden_manifest_sha256':self.plan.sha256,'registry_sha256':self.registry_sha,
            'processed':0,'steps_reserved':0,'cases_reserved':0,'status':'queued','lease_token':None,'lease_until_ms':0,'lease_runtime':None,
            'completed_cases':0,'passed_cases':0,'failed_cases':0,'unknown_cases':0,'golden_hashes':[],'software_report_sha256':request.preparation_report_sha256,
            'chain_sha256':digest({'id':ident,'request_sha256':hashlib.sha256(text.encode()).hexdigest()}),'report_sha256':None,'failure_reason':None,**FLAGS}
        data['processing_authority']=issue(self.access,actor,data,Role.REVIEWER)
        def final():
            self.access._fresh(actor,Role.REVIEWER)
            if self.access.now()>=expiry:raise StoreUnavailable('qualification admission expired')
        with self._metadata_window(actor):
            result=self.access._record(actor,'policy-qualification-create',idem,body_hash,{'id':ident},
                (Write(job_key(ident),None,data),Write(headkey,None if head is None else head.revision,{'qualification_id':ident,'status':'pending','report_sha256':None}),
                 Write(Key('state','policy-qualification-catalog#'+ident),None,{'id':ident}),Write(Key('state','policy-qualification-user#'+actor.scope+'#'+ident),None,{'id':ident}),self._quota(actor,'create')),
                tuple(checks.values()),required_role=Role.REVIEWER,before_commit=final)
        return self.job(actor,result['id'])

    def _execute(self,actor,row,record,index,gate):
        request=self._request(row);spec=PolicyDraft.model_validate_json(canonical(record.data['spec']));extra=[];guard=gate;passed=failed=unknown=0;software=None
        prefix=1 if request.mode=='installed_default' else integer(row.data['preparation_pages'])+integer(row.data['source_examples'])
        if request.mode=='installed_default' and index==0:
            suite=PolicyContractSuite(spec,self.suite_config,checkpoint=gate);report=suite.run();cases=report['cases'];hashes=[]
            for start in range(0,len(cases),20):
                page={'id':row.data['id'],'start':start,'cases':cases[start:start+20]};page['sha256']=digest(page)
                if len(canonical(page).encode())>196608:raise StoreUnavailable('software report page exceeds item bound')
                hashes.append(page['sha256']);extra.append(Write(software_page_key(row.data['id'],start//20),None,page))
            summary={'id':row.data['id'],'metadata':{k:v for k,v in report.items() if k!='cases'},'page_hashes':hashes,'report_sha256':digest(report)};summary['sha256']=digest(summary)
            extra.append(Write(software_key(row.data['id']),None,summary));software=summary['sha256'];passed=integer(report['counts'].get('PASS',0));failed=integer(report['counts'].get('FAIL',0))
            content={'phase':'executed_installed_default_contracts','cases':len(cases),'passed':passed,'failed':failed,'software_report_sha256':software}
        elif request.mode=='candidate' and index<integer(row.data['preparation_pages']):
            start=index*20;page=self.preparations.entries(actor,request.preparation_id,start=start,limit=20);items=[]
            for offset,value in enumerate(page['entries']):
                position=start+offset
                if position<len(self.cases):
                    case=self.cases[position];expected=contract_registry.expected_result(case,spec)
                    if value.get('phase')!='software_contract' or canonical(value.get('case'))!=canonical(asdict(case)) or value.get('expected')!=expected:raise StoreUnavailable('installed preparation software case mismatch')
                    ok=value.get('passed') is True and value.get('actual')==expected and value.get('error') is None;passed+=ok;failed+=not ok
                elif value.get('phase')!='source_evaluation_integrity' or value.get('source_index')!=position-len(self.cases):raise StoreUnavailable('complete preparation source coverage required')
                items.append({'index':position,'sha256':digest(value)})
            content={'phase':'verified_preparation_page','start':start,'entries':items,'passed':passed,'failed':failed}
        elif index<prefix:
            source=index-integer(row.data['preparation_pages']);prep_request=self.preparations._request(self.preparations._row(request.preparation_id))
            prepared=self.preparations.entries(actor,request.preparation_id,start=len(self.cases)+source,limit=1)['entries'][0]
            value=self.preparations.evaluations.examples(actor,prep_request.source_evaluation_id,start=source,limit=1)['examples'][0]
            if prepared['source_entry_sha256']!=digest(value):raise StoreUnavailable('exact prepared source regression required')
            measurements=[*value['baseline']['measurements'],*value['candidate']['measurements']]
            observable=all(m['count_comparison_observable'] is True for m in measurements)
            good=(value['data_origin']=='synthetic' and observable and all(m['counts_match_declared_truth'] is True for m in measurements)
                and [m['findings'] for m in value['baseline']['measurements']]==[m['findings'] for m in value['candidate']['measurements']])
            passed=int(good);unknown=int(not observable);failed=int(not good and observable)
            content={'phase':'source_regression','source_index':source,'source_entry_sha256':digest(value),'data_origin':value['data_origin'],
                'passed':bool(passed),'unknown':bool(unknown),'findings_unchanged':good,'physical_truth_verified':False}
        else:
            content,guard=policy_golden.measure_case(self.plan,index-prefix,spec,self.registry,self.runtime.instance_id,gate=gate,max_case_ms=self.config.golden_case_ms)
            passed=int(content['passed']);failed=int(not content['passed'])
        return content,passed,failed,unknown,extra,guard,software

    def advance(self,actor,ident,*,expected_version,idempotency_key,execution_gate=None):
        actor=self.access._fresh(actor,Role.REVIEWER);row=self._row(ident)
        if actor.member.data['id']!=row.data['requested_by'] or type(expected_version) is not int or expected_version<1:raise Denied('original reviewer and exact qualification version required')
        idem,body_hash,prior=self.access._idempotency(actor,'policy-qualification-step:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        actor,checks,record=self._guard(actor,row)
        if row.revision!=expected_version or row.data['status'] not in {'queued','processing'} or self.access.now()<integer(row.data['lease_until_ms']):raise StoreConflict('available exact qualification step required')
        index=integer(row.data['processed']);request=self._request(row);started=self.tick();last=[started]
        def gate():
            if execution_gate is not None and execution_gate() is False:raise StoreUnavailable('qualification stopped')
            now=self.tick()
            if (type(now) is not int or type(started) is not int or not now>=last[0]>=started>=0 or now-started>=self.config.jobs.lease_ms*1000000
                    or self.access.now()>=min(integer(row.data['expires_at_ms']),integer(actor.session.data['expires_at_ms']))):raise StoreUnavailable('original qualification lease expired')
            last[0]=now
        gate();cost=(len(self.cases) if index==0 else 1) if request.mode=='installed_default' else max(0,min(20,len(self.cases)-index*20)) if index<integer(row.data['preparation_pages']) else 1
        data=json.loads(canonical(row.data));exhausted=data['steps_reserved']>=self.config.jobs.max_steps or data['cases_reserved']+cost>self.config.max_reserved_cases;token=str(uuid4())
        data.update(status='failed' if exhausted else 'processing',steps_reserved=data['steps_reserved']+(not exhausted),cases_reserved=data['cases_reserved']+(0 if exhausted else cost),
            lease_token=None if exhausted else token,lease_runtime=asdict(self.runtime.handle),lease_until_ms=0 if exhausted else min(data['expires_at_ms'],self.access.now()+self.config.jobs.lease_ms),failure_reason='ORIGINAL_BUDGET_EXHAUSTED' if exhausted else None)
        with self._metadata_window(actor):
            self.access._record(actor,'policy-qualification-step:'+ident,idem,body_hash,{'id':ident},(Write(row.key,row.revision,data),self._quota(actor,'step')),
                tuple(checks.values()),required_role=Role.REVIEWER,before_commit=gate)
        if exhausted:return self.job(actor,ident)
        def lease():
            gate();current=self._row(ident)
            if (current.data['lease_token']!=token or current.data['status']!='processing' or self.access.now()>=integer(current.data['lease_until_ms'])
                    or current.data['lease_runtime']!=asdict(self.runtime.handle)):raise StoreConflict('current original qualification lease required')
            return current
        current=lease();actor,checks,record=self._guard(actor,current)
        content,passed,failed,unknown,writes,case_guard,software=self._execute(actor,current,record,index,gate)
        case_guard();latest=lease();actor,checks,record=self._guard(actor,latest)
        if latest!=current:raise StoreConflict('qualification lease changed during execution')
        text=canonical(content)
        if len(text.encode())>32768:raise StoreUnavailable('qualification entry exceeds output bound')
        entry={'id':ident,'index':index,'previous_sha256':current.data['chain_sha256'],'content_json':text};entry['sha256']=digest(entry)
        data=json.loads(canonical(current.data));data.update(status='queued',processed=index+1,lease_token=None,lease_until_ms=0,lease_runtime=None,chain_sha256=entry['sha256'],
            completed_cases=data['completed_cases']+passed+failed+unknown,passed_cases=data['passed_cases']+passed,failed_cases=data['failed_cases']+failed,unknown_cases=data['unknown_cases']+unknown)
        if software is not None:data['software_report_sha256']=software
        if content['phase']=='installed_golden':data['golden_hashes'].append(digest(content))
        writes.append(Write(entry_key(ident,index),None,entry))
        if index+1==integer(data['example_count']):
            if data['completed_cases']!=data['required_case_count'] or len(data['golden_hashes'])!=12:raise StoreUnavailable('all planned qualification cases required')
            golden={'id':ident,'manifest_sha256':self.plan.sha256,'case_hashes':data['golden_hashes'],'case_count':12,**FLAGS};golden['sha256']=digest(golden);writes.append(Write(golden_key(ident),None,golden))
            status='qualified' if data['failed_cases']==data['unknown_cases']==0 else 'rejected'
            report={'schema_version':1,'runner':'policy_qualification_v1','id':ident,'status':status,'scope':'synthetic_demo_only','policy_id':request.policy_id,
                'policy_revision':request.policy_revision,'policy_revision_sha256':request.policy_revision_sha256,'behavior_sha256':record.data['behavior_sha256'],
                'installed_sha256':self.policies.installed_sha256,'registry_sha256':self.registry_sha,'configuration':self.configuration,'environment':self.runtime.environment,
                'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,'runtime_epoch':integer(checks[RUNTIME].data['runtime_epoch']),
                'control_version':data['control_version'],'data_epoch':data['data_epoch'],'issued_at_ms':self.access.now(),'expires_at_ms':data['expires_at_ms'],
                'required_case_count':data['required_case_count'],'completed_case_count':data['completed_cases'],'passed_case_count':data['passed_cases'],
                'failed_case_count':data['failed_cases'],'unknown_case_count':data['unknown_cases'],'preparation_basis':'executed_installed_default_contracts' if request.mode=='installed_default' else 'current_reviewer_preparation',
                'preparation_report_sha256':data['software_report_sha256'],'golden_report_sha256':golden['sha256'],'chain_sha256':entry['sha256'],'steps':data['example_count'],**FLAGS}
            if request.rollback_target is not None:report['rollback_target']=request.rollback_target.model_dump(mode='json')
            report['sha256']=digest(report)
            if len(canonical(report).encode())>32768:raise StoreUnavailable('qualification header exceeds bound')
            data.update(status='completed',report_sha256=report['sha256']);headkey=qualification_head(request.policy_id,request.policy_revision);head=checks[headkey]
            writes.extend((Write(qualification_key(ident),None,report),Write(headkey,head.revision,{'qualification_id':ident,'status':status,'report_sha256':report['sha256']})))
        writes.insert(0,Write(current.key,current.revision,data));expected=self._merge((*checks.values(),*self.access._fresh(actor,Role.REVIEWER).rows))
        with self._metadata_window(actor):
            case_guard();lease();self.access._fresh(actor,Role.REVIEWER);case_guard()
            self.access._commit(tuple(writes),tuple(r for k,r in expected.items() if k not in {w.key for w in writes}))
        return self.job(actor,ident)

    def _sealed(self,actor,row,*,consumed=None):
        actor,checks,record=self._guard(actor,row,consumed=consumed);request=self._request(row);key=qualification_key(row.data['id']);gold=golden_key(row.data['id'])
        values=self.repository.snapshot((key,gold));report,golden=values[key],values[gold]
        if (row.data['status']!='completed' or report is None or report.revision!=1 or report.data['sha256']!=row.data['report_sha256']
                or digest({k:v for k,v in report.data.items() if k!='sha256'})!=report.data['sha256'] or golden is None or golden.revision!=1
                or digest({k:v for k,v in golden.data.items() if k!='sha256'})!=golden.data['sha256'] or golden.data['sha256']!=report.data['golden_report_sha256']
                or report.data['completed_case_count']!=row.data['required_case_count'] or report.data['steps']!=row.data['processed']):raise StoreUnavailable('complete intact qualification report required')
        head=checks[qualification_head(request.policy_id,request.policy_revision)]
        if (row.data['processed']!=row.data['example_count'] or head.data['report_sha256']!=report.data['sha256'] or head.data['status']!=report.data['status']
                or any(report.data[k]!=row.data[v] for k,v in [('completed_case_count','completed_cases'),('failed_case_count','failed_cases'),('unknown_case_count','unknown_cases'),('passed_case_count','passed_cases')])
                or report.data['passed_case_count']+report.data['failed_case_count']+report.data['unknown_case_count']!=report.data['required_case_count']):raise StoreUnavailable('qualification counts or current head do not reconcile')
        if (integer(report.data['schema_version'])!=1 or report.data['id']!=row.data['id']
                or any(report.data[k]!=row.data[k] for k in ('configuration','registry_sha256','environment','artifact_sha256','controls_sha256','control_version','data_epoch','expires_at_ms','required_case_count'))
                or report.data['policy_id']!=request.policy_id or report.data['policy_revision']!=request.policy_revision or report.data['policy_revision_sha256']!=request.policy_revision_sha256
                or report.data.get('rollback_target')!=(None if request.rollback_target is None else request.rollback_target.model_dump(mode='json'))):raise StoreUnavailable('qualification header differs from its original job')
        previous=digest({'id':row.data['id'],'request_sha256':row.data['request_sha256']});golden_hashes=[];totals=Counter()
        for start in range(0,integer(row.data['example_count']),80):
            keys=tuple(entry_key(row.data['id'],i) for i in range(start,min(start+80,integer(row.data['example_count']))));items=self.repository.snapshot(keys)
            for index,k in enumerate(keys,start):
                item=items[k]
                if (item is None or item.revision!=1 or item.data['index']!=index or item.data['previous_sha256']!=previous
                        or digest({n:v for n,v in item.data.items() if n!='sha256'})!=item.data['sha256']):raise StoreUnavailable('intact complete qualification chain required')
                previous=item.data['sha256'];text=item.data['content_json'];content=json.loads(text)
                if len(text.encode())>32768 or canonical(content)!=text:raise StoreUnavailable('bounded canonical qualification content required')
                if content['phase']=='installed_golden':
                    offset=len(golden_hashes);expected=json.loads(self.plan.inputs[offset].expected_json)
                    if (content['case_id']!=self.plan.inputs[offset].id or content['manifest_sha256']!=self.plan.sha256 or content['expected']!=expected
                            or type(content['passed']) is not bool or content['passed']!=(content['actual']==expected)):raise StoreUnavailable('golden outcome contradicts installed expectation')
                    golden_hashes.append(digest(content));totals['passed' if content['passed'] else 'failed']+=1
                elif content['phase']=='source_regression':
                    if type(content['passed']) is not bool or type(content['unknown']) is not bool or (content['passed'] and content['unknown']):raise StoreUnavailable('explicit source outcome required')
                    totals['passed' if content['passed'] else 'unknown' if content['unknown'] else 'failed']+=1
                elif content['phase'] in {'executed_installed_default_contracts','verified_preparation_page'}:
                    totals['passed']+=integer(content['passed']);totals['failed']+=integer(content['failed'])
                else:raise StoreUnavailable('installed qualification phase required')
        if previous!=report.data['chain_sha256'] or golden_hashes!=golden.data['case_hashes'] or len(golden_hashes)!=12 or golden.data['manifest_sha256']!=self.plan.sha256:raise StoreUnavailable('complete golden evidence chain required')
        if (any(totals[k]!=integer(report.data[k+'_case_count']) for k in ('passed','failed','unknown'))
                or report.data['status']!=('qualified' if totals['failed']==totals['unknown']==0 else 'rejected')):raise StoreUnavailable('all qualification outcomes must reconcile')
        checks=self._merge((*checks.values(),*values.values()))
        if request.mode=='installed_default':
            header=self.repository.snapshot((software_key(row.data['id']),))[software_key(row.data['id'])]
            if header is None or header.revision!=1 or header.data['sha256']!=report.data['preparation_report_sha256'] or digest({k:v for k,v in header.data.items() if k!='sha256'})!=header.data['sha256']:raise StoreUnavailable('intact executed software phase required')
            keys=tuple(software_page_key(row.data['id'],i) for i in range(len(header.data['page_hashes'])));pages=self.repository.snapshot(keys);cases=[]
            for i,k in enumerate(keys):
                page=pages[k]
                if page is None or page.revision!=1 or page.data['start']!=i*20 or page.data['sha256']!=header.data['page_hashes'][i] or digest({n:v for n,v in page.data.items() if n!='sha256'})!=page.data['sha256']:raise StoreUnavailable('intact software case pages required')
                cases.extend(page.data['cases'])
            if len(cases)!=len(self.cases) or digest({**header.data['metadata'],'cases':cases})!=header.data['report_sha256']:raise StoreUnavailable('complete executed software population required')
            spec=PolicyDraft.model_validate_json(canonical(record.data['spec']));outcomes=Counter()
            for case,value in zip(self.cases,cases,strict=True):
                expected=contract_registry.expected_result(case,spec);status='PASS' if value.get('actual')==expected and value.get('reason') is None else 'FAIL'
                if value.get('id')!=case.id or value.get('expected')!=expected or value.get('status')!=status:raise StoreUnavailable('executed software outcome mismatch')
                outcomes[status]+=1
            metadata=header.data['metadata']
            if metadata['complete'] is not True or metadata['counts']!=dict(outcomes) or metadata['planned_cases']!=len(self.cases) or metadata['reserved_attempts']!=len(self.cases):raise StoreUnavailable('complete software outcomes required')
            checks=self._merge((*checks.values(),header,*pages.values()))
        return checks,report

    def read_current(self,ident):
        row=self._row(ident);actor=resolve(self.access,row.data);checks,report=self._sealed(actor,row)
        if report.data['status']!='qualified' or report.data['failed_case_count']!=0 or report.data['unknown_case_count']!=0:raise Denied('qualification failed or unknown')
        frozen=self._merge(checks.values());deadline=integer(report.data['expires_at_ms'])
        def final_guard():
            current_actor=resolve(self.access,row.data);current=self._row(ident);values,latest=self._sealed(current_actor,current)
            if current!=row or values!=frozen or latest!=report:raise StoreConflict('qualified source changed before consumption')
            self.access._fresh(current_actor,Role.REVIEWER)
            if self.access.now()>=deadline:raise StoreUnavailable('original qualification expired')
        final_guard();return QualifiedPolicySnapshot(report,tuple(frozen.values()),deadline,final_guard)

    def _decision_metadata(self,row):
        request=self._request(row)
        return {key:getattr(request,key) for key in ('policy_id','policy_revision','policy_state_version','policy_revision_sha256',
            'mode','preparation_id','preparation_state_version','preparation_report_sha256')} | {
            'registry_sha256':row.data['registry_sha256'],'source_examples':integer(row.data['source_examples']),
            'rollback_target':None if request.rollback_target is None else request.rollback_target.model_dump(mode='json')}

    def job(self,actor,ident):
        with self._metadata_window(actor):return self._job(actor,ident)

    def _job(self,actor,ident):
        binding=self._configuration();row=self._row(ident);actor=self.access._fresh(actor)
        original=actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles
        if not original:actor=self.access._fresh(actor,Role.OWNER);self.access._recent_mfa(actor)
        current=False;report=None;checks={row.key:row}
        try:
            source=actor if original else resolve(self.access,row.data);_,scope,_=self._guard(source,row);checks=self._merge((*checks.values(),*scope.values()))
            if row.data['status']=='completed':checks,report=self._sealed(source,row)
            current=True
        except (Denied,StoreConflict,StoreUnavailable,ResourceUnavailable):pass
        def revalidate(fresh):
            if not current:return (),integer(fresh.session.data['expires_at_ms'])
            source=fresh if original else resolve(self.access,row.data);_,latest,_=self._guard(source,row)
            if report is not None:
                latest,latest_report=self._sealed(source,row)
                if latest_report!=report:raise StoreConflict('qualification report changed during metadata delivery')
            return tuple(latest.values()),min(integer(row.data['expires_at_ms']),integer(source.session.data['expires_at_ms']))
        self._finish_metadata(actor,tuple(checks.values()),Role.REVIEWER if original else Role.OWNER,'job',binding,revalidate)
        remaining=max(0,integer(row.data['expires_at_ms'])-self.access.now());lease=max(0,integer(row.data['lease_until_ms'])-self.access.now())
        return {**self._decision_metadata(row),'id':ident,'kind':KIND,'state_version':row.revision,'status':row.data['status'],'current':current,'report_current':report is not None,
            'steps_prepared':integer(row.data['processed']),'planned_steps':integer(row.data['example_count']),'steps_reserved':integer(row.data['steps_reserved']),
            'cases_reserved':integer(row.data['cases_reserved']),'required_cases':integer(row.data['required_case_count']),
            'report_sha256':None if report is None else report.data['sha256'],'qualification_status':'not_qualified' if report is None else report.data['status'],
            'counts':None if report is None else {'passed':integer(report.data['passed_case_count']),'failed':integer(report.data['failed_case_count']),'unknown':integer(report.data['unknown_case_count'])},
            'remaining_ms':remaining,'lease_remaining_ms':lease,
            'can_advance':bool(original and current and remaining and not lease and row.data['status'] in {'queued','processing'}),
            'can_cancel':row.data['status'] in {'queued','processing','failed'},'can_retire':row.data['status']=='completed',
            'can_read_request':original,'can_read_details':bool(original and report is not None),
            'failure_reason':row.data['failure_reason'],'inspection_enablement_granted':False,**FLAGS}

    def _detail(self,actor,ident):
        row=self._row(ident);actor=self.access._fresh(actor,Role.REVIEWER)
        if row.data['requested_by']!=actor.member.data['id']:raise Denied('original qualification reviewer required')
        checks,report=self._sealed(actor,row);return actor,row,checks,report

    def _deliver(self,actor,row,checks,report,kind,start,end):
        expected=self._merge((*checks.values(),*actor.rows))
        def final_read():
            fresh=self.access._fresh(actor,Role.REVIEWER)
            if self.access.now()>=min(integer(report.data['expires_at_ms']),integer(fresh.session.data['expires_at_ms'])):
                raise StoreUnavailable('qualification detail read expired')
        self.access._commit_linked(kind,(self._quota(actor,'read'),Write(Key('events','policy-qualification-read#'+str(uuid4())),None,
            {'qualification_id':row.data['id'],'kind':kind,'start':start,'end':end,'user_id':actor.member.data['id'],'at_ms':self.access.now()})),tuple(expected.values()),before_commit=final_read)
        current_actor=self.access._fresh(actor,Role.REVIEWER);current=self._row(row.data['id']);latest,current_report=self._sealed(current_actor,current)
        if current!=row or current_report!=report or any(checks.get(k)!=v for k,v in latest.items()):raise StoreConflict('qualification changed during detail delivery')
        final_actor=self.access._fresh(current_actor,Role.REVIEWER);expected=self._merge((*expected.values(),*final_actor.rows))
        values=self.repository.snapshot(tuple(expected))
        if any(values[k]!=v for k,v in expected.items()) or self._configuration()!=self.configuration:raise StoreConflict('qualification details changed during delivery')
        if self.access.now()>=min(integer(report.data['expires_at_ms']),integer(final_actor.session.data['expires_at_ms'])):raise StoreUnavailable('qualification detail delivery expired')

    def entries(self,actor,ident,*,start=0,limit=20):
        if type(start) is not int or start<0 or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded qualification page required')
        actor,row,checks,report=self._detail(actor,ident);count=integer(row.data['example_count'])
        if start>=count:raise ValueError('qualification page outside complete report')
        keys=tuple(entry_key(ident,i) for i in range(start,min(start+limit,count)));values=self.repository.snapshot(keys)
        checks=self._merge((*checks.values(),*values.values()));result=[]
        for key in keys:
            item=values[key]
            if item is None or item.revision!=1 or digest({k:v for k,v in item.data.items() if k!='sha256'})!=item.data['sha256']:raise StoreUnavailable('intact qualification detail required')
            result.append({'index':integer(item.data['index']),**json.loads(item.data['content_json'])})
        self._deliver(actor,row,checks,report,'entries',start,start+len(result))
        return {'id':ident,'entries':result,'next_index':None if start+len(result)==count else start+len(result),**FLAGS}

    def software_cases(self,actor,ident,*,start=0,limit=20):
        if type(start) is not int or not 0<=start<len(self.cases) or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded software case page required')
        actor,row,checks,report=self._detail(actor,ident);request=self._request(row);end=min(len(self.cases),start+limit)
        if request.mode=='candidate':
            page=self.preparations.entries(actor,request.preparation_id,start=start,limit=end-start)
            result=[{'id':value['case']['id'],'status':'PASS' if value['passed'] else 'FAIL','expected':value['expected'],'actual':value['actual'],'reason':value['error']} for value in page['entries']]
        else:
            all_cases=[]
            for i in range((len(self.cases)+19)//20):all_cases.extend(checks[software_page_key(ident,i)].data['cases'])
            result=json.loads(canonical(all_cases[start:end]))
        if len(result)!=end-start or [v['id'] for v in result]!=[c.id for c in self.cases[start:end]]:raise StoreUnavailable('complete ordered software cases required')
        self._deliver(actor,row,checks,report,'software_cases',start,end)
        return {'id':ident,'cases':result,'next_index':None if end==len(self.cases) else end,**FLAGS}

    def _finish_metadata(self,actor,checks,role,kind,binding,guard=None):
        actor=self.access._fresh(actor,role)
        if role==Role.OWNER:self.access._recent_mfa(actor)
        expected=self._merge((*checks,*actor.rows));deadline=integer(actor.session.data['expires_at_ms'])
        def final_read():
            self.access._fresh(actor,role)
            if self.access.now()>=deadline:raise StoreUnavailable('qualification metadata read expired')
        self.access._commit_linked(kind,(self._quota(actor,'read'),Write(Key('events','policy-qualification-access#'+str(uuid4())),None,
            {'kind':kind,'user_id':actor.member.data['id'],'at_ms':self.access.now()})),tuple(expected.values()),before_commit=final_read)
        fresh=self.access._fresh(actor,role)
        if role==Role.OWNER:self.access._recent_mfa(fresh)
        if guard is not None:
            rows,expiry=guard(fresh);expected=self._merge((*expected.values(),*rows));deadline=min(deadline,expiry)
        expected=self._merge((*expected.values(),*fresh.rows));values=self.repository.snapshot(tuple(expected))
        if any(values[k]!=v for k,v in expected.items()) or self._configuration()!=binding:raise StoreConflict('qualification metadata changed during final delivery')
        if self.access.now()>=deadline:raise StoreUnavailable('qualification metadata delivery expired')

    def list(self,actor,*,limit=20,cursor=None,owner_view=False):
        if type(owner_view) is not bool or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded explicit qualification catalog required')
        role=Role.OWNER if owner_view else Role.REVIEWER;actor=self.access._fresh(actor,role)
        if owner_view:self.access._recent_mfa(actor)
        binding=self._configuration();runtime=self.policies._runtime()
        prefix='policy-qualification-catalog#' if owner_view else 'policy-qualification-user#'+actor.scope+'#'
        rows,last=self.repository.query(prefix=prefix,limit=limit,start_resource=None if cursor is None else prefix+uuid(cursor))
        if len(rows)>limit or (last is not None and not last.startswith(prefix)):raise StoreUnavailable('bounded exact qualification catalog required')
        checks=[runtime];items=[]
        for pointer in rows:
            ident=uuid(pointer.data['id'])
            if pointer.key!=Key('state',prefix+ident):raise StoreUnavailable('intact qualification catalog required')
            row=self._row(ident);request=self._request(row)
            if not owner_view and row.data['requested_by']!=actor.member.data['id']:raise Denied('own qualification catalog required')
            checks.extend((pointer,row));items.append({**self._decision_metadata(row),'id':ident,'kind':KIND,'state_version':row.revision,'status':row.data['status'],
                'policy_id':request.policy_id,'policy_revision':request.policy_revision,'policy_revision_sha256':request.policy_revision_sha256,
                'mode':request.mode,'steps_prepared':integer(row.data['processed']),'planned_steps':integer(row.data['example_count']),
                'created_at_ms':integer(row.data['created_at_ms']),'expires_at_ms':integer(row.data['expires_at_ms']),
                'report_sha256':row.data['report_sha256'],'current':None,'report_current':None,'currency_not_checked':True,
                'inspection_enablement_granted':False,**FLAGS})
        self._finish_metadata(actor,checks,role,'catalog-owner' if owner_view else 'catalog-own',binding)
        return {'qualifications':items,'scope':'owner' if owner_view else 'own','next_cursor':None if last is None else uuid(last[len(prefix):])}

    def options(self,actor):
        actor=self.access._fresh(actor);role=Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER;actor=self.access._fresh(actor,role)
        if role==Role.OWNER:self.access._recent_mfa(actor)
        binding=self._configuration()
        if binding!=self.configuration:raise StoreUnavailable('installed qualification configuration changed')
        runtime=self.policies._runtime();self._finish_metadata(actor,(runtime,),role,'options',binding)
        return {'software_cases':len(self.cases),'golden_cases':len(self.plan.inputs),'registry_sha256':self.registry_sha,
            'max_reserved_cases':self.config.max_reserved_cases,'max_steps':self.config.jobs.max_steps,'lifetime_ms':self.config.jobs.lifetime_ms,
            'lease_ms':self.config.jobs.lease_ms,'page_size':20,'synthetic_demo_only':True,'inspection_enablement_granted':False,**FLAGS}

    def selections(self,actor,ident):
        binding=self._configuration();row=self._row(ident);actor=self.access._fresh(actor,Role.REVIEWER)
        if row.data['requested_by']!=actor.member.data['id']:raise Denied('original qualification reviewer required')
        request=self._request(row);runtime=self.policies._runtime();self._finish_metadata(actor,(row,runtime),Role.REVIEWER,'request',binding)
        return request.model_dump(mode='json')

    def _end(self,actor,ident,expected_version,idempotency_key,request=None):
        row=self._row(ident);actor=self.access._fresh(actor)
        role=Role.REVIEWER if actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles else Role.OWNER
        actor=self.access._fresh(actor,role)
        if role==Role.OWNER:self.access._recent_mfa(actor)
        retire=request is not None
        if retire and (not isinstance(request,Consequence) or request.acknowledged is not True):raise Denied('explicit qualification retirement consequence required')
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact qualification version required')
        body={'expected_version':expected_version,'reason':request.reason if retire else 'cancelled-by-request'}
        operation='policy-qualification-'+('retire:' if retire else 'cancel:')+ident;idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is not None:return self.job(actor,ident)
        if row.revision!=expected_version or (retire and row.data['status'] not in {'completed','retired'}) or (not retire and row.data['status'] in {'completed','retired'}):raise StoreConflict('appropriate exact qualification state required')
        runtime=self.policies._runtime();data=self.repository.snapshot((DATA,))[DATA];original=self._request(row);headkey=qualification_head(original.policy_id,original.policy_revision);head=self.repository.snapshot((headkey,))[headkey]
        status='retired' if retire else 'cancelled';writes=[]
        if row.data['status']!=status:
            writes.append(Write(row.key,row.revision,{**row.data,'status':status,'lease_token':None,'lease_until_ms':0,'lease_runtime':None,
                'end_reason':body['reason'],'ended_by':actor.member.data['id'],'ended_at_ms':self.access.now()}))
            if head is not None and head.data['qualification_id']==ident:writes.append(Write(headkey,head.revision,{**head.data,'status':status}))
            if retire:writes.append(Write(DATA,data.revision,{**data.data,'epoch':integer(data.data['epoch'])+1,'changed_at_ms':self.access.now()}))
        def final():
            fresh=self.access._fresh(actor,role)
            if role==Role.OWNER:self.access._recent_mfa(fresh)
            if self.access.now()>=integer(fresh.session.data['expires_at_ms']):raise Denied('current qualification end authority required')
        checks=self._merge((row,runtime,data,head,*actor.rows));writes.append(self._quota(actor,'end'))
        with self._metadata_window(actor):
            self.access._record(actor,operation,idem,body_hash,{'id':ident},tuple(writes),tuple(checks.values()),required_role=role,before_commit=final,
                event_details={'qualification_id':ident,'operation':status,'reason':body['reason'],'attempts_preserved':True})
        return self.job(actor,ident)

    def cancel(self,actor,ident,*,expected_version,idempotency_key):return self._end(actor,ident,expected_version,idempotency_key)
    def retire(self,actor,ident,*,request,expected_version,idempotency_key):
        if not isinstance(request,Consequence) or request.acknowledged is not True:raise Denied('explicit qualification retirement consequence required')
        return self._end(actor,ident,expected_version,idempotency_key,request)
