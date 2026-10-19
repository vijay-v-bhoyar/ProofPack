"""Durable source-bound preparation for qualification; never an approval writer."""
from dataclasses import asdict
import hashlib,json,time
from uuid import uuid4
from pydantic import Field,model_validator

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.evidence.erasure import job_key
from proofpack.evidence.job_authority import issue,resolve
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.consumption import consumption
from proofpack.planner import contract_registry
from proofpack.planner.contract_suite import ContractSuiteConfig,implementation_sha256
from proofpack.recipes.models import Contract
from proofpack.review.labels import UUIDText
from proofpack.review.evaluation_models import EvaluationConfig,EvaluationLimited
from proofpack.review.manifests import Consequence
from proofpack.runtime.control import DATA,integer,uuid

KIND='policy_qualification_preparation'
FLAGS={'qualification_eligible':False,'promotion_eligible':False,'physical_truth_verified':False,'independent_benchmark_qualified':False}


class PreparationRequest(Contract):
    policy_id:UUIDText
    source_evaluation_id:UUIDText
    source_evaluation_state_version:int=Field(ge=1,le=9007199254740991)
    source_report_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    preparation_only_acknowledged:bool

    @model_validator(mode='after')
    def acknowledged(self):
        if self.preparation_only_acknowledged is not True:raise ValueError('explicit preparation-only acknowledgment required')
        return self


def entry_key(ident,index):return Key('state','qualification-preparation-entry#'+uuid(ident)+'#'+str(integer(index)).zfill(4))
def report_key(ident):return Key('state','qualification-preparation-report#'+uuid(ident))


class QualificationPreparations:
    def __init__(self,evaluations,config,suite_config,*,tick_ns=None):
        if not isinstance(config,EvaluationConfig) or not isinstance(suite_config,ContractSuiteConfig):raise ValueError('explicit preparation/suite bounds required')
        self.evaluations=evaluations;self.access=evaluations.access;self.repository=evaluations.repository;self.runtime=evaluations.runtime
        self.config=config;self.suite_config=suite_config;self.tick=tick_ns or time.monotonic_ns
        self.cases=contract_registry.installed_cases();self.registry_sha=digest(contract_registry.registry_record());self.implementation_sha=implementation_sha256()
        if not self.cases or len(self.cases)>suite_config.max_cases or len({c.id for c in self.cases})!=len(self.cases):raise ValueError('complete distinct installed case inventory required')
        self.configuration=digest({'bounds':asdict(config),'suite':asdict(suite_config),'registry':self.registry_sha,
            'implementation':self.implementation_sha,'evaluation':evaluations.configuration})

    def _merge(self,rows):
        values=self.evaluations._merge(rows)
        if len(values)>90:raise StoreUnavailable('complete preparation dependencies exceed transaction bound')
        return values

    def _row(self,ident):
        row=self.repository.snapshot((job_key(uuid(ident)),))[job_key(ident)]
        if row is None or row.data.get('kind')!=KIND or row.data.get('id')!=ident:raise ResourceUnavailable('preparation unavailable')
        return row

    def _request(self,row):
        try:
            text=row.data['request_json']
            if len(text.encode())>8192 or hashlib.sha256(text.encode()).hexdigest()!=row.data['request_sha256']:raise ValueError()
            return PreparationRequest.model_validate_json(text)
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('intact preparation request required') from exc

    def _inputs(self,actor,request,*,consumed=None):
        actor=self.access._fresh(actor,Role.REVIEWER);source=self.evaluations._row(request.source_evaluation_id)
        original=self.evaluations._request(source)
        if (source.revision!=request.source_evaluation_state_version or source.data['requested_by']!=actor.member.data['id']
                or original.runner!='vision_replay_v1' or original.policy_id!=request.policy_id):raise Denied('original reviewer and exact image evaluation required')
        source_actor=resolve(self.access,source.data)
        if source_actor.member.data['id']!=actor.member.data['id']:raise Denied('current original source reviewer required')
        actor,checks,report,_=self.evaluations._sealed(actor,source,consumed=consumed)
        if report.data['sha256']!=request.source_report_sha256:raise StoreConflict('source report changed')
        head,policy,rows=self.evaluations.policies._load(original.policy_id,original.policy_revision)
        checks=self._merge((*checks.values(),*rows,*actor.rows,*source_actor.rows))
        return actor,checks,report,policy

    def _guard(self,actor,row,*,consumed=None):
        actor,checks,report,policy=self._inputs(actor,self._request(row),consumed=consumed);data=row.data;now=self.access.now()
        control=checks[RUNTIME].data['control_version'] if consumed is None else consumption(consumed).execution_control(row,checks[RUNTIME])
        origin=resolve(self.access,data)
        if actor.member.data['id']!=origin.member.data['id']:raise Denied('original preparation reviewer required')
        checks=self._merge((*checks.values(),*origin.rows))
        if (data['configuration']!=self.configuration or data['validation_runtime']!=asdict(self.runtime.handle)
                or data['control_version']!=control or data['data_epoch']!=checks[DATA].data['epoch']
                or data['registry_sha256']!=self.registry_sha or data['implementation_sha256']!=implementation_sha256()
                or digest(contract_registry.registry_record())!=self.registry_sha
                or integer(data['software_cases'])!=len(self.cases) or integer(data['source_examples'])!=integer(report.data['example_count'])
                or integer(data['example_count'])!=len(self.cases)+integer(report.data['example_count'])
                or not integer(data['created_at_ms'])<=now<min(integer(data['expires_at_ms']),integer(report.data['expires_at_ms']))):
            raise StoreConflict('preparation source, runtime, configuration or lifetime changed')
        return actor,checks,report,policy

    def _quota(self,actor,kind):
        key=Key('state','qualification-preparation-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('preparation quota clock moved backwards')
        count=0 if row is None or row.data['minute']!=minute else integer(row.data['count'])
        cap=self.config.jobs_per_minute if kind=='create' else self.config.reads_per_minute if kind=='read' else self.config.step_attempts_per_minute
        if count>=cap:raise EvaluationLimited('preparation allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def create(self,actor,*,request,idempotency_key):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if not isinstance(request,PreparationRequest):raise ValueError('typed preparation request required')
        text=canonical(request.model_dump(mode='json'))
        if len(text.encode())>8192:raise ValueError('bounded preparation request required')
        idem,body_hash,prior=self.access._idempotency(actor,'qualification-preparation-create',idempotency_key,request.model_dump(mode='json'))
        if prior is not None:return self.job(actor,prior.data['result']['id'])
        actor,checks,source,policy=self._inputs(actor,request);count=integer(source.data['example_count']);total=count+len(self.cases)
        if not 1<=count<=1000 or total>self.config.max_steps:raise EvaluationLimited('original preparation budget must cover every required case')
        ident=str(uuid4());now=self.access.now();expiry=min(now+self.config.lifetime_ms,integer(source.data['expires_at_ms']),integer(actor.session.data['expires_at_ms']))
        data={'id':ident,'kind':KIND,'requested_by':actor.member.data['id'],'request_json':text,'request_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'configuration':self.configuration,'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,
            'environment':self.runtime.environment,'validation_runtime':asdict(self.runtime.handle),'control_version':integer(checks[RUNTIME].data['control_version']),
            'data_epoch':integer(checks[DATA].data['epoch']),'created_at_ms':now,'expires_at_ms':expiry,'example_count':total,
            'software_cases':len(self.cases),'source_examples':count,'processed':0,'steps_reserved':0,'status':'queued',
            'lease_token':None,'lease_until_ms':0,'lease_runtime':None,'report_sha256':None,
            'registry_sha256':self.registry_sha,'implementation_sha256':self.implementation_sha,'counts':{'software_pass':0,'software_fail':0,'source_entries_verified':0},
            'chain_sha256':digest({'id':ident,'request_sha256':hashlib.sha256(text.encode()).hexdigest()}),'failure_reason':None,**FLAGS}
        data['processing_authority']=issue(self.access,actor,data,Role.REVIEWER)
        def deadline():
            if self.access.now()>=expiry:raise StoreUnavailable('preparation admission expired')
        result=self.access._record(actor,'qualification-preparation-create',idem,body_hash,{'id':ident},
            (Write(job_key(ident),None,data),Write(Key('state','qualification-preparation-catalog#'+ident),None,{'id':ident}),
             Write(Key('state','qualification-preparation-user#'+actor.scope+'#'+ident),None,{'id':ident}),self._quota(actor,'create')),
            tuple(checks.values()),required_role=Role.REVIEWER,before_commit=deadline)
        return self.job(actor,result['id'])

    def _lease(self,ident,token,gate):
        gate();row=self._row(ident)
        if (row.data['status']!='processing' or row.data['lease_token']!=token or row.data['lease_runtime']!=asdict(self.runtime.handle)
                or self.access.now()>=min(integer(row.data['lease_until_ms']),integer(row.data['expires_at_ms']))):raise StoreConflict('current preparation lease required')
        return row

    def advance(self,actor,ident,*,expected_version,idempotency_key,execution_gate=None):
        actor=self.access._fresh(actor,Role.REVIEWER);row=self._row(ident)
        if actor.member.data['id']!=row.data['requested_by']:raise Denied('original preparation reviewer required')
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact preparation version required')
        idem,body_hash,prior=self.access._idempotency(actor,'qualification-preparation-step:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        actor,checks,source,policy=self._guard(actor,row)
        if row.revision!=expected_version or row.data['status'] not in {'queued','processing'} or (row.data['status']=='processing' and self.access.now()<integer(row.data['lease_until_ms'])):
            raise StoreConflict('available exact preparation step required')
        started=self.tick();last=[started]
        def gate():
            if execution_gate is not None and execution_gate() is False:raise StoreUnavailable('preparation stopped')
            now=self.tick()
            if type(now) is not int or not now>=last[0]>=started>=0 or now-started>=self.config.lease_ms*1000000:raise StoreUnavailable('preparation monotonic lease expired')
            last[0]=now
            if self.access.now()>=min(integer(row.data['expires_at_ms']),integer(actor.session.data['expires_at_ms'])):raise StoreUnavailable('preparation deadline expired')
        gate();data=json.loads(canonical(row.data))
        exhausted=integer(data['steps_reserved'])>=self.config.max_steps;token=str(uuid4())
        data.update(status='failed' if exhausted else 'processing',steps_reserved=integer(data['steps_reserved'])+(not exhausted),lease_token=None if exhausted else token,
            lease_until_ms=0 if exhausted else min(integer(data['expires_at_ms']),self.access.now()+self.config.lease_ms),lease_runtime=None if exhausted else asdict(self.runtime.handle))
        if exhausted:data['failure_reason']='STEP_BUDGET_EXHAUSTED'
        self.access._record(actor,'qualification-preparation-step:'+ident,idem,body_hash,{'id':ident},(Write(row.key,row.revision,data),self._quota(actor,'step')),
            tuple(checks.values()),required_role=Role.REVIEWER,before_commit=gate)
        if exhausted:return self.job(actor,ident)
        lease=self._lease(ident,token,gate);actor,checks,source,policy=self._guard(actor,lease);index=integer(lease.data['processed'])
        if index<len(self.cases):
            case=self.cases[index];spec=PolicyDraft.model_validate_json(canonical(policy.data['spec']));expected=contract_registry.expected_result(case,spec)
            try:actual=contract_registry.execute_case(case,spec);error=None
            except Exception:actual=None;error='CASE_EXECUTION_ERROR'
            content={'phase':'software_contract','case':asdict(case),'expected':expected,'actual':actual,'passed':actual==expected and error is None,'error':error}
        else:
            offset=index-len(self.cases);page=self.evaluations.examples(actor,self._request(lease).source_evaluation_id,start=offset,limit=1)
            if len(page['examples'])!=1:raise StoreUnavailable('required source evaluation entry missing')
            content={'phase':'source_evaluation_integrity','source_index':offset,'source_entry_sha256':digest(page['examples'][0]),'source_report_sha256':source.data['sha256'],
                'physical_truth_verified':False,'new_pixel_measurement':False}
        gate();text=canonical(content)
        if len((text+'\n').encode())>self.suite_config.max_case_report_bytes:raise StoreUnavailable('preparation case exceeds output bound')
        current=self._lease(ident,token,gate);actor,checks,source,_=self._guard(actor,current)
        if current!=lease:raise StoreConflict('preparation lease changed before commit')
        entry={'id':ident,'index':index,'previous_sha256':current.data['chain_sha256'],'content_json':text};entry['sha256']=digest(entry)
        data=json.loads(canonical(current.data));data.update(status='queued',processed=index+1,chain_sha256=entry['sha256'],lease_token=None,lease_until_ms=0,lease_runtime=None)
        count_key=('software_pass' if content['passed'] else 'software_fail') if index<len(self.cases) else 'source_entries_verified'
        data['counts'][count_key]=integer(data['counts'][count_key])+1;writes=[Write(entry_key(ident,index),None,entry)]
        if index+1==integer(data['example_count']):
            header={k:data[k] for k in ('id','request_sha256','configuration','artifact_sha256','controls_sha256','environment','validation_runtime','data_epoch','control_version',
                'example_count','software_cases','source_examples','registry_sha256','implementation_sha256','counts','chain_sha256','expires_at_ms')}
            header.update(qualification_status='not_qualified',blocking_reasons=['INDEPENDENT_QUALIFICATION_EVIDENCE_REQUIRED',*(['SOFTWARE_CONTRACT_FAILURE'] if data['counts']['software_fail'] else [])],**FLAGS)
            header['sha256']=digest(header)
            if len(canonical(header).encode())>32768:raise StoreUnavailable('preparation report header exceeds bound')
            data.update(status='completed',report_sha256=header['sha256']);writes.append(Write(report_key(ident),None,header))
        fresh=self.access._fresh(actor,Role.REVIEWER);expected=self._merge((*checks.values(),current,*actor.rows,*fresh.rows));gate()
        self._lease(ident,token,gate)
        writes.insert(0,Write(current.key,current.revision,data));keys={w.key for w in writes}
        self.access._commit(tuple(writes),tuple(v for k,v in expected.items() if k not in keys))
        return self.job(actor,ident)

    def _viewer(self,actor,row,*,entries=False):
        actor=self.access._fresh(actor)
        if actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles:return self.access._fresh(actor,Role.REVIEWER)
        if entries:raise Denied('original preparation reviewer required')
        actor=self.access._fresh(actor,Role.OWNER);self.access._recent_mfa(actor);return actor

    def _sealed(self,actor,row,*,consumed=None):
        actor,checks,_,_=self._guard(actor,row,consumed=consumed);report=self.repository.snapshot((report_key(row.data['id']),))[report_key(row.data['id'])]
        try:
            if (row.data['status']!='completed' or report is None or report.revision!=1 or report.data['sha256']!=row.data['report_sha256']
                    or digest({k:v for k,v in report.data.items() if k!='sha256'})!=report.data['sha256']
                    or any(report.data[k]!=row.data[k] for k in ('chain_sha256','counts','example_count','request_sha256','configuration','expires_at_ms','registry_sha256','implementation_sha256'))
                    or integer(row.data['processed'])!=integer(row.data['example_count'])
                    or integer(report.data['counts']['software_pass'])+integer(report.data['counts']['software_fail'])!=len(self.cases)
                    or integer(report.data['counts']['source_entries_verified'])!=integer(row.data['source_examples'])
                    or report.data['qualification_status']!='not_qualified' or any(report.data[k] is not False for k in FLAGS)):
                raise ValueError()
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('complete intact preparation report required') from exc
        return self._merge((*checks.values(),row,report)),report

    def _finish_read(self,actor,row,checks,kind,*,deadline=None):
        actor=self._viewer(actor,row);expected=self._merge((*checks,*actor.rows));quota=self._quota(actor,'read')
        deadline=min(integer(actor.session.data['expires_at_ms']),integer(deadline) if deadline is not None else integer(actor.session.data['expires_at_ms']))
        def final_read():
            self._viewer(actor,row)
            if self.access.now()>=deadline:raise StoreUnavailable('preparation read deadline expired')
        self.access._commit_linked(kind,(quota,Write(Key('events','qualification-preparation-access#'+str(uuid4())),None,{'preparation_id':row.data['id'],'kind':kind,'user_id':actor.member.data['id'],'at_ms':self.access.now()})),tuple(expected.values()),before_commit=final_read)
        fresh=self._viewer(actor,row);expected=self._merge((*expected.values(),*fresh.rows));current=self.repository.snapshot(tuple(expected))
        if any(current[k]!=v for k,v in expected.items()):raise StoreConflict('preparation delivery authority changed')
        if not (fresh.member.data['id']==row.data['requested_by'] and Role.REVIEWER in fresh.principal.roles):self.access._recent_mfa(fresh)
        if self.access.now()>=deadline:raise StoreUnavailable('preparation delivery deadline expired')

    def job(self,actor,ident):
        row=self._row(ident);actor=self._viewer(actor,row);checks=[row];source_current=False;header=None
        try:
            origin=actor if actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles else resolve(self.access,row.data)
            _,binding,_,_=self._guard(origin,row);checks.extend(binding.values());source_current=True
            if row.data['status']=='completed':sealed,header=self._sealed(origin,row);checks.extend(sealed.values())
        except (Denied,StoreConflict,StoreUnavailable,ResourceUnavailable):pass
        request=self._request(row);now=self.access.now();value={'id':ident,'kind':KIND,'state_version':row.revision,'status':row.data['status'],
            'policy_id':request.policy_id,'source_evaluation_id':request.source_evaluation_id,'source_report_sha256':request.source_report_sha256,
            'software_cases':integer(row.data['software_cases']),'source_examples':integer(row.data['source_examples']),'expires_at_ms':integer(row.data['expires_at_ms']),
            'planned_count':integer(row.data['example_count']),'prepared_count':integer(row.data['processed']),'steps_reserved':integer(row.data['steps_reserved']),
            'remaining_ms':max(0,integer(row.data['expires_at_ms'])-now),'source_current':source_current,'report_current':header is not None,
            'counts':None if header is None else json.loads(canonical(header.data['counts'])),'qualification_status':'not_qualified',
            'failure_reason':row.data['failure_reason'],'lease_remaining_ms':max(0,integer(row.data['lease_until_ms'])-now),'end_reason':row.data.get('end_reason'),
            'blocking_reasons':['PREPARATION_OR_SOURCE_INCOMPLETE'] if header is None else list(header.data['blocking_reasons']),
            'report_sha256':row.data['report_sha256'],'can_advance':bool(source_current and actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles
                and row.data['status'] in {'queued','processing'} and now>=integer(row.data['lease_until_ms'])),**FLAGS}
        self._finish_read(actor,row,checks,'summary',deadline=integer(row.data['expires_at_ms']) if source_current else None);return value

    def entries(self,actor,ident,*,start=0,limit=20):
        if type(start) is not int or start<0 or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded preparation page required')
        row=self._row(ident);actor=self._viewer(actor,row,entries=True);checks,report=self._sealed(actor,row);count=integer(row.data['example_count'])
        if start>=count:raise ValueError('preparation page outside report')
        keys=tuple(entry_key(ident,i) for i in range(max(0,start-1),min(count,start+limit)));values=self.repository.snapshot(keys);items=[]
        previous=digest({'id':ident,'request_sha256':row.data['request_sha256']}) if start==0 else None
        for index in range(max(0,start-1),min(count,start+limit)):
            item=values[entry_key(ident,index)]
            if (item is None or item.revision!=1 or item.data['id']!=ident or integer(item.data['index'])!=index
                    or digest({k:v for k,v in item.data.items() if k!='sha256'})!=item.data['sha256']
                    or (previous is not None and item.data['previous_sha256']!=previous)):raise StoreUnavailable('intact preparation entry chain required')
            text=item.data['content_json']
            if len((text+'\n').encode())>self.suite_config.max_case_report_bytes or canonical(json.loads(text))!=text:raise StoreUnavailable('intact bounded preparation content required')
            previous=item.data['sha256']
            if index>=start:items.append(json.loads(text))
        if min(count,start+limit)==count and previous!=report.data['chain_sha256']:raise StoreUnavailable('final preparation chain mismatch')
        self._finish_read(actor,row,(*checks.values(),*values.values()),'entries',deadline=integer(report.data['expires_at_ms']))
        return {'id':ident,'entries':items,'next_index':None if start+len(items)==count else start+len(items),**FLAGS}

    def _finish_catalog_read(self,actor,checks,role,kind):
        fresh=self.access._fresh(actor,role)
        if role==Role.OWNER:self.access._recent_mfa(fresh)
        expected=self._merge((*checks,*actor.rows,*fresh.rows));deadline=integer(fresh.session.data['expires_at_ms'])
        def final_read():
            self.access._fresh(fresh,role)
            if self.access.now()>=deadline:raise StoreUnavailable('preparation metadata read expired')
        self.access._commit_linked(kind,(self._quota(fresh,'read'),Write(Key('events','qualification-preparation-access#'+str(uuid4())),None,
            {'kind':kind,'user_id':fresh.member.data['id'],'at_ms':self.access.now()})),tuple(expected.values()),before_commit=final_read)
        current_actor=self.access._fresh(fresh,role);expected=self._merge((*expected.values(),*current_actor.rows))
        current=self.repository.snapshot(tuple(expected))
        if any(current[k]!=v for k,v in expected.items()):raise StoreConflict('preparation metadata changed during delivery')
        if role==Role.OWNER:self.access._recent_mfa(current_actor)
        if self.access.now()>=deadline:raise StoreUnavailable('preparation metadata delivery expired')

    def list(self,actor,*,limit=20,cursor=None,owner_view=False):
        if type(owner_view) is not bool or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded explicit preparation view required')
        role=Role.OWNER if owner_view else Role.REVIEWER;actor=self.access._fresh(actor,role)
        if owner_view:self.access._recent_mfa(actor)
        runtime=self.evaluations._runtime();prefix='qualification-preparation-catalog#' if owner_view else 'qualification-preparation-user#'+actor.scope+'#'
        rows,last=self.repository.query(prefix=prefix,limit=limit,start_resource=None if cursor is None else prefix+uuid(cursor))
        checks=[runtime];items=[]
        for catalog in rows:
            ident=uuid(catalog.data['id'])
            if catalog.key.resource!=prefix+ident:raise StoreUnavailable('intact preparation catalog required')
            row=self._row(ident);request=self._request(row)
            if not owner_view and row.data['requested_by']!=actor.member.data['id']:raise Denied('own preparation catalog required')
            checks.extend((catalog,row));items.append({'id':ident,'kind':KIND,'state_version':row.revision,'status':row.data['status'],
                'policy_id':request.policy_id,'source_evaluation_id':request.source_evaluation_id,'source_report_sha256':request.source_report_sha256,
                'planned_count':integer(row.data['example_count']),'prepared_count':integer(row.data['processed']),
                'steps_reserved':integer(row.data['steps_reserved']),'created_at_ms':integer(row.data['created_at_ms']),
                'expires_at_ms':integer(row.data['expires_at_ms']),'report_sha256':row.data['report_sha256'],
                'source_current':None,'report_current':None,'currency_not_checked':True,'qualification_status':'not_qualified',**FLAGS})
        self._finish_catalog_read(actor,checks,role,'catalog-owner' if owner_view else 'catalog-own')
        return {'preparations':items,'scope':'owner' if owner_view else 'own','next_cursor':None if last is None else uuid(last[len(prefix):])}

    def options(self,actor):
        actor=self.access._fresh(actor);role=Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER
        actor=self.access._fresh(actor,role)
        if role==Role.OWNER:self.access._recent_mfa(actor)
        runtime=self.evaluations._runtime();self._finish_catalog_read(actor,(runtime,),role,'options')
        return {'software_cases':len(self.cases),'registry_sha256':self.registry_sha,'implementation_sha256':self.implementation_sha,
            'max_source_examples':max(0,min(1000,self.config.max_steps-len(self.cases))),'max_steps':self.config.max_steps,
            'lifetime_ms':self.config.lifetime_ms,'lease_ms':self.config.lease_ms,'page_size':20,
            'image_evaluation_required':True,'preparation_only':True,**FLAGS}

    def selections(self,actor,ident):
        row=self._row(ident);actor=self._viewer(actor,row,entries=True);runtime=self.evaluations._runtime();request=self._request(row)
        self._finish_read(actor,row,(row,runtime),'request')
        return request.model_dump(mode='json')

    def _end(self,actor,ident,expected_version,idempotency_key,retire,request=None):
        row=self._row(ident);actor=self._viewer(actor,row);role=Role.REVIEWER if actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles else Role.OWNER
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact preparation version required')
        if retire and (not isinstance(request,Consequence) or request.acknowledged is not True):raise Denied('explicit preparation retirement consequence required')
        operation=('qualification-preparation-retire:' if retire else 'qualification-preparation-cancel:')+ident
        body={'expected_version':expected_version,'reason':request.reason if retire else 'cancelled-by-request'}
        idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is not None:return self.job(actor,ident)
        if row.revision!=expected_version or (retire and row.data['status'] not in {'completed','retired'}) or (not retire and row.data['status'] in {'completed','retired'}):raise StoreConflict('current appropriate preparation state required')
        runtime=self.evaluations._runtime();epoch=self.evaluations.purposes.head();writes=[];target='retired' if retire else 'cancelled'
        if row.data['status']!=target:
            writes.append(Write(row.key,row.revision,{**row.data,'status':target,'lease_token':None,'lease_until_ms':0,'lease_runtime':None,
                'end_reason':body['reason'],'ended_at_ms':self.access.now(),'ended_by':actor.member.data['id']}))
            if retire:writes.append(self.evaluations.purposes.advance(epoch))
        self.access._record(actor,operation,idem,body_hash,{'id':ident},(*writes,self._quota(actor,'end')),(row,runtime,epoch),required_role=role,
            event_details={'preparation_id':ident,'status':target,'reason':body['reason']})
        return self.job(actor,ident)

    def cancel(self,actor,ident,*,expected_version,idempotency_key):return self._end(actor,ident,expected_version,idempotency_key,False)
    def retire(self,actor,ident,*,request,expected_version,idempotency_key):return self._end(actor,ident,expected_version,idempotency_key,True,request)
