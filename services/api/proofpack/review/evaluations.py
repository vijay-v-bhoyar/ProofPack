"""Durable exact-scope historical replay using existing labels/permissions/maintenance."""
from dataclasses import asdict
import hashlib
import json
import time
from uuid import uuid4
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.evidence.erasure import job_key
from proofpack.evidence.job_authority import issue,resolve
from proofpack.planner.candidates import PolicyDraft
from proofpack.review.manifests import DatasetManifests,Consequence
from proofpack.review.evaluation_models import EvaluationConfig,EvaluationRequest,EvaluationLimited,empty_counts,replay_decision,parse_evaluation_request
from proofpack.vision.worker import WorkerUnavailable
from proofpack.runtime.control import DATA,integer,uuid


def report_key(ident):return Key('state','evaluation-report#'+uuid(ident))
def entry_key(ident,index):return Key('state','evaluation-example#'+uuid(ident)+'#'+str(integer(index)).zfill(4))


class PolicyEvaluations:
    def __init__(self,policies,datasets,config,*,vision_registry=None,vision_config=None):
        if (not isinstance(config,EvaluationConfig) or policies.access is not datasets.access
                or policies.runtime is not datasets.runtime or policies.repository is not datasets.repository):
            raise ValueError('shared evaluation services and explicit bounds required')
        self.policies=policies;self.datasets=datasets;self.config=config;self.access=datasets.access
        self.runtime=datasets.runtime;self.repository=datasets.repository;self.purposes=datasets.purposes
        self.configuration=digest({'bounds':asdict(config),'policies':policies.configuration,'datasets':datasets.configuration,'runner':'decision_replay_v1'})
        self.vision=None
        if (vision_registry is None)!=(vision_config is None):raise ValueError('explicit paired vision registry/configuration required')
        if vision_registry is not None:
            from proofpack.review.vision_replay import VisionReprocessor
            self.vision=VisionReprocessor(self,vision_registry,vision_config)
            self.configuration=digest({'decision':self.configuration,'vision':self.vision.configuration})

    def _viewer(self,actor):return self.policies._reader(actor)
    def _runtime(self):return self.datasets._runtime()
    def _merge(self,rows):return DatasetManifests._merge(rows)

    def _quota(self,actor,kind):
        key=Key('state','evaluation-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('evaluation allowance clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        maximum=self.config.jobs_per_minute if kind=='create' else self.config.reads_per_minute if kind=='read' else self.config.step_attempts_per_minute
        if count>=maximum:raise EvaluationLimited('evaluation allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def _row(self,ident):
        row=self.repository.snapshot((job_key(ident),))[job_key(ident)]
        if row is None or row.data.get('kind')!='policy_evaluation' or row.data.get('id')!=ident:raise ResourceUnavailable('evaluation unavailable')
        return row

    def _request(self,row):
        try:
            text=row.data['request_json']
            if len(text.encode())>8192 or hashlib.sha256(text.encode()).hexdigest()!=row.data['request_sha256']:raise ValueError()
            return parse_evaluation_request(text)
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('intact evaluation request required') from exc

    def _inputs(self,actor,request,*,consumed=None):
        from proofpack.planner.rollback import rollback_checks
        actor=self.access._fresh(actor,Role.REVIEWER)
        head,policy,rows=self.policies._load(request.policy_id,request.policy_revision)
        if consumed is not None:
            from proofpack.planner.consumption import consumption
            consumption(consumed).candidate(request,head,policy)
        elif head.revision!=request.policy_state_version or (request.rollback_target is None and integer(head.data['latest_revision'])!=request.policy_revision):
            raise StoreConflict('current exact installed candidate required')
        rollback=rollback_checks(self.policies,request,consumed=consumed)
        rows=(*rows,*rollback.values())
        if policy.data['sha256']!=request.policy_revision_sha256 or head.data['binding']!=self.policies._binding():
            raise StoreConflict('current exact installed candidate required')
        manifest=self.datasets._row(request.manifest_id);actor,binding,sealed=self.datasets._sealed(actor,manifest)
        if sealed.data['sha256']!=request.manifest_sha256:raise StoreConflict('exact complete dataset required')
        if integer(sealed.data['splits']['FROZEN_TEST']) and not request.frozen_holdout_acknowledged:raise Denied('explicit frozen-data diagnostic acknowledgment required')
        if request.runner=='vision_replay_v1' and self.vision is not None:
            _,recipe_rows=self.vision._candidate(request);rows=(*rows,*recipe_rows)
        return actor,self._merge((*rows,*binding.values())),policy,manifest,sealed

    def _guard(self,actor,row,*,consumed=None):
        request=self._request(row)
        inputs=self._inputs(actor,request) if consumed is None else self._inputs(actor,request,consumed=consumed)
        actor,checks,policy,manifest,sealed=inputs;data=row.data
        epoch=checks[DATA]
        if (data['configuration']!=self.configuration or data['artifact_sha256']!=self.runtime.artifact_sha256
                or data['controls_sha256']!=self.runtime.controls_sha256 or data['environment']!=self.runtime.environment
                or data['validation_runtime']!=asdict(self.runtime.handle) or integer(data['data_epoch'])!=integer(epoch.data['epoch'])
                or integer(data['example_count'])!=integer(sealed.data['example_count'])
                or not integer(data['created_at_ms'])<=self.access.now()<integer(data['effective_deadline_ms'])):
            raise StoreConflict('evaluation source, runtime or lifetime changed')
        return actor,checks,policy,manifest,sealed,request

    def create(self,actor,*,request,idempotency_key):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if not isinstance(request,EvaluationRequest):raise ValueError('typed evaluation required')
        if request.runner=='vision_replay_v1' and self.vision is None:raise StoreUnavailable('full vision replay is not configured')
        body=request.model_dump(mode='json');text=canonical(body)
        if len(text.encode())>8192:raise EvaluationLimited('evaluation request size exceeded')
        idem,body_hash,prior=self.access._idempotency(actor,'evaluation-create',idempotency_key,body)
        if prior is not None:return self.job(actor,prior.data['result']['id'])
        actor,checks,policy,manifest,sealed=self._inputs(actor,request);count=integer(sealed.data['example_count'])
        if count>self.config.max_steps:raise EvaluationLimited('evaluation original step budget insufficient')
        now=self.access.now();ident=str(uuid4());request_sha=hashlib.sha256(text.encode()).hexdigest();seed=digest({'evaluation_id':ident,'request_sha256':request_sha})
        expires=min(now+self.config.lifetime_ms,integer(actor.session.data['expires_at_ms']),integer(sealed.data['expires_at_ms']))
        data={'id':ident,'kind':'policy_evaluation','requested_by':actor.member.data['id'],'configuration':self.configuration,
            'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,'environment':self.runtime.environment,
            'data_epoch':integer(checks[DATA].data['epoch']),'validation_runtime':asdict(self.runtime.handle),
            'created_at_ms':now,'expires_at_ms':expires,'effective_deadline_ms':expires,'request_json':text,'request_sha256':request_sha,
            'example_count':count,'processed':0,'steps_reserved':0,'seed_sha256':seed,'chain_sha256':seed,'counts':empty_counts(),
            'candidate_name':policy.data['spec']['name'],'status':'queued','failure_reason':None,'report_sha256':None,
            'lease_token':None,'lease_until_ms':0,'lease_runtime':None}
        if request.runner=='vision_replay_v1':
            for side in ('baseline','candidate'):
                data['counts'][side].update(measurements=0,observable_frames=0,count_matches=0,count_mismatches=0,unobservable_frames=0)
        data['processing_authority']=issue(self.access,actor,data,Role.REVIEWER)
        def deadline():
            if self.access.now()>=expires:raise StoreUnavailable('evaluation creation deadline expired')
        committed=self.access._record(actor,'evaluation-create',idem,body_hash,{'id':ident},
            (Write(job_key(ident),None,data),Write(Key('state','evaluation-catalog#'+ident),None,{'id':ident}),self._quota(actor,'create')),
            tuple(checks.values()),required_role=Role.REVIEWER,before_commit=deadline,event_details={'evaluation_id':ident,'diagnostic_only':True})
        return self.job(actor,committed['id'])

    def _lease(self,ident,token,started,gate):
        gate();row=self._row(ident);runtime=self._runtime()
        if (row.data['status']!='processing' or row.data['lease_token']!=token or row.data['lease_runtime']!=asdict(self.runtime.handle)
                or self.access.now()>=integer(row.data['lease_until_ms']) or not 0<=time.monotonic_ns()-started<self.config.lease_ms*1000000):
            raise StoreConflict('current evaluation lease required')
        return row,runtime

    def _case(self,actor,request,policy,manifest,sealed,index,gate):
        content,label,source,checks,deadline=self.datasets.source_case(actor,manifest,sealed,index,gate)
        spec=PolicyDraft.model_validate_json(canonical(policy.data['spec']));result=replay_decision(label,spec)
        value={'schema_version':1,'runner':'decision_replay_v1','dataset_example_sha256':source['content_sha256'],
            'label_id':content['label_id'],'label_revision':content['label_revision'],'label_sha256':content['label_sha256'],
            'source_context_sha256':content['source_context_sha256'],'split':content['split'],'data_origin':content['data_origin'],
            'policy_revision_sha256':policy.data['sha256'],**result}
        return json.loads(canonical(value)),tuple(checks.values()),deadline

    def advance(self,actor,ident,*,expected_version,idempotency_key,execution_gate=None):
        if execution_gate is not None and not callable(execution_gate):raise ValueError('trusted evaluation checkpoint required')
        def gate():
            if execution_gate is not None:execution_gate()
        gate();ident=uuid(ident);row=self._row(ident);actor=self.access._fresh(actor,Role.REVIEWER)
        if actor.member.data['id']!=row.data['requested_by']:raise Denied('original evaluation reviewer required')
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact evaluation job version required')
        idem,body_hash,prior=self.access._idempotency(actor,'evaluation-step:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        actor,checks,policy,manifest,sealed,request=self._guard(actor,row)
        if (row.revision!=expected_version or row.data['status'] not in {'queued','processing'}
                or (row.data['status']=='processing' and self.access.now()<integer(row.data['lease_until_ms']))):raise StoreConflict('available evaluation step required')
        def admission():
            gate()
            if not integer(row.data['created_at_ms'])<=self.access.now()<min(integer(row.data['effective_deadline_ms']),integer(actor.session.data['expires_at_ms'])):
                raise StoreUnavailable('evaluation admission deadline expired')
        if integer(row.data['steps_reserved'])>=self.config.max_steps:
            self.access._record(actor,'evaluation-step:'+ident,idem,body_hash,{'id':ident},
                (Write(row.key,row.revision,{**row.data,'status':'failed','failure_reason':'STEP_BUDGET_EXHAUSTED'}),self._quota(actor,'step')),
                tuple(checks.values()),required_role=Role.REVIEWER,before_commit=admission)
            return self.job(actor,ident)
        token=str(uuid4());started=time.monotonic_ns();data=json.loads(canonical(row.data))
        data.update(status='processing',steps_reserved=integer(data['steps_reserved'])+1,lease_token=token,
            lease_until_ms=min(integer(data['effective_deadline_ms']),self.access.now()+self.config.lease_ms),lease_runtime=asdict(self.runtime.handle),
            processing_authority=issue(self.access,actor,row.data,Role.REVIEWER))
        reserved=self.access._record(actor,'evaluation-step:'+ident,idem,body_hash,{'id':ident,'attempt':token},
            (Write(row.key,row.revision,data),self._quota(actor,'step')),tuple(checks.values()),required_role=Role.REVIEWER,before_commit=admission)
        if reserved.get('attempt')!=token:return self.job(actor,ident)
        lease,runtime=self._lease(ident,token,started,gate);index=integer(lease.data['processed'])
        measurement=None
        try:
            if request.runner=='vision_replay_v1':
                if self.vision is None:raise StoreUnavailable('full vision replay is not configured')
                def case_gate():self._lease(ident,token,started,gate)
                measurement=self.vision.measure_case(actor,request=request,index=index,execution_gate=case_gate,consumer_id=ident)
                content,source_checks,expires=measurement.value,measurement.checks,measurement.source_expires_at_ms
            else:content,source_checks,expires=self._case(actor,request,policy,manifest,sealed,index,gate)
        except (Denied,ResourceUnavailable,StoreConflict,StoreUnavailable,ValueError,WorkerUnavailable) as exc:
            lease,runtime=self._lease(ident,token,started,gate);actor=self.access._fresh(actor,Role.REVIEWER);gate()
            current,current_runtime=self._lease(ident,token,started,gate)
            if current!=lease:raise StoreConflict('evaluation failure lease changed before commit')
            if self.access.now()>=min(integer(lease.data['effective_deadline_ms']),integer(actor.session.data['expires_at_ms'])):
                raise StoreUnavailable('evaluation failure deadline expired')
            reason='VISION_WORKER_UNAVAILABLE' if isinstance(exc,WorkerUnavailable) else 'SOURCE_OR_PERMISSION_HELD'
            self.access._commit((Write(lease.key,lease.revision,{**lease.data,'status':'failed','failure_reason':reason,'lease_token':None,'lease_until_ms':0,'lease_runtime':None}),),(*actor.rows,current_runtime))
            return self.job(actor,ident)
        lease,runtime=self._lease(ident,token,started,gate);actor,checks,_,_,_,_=self._guard(actor,lease)
        data=json.loads(canonical(lease.data));effective=min(integer(data['effective_deadline_ms']),expires)
        record={'schema_version':1,'evaluation_id':ident,'index':index,'content_sha256':digest(content),'previous_chain_sha256':data['chain_sha256']}
        # Exact numeric CV intervals remain JSON numbers; DynamoDB stores their
        # canonical JSON text rather than unsupported native Python floats.
        if request.runner=='vision_replay_v1':record['content_json']=canonical(content)
        else:record['content']=content
        record['chain_sha256']=digest(record);key=entry_key(ident,index);existing=self.repository.snapshot((key,))[key];writes=[]
        if existing is None:writes.append(Write(key,None,record))
        elif existing.revision!=1 or canonical(existing.data)!=canonical(record):raise StoreUnavailable('evaluation entry cannot be overwritten')
        else:source_checks=(*source_checks,existing)
        data.update(processed=index+1,chain_sha256=record['chain_sha256'],effective_deadline_ms=effective,status='queued',lease_token=None,lease_until_ms=0,lease_runtime=None)
        for side in ('baseline','candidate'):
            item=content[side];data['counts'][side][item['classification']]+=1
            if item['declared_resolved'] is not None:data['counts'][side]['declared_resolved' if item['declared_resolved'] else 'declared_unresolved']+=1
            if request.runner=='vision_replay_v1':
                measurements=item['measurements'];counts=data['counts'][side];counts['measurements']+=len(measurements)
                for measured in measurements:
                    observable=measured['count_comparison_observable'];counts['observable_frames' if observable else 'unobservable_frames']+=1
                    if observable:counts['count_matches' if measured['counts_match_declared_truth'] else 'count_mismatches']+=1
        if index+1==integer(data['example_count']):
            report={k:data[k] for k in ('id','request_sha256','example_count','chain_sha256','seed_sha256','configuration','artifact_sha256','controls_sha256','environment','data_epoch','created_at_ms','validation_runtime','counts')}
            report.update(schema_version=1,expires_at_ms=effective,diagnostic_only=True,independent_benchmark_qualified=False,promotion_eligible=False,operator_effort_measured=False)
            if request.runner=='vision_replay_v1':report.update(runner=request.runner,pixel_measurement_performed=True,physical_truth_verified=False)
            report['sha256']=digest(report);writes.append(Write(report_key(ident),None,report));data.update(status='completed',report_sha256=report['sha256'])
        actor=self.access._fresh(actor,Role.REVIEWER);current,current_runtime=self._lease(ident,token,started,gate)
        if current!=lease:raise StoreConflict('evaluation lease changed before commit')
        expected=self._merge((*checks.values(),*source_checks,*actor.rows,current_runtime));gate()
        if (self.access.now()>=min(effective,integer(lease.data['lease_until_ms']),integer(actor.session.data['expires_at_ms']))
                or not 0<=time.monotonic_ns()-started<self.config.lease_ms*1000000):raise StoreUnavailable('evaluation commit deadline expired')
        if measurement is not None:measurement.final_guard()
        self.access._commit((Write(lease.key,lease.revision,data),*writes),tuple(r for k,r in expected.items() if k not in {w.key for w in writes} and k!=lease.key))
        return self.job(actor,ident)

    def _base(self,actor,row):
        request=self._request(row);own=actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles
        can_end=own
        if not can_end and Role.OWNER in actor.principal.roles:
            try:self.access._fresh(actor,Role.OWNER);can_end=True
            except Denied:pass
        available=False
        if own:
            try:self._guard(actor,row);available=True
            except (Denied,StoreConflict,StoreUnavailable,ResourceUnavailable):pass
        data=row.data;remaining=max(0,integer(data['lease_until_ms'])-self.access.now())
        value={'id':data['id'],'kind':'policy_evaluation','state_version':row.revision,'status':data['status'],
            'policy_id':request.policy_id,'policy_revision':request.policy_revision,'policy_state_version':request.policy_state_version,'policy_revision_sha256':request.policy_revision_sha256,
            'manifest_id':request.manifest_id,'manifest_sha256':request.manifest_sha256,'candidate_name':data['candidate_name'],
            'example_count':integer(data['example_count']),'prepared_count':integer(data['processed']),'steps_reserved':integer(data['steps_reserved']),
            'remaining_ms':max(0,integer(data['effective_deadline_ms'])-self.access.now()),'lease_remaining_ms':remaining,
            'report_sha256':data['report_sha256'],'failure_reason':data['failure_reason'],'runner':request.runner,
            'diagnostic_only':True,'independent_benchmark_qualified':False,'promotion_eligible':False,'operator_effort_measured':False,
            'can_read_request':own,'can_advance':bool(available and data['status'] in {'queued','processing'} and remaining==0),
            'can_cancel':bool(can_end and data['status'] in {'queued','processing','failed'}),'can_retire':bool(can_end and data['status']=='completed')}
        if request.rollback_target is not None:value['rollback_target']=request.rollback_target.model_dump(mode='json')
        if request.runner=='vision_replay_v1':
            value.update({k:getattr(request,k) for k in ('candidate_recipe_id','candidate_recipe_revision','candidate_recipe_state_version','candidate_recipe_sha256')})
        return value

    def job(self,actor,ident):
        actor=self._viewer(actor);row=self._row(uuid(ident));value=self._base(actor,row);self._viewer(actor);return value

    def _sealed(self,actor,row,*,consumed=None):
        actor,checks,_,manifest,_,_=self._guard(actor,row,consumed=consumed);key=report_key(row.data['id']);report=self.repository.snapshot((key,))[key]
        try:
            if (row.data['status']!='completed' or report is None or report.revision!=1
                    or report.data['sha256']!=row.data['report_sha256'] or digest({k:v for k,v in report.data.items() if k!='sha256'})!=report.data['sha256']
                    or integer(row.data['processed'])!=integer(row.data['example_count'])
                    or any(canonical(report.data[k])!=canonical(row.data[k]) for k in ('id','request_sha256','example_count','configuration','artifact_sha256',
                        'controls_sha256','environment','data_epoch','validation_runtime','seed_sha256','chain_sha256','counts'))
                    or integer(report.data['expires_at_ms'])!=integer(row.data['effective_deadline_ms'])
                    or report.data['diagnostic_only'] is not True or any(report.data[k] is not False for k in ('independent_benchmark_qualified','promotion_eligible','operator_effort_measured'))
                    or self.access.now()>=integer(report.data['expires_at_ms'])):raise ValueError()
            request=self._request(row)
            if request.runner=='vision_replay_v1':
                if (self.vision is None or report.data.get('runner')!=request.runner or report.data.get('pixel_measurement_performed') is not True
                        or report.data.get('physical_truth_verified') is not False):raise ValueError()
                count=integer(row.data['example_count']);frames=[]
                for side in ('baseline','candidate'):
                    c=report.data['counts'][side];measured=integer(c['measurements']);frames.append(measured)
                    if (not count<=measured<=count*2 or integer(c['observable_frames'])+integer(c['unobservable_frames'])!=measured
                            or integer(c['count_matches'])+integer(c['count_mismatches'])!=integer(c['observable_frames'])
                            or sum(integer(c[k]) for k in ('observed_match','counterfactual_unknown','no_recorded_outcome','not_actionable','incorrect_finding'))!=count):raise ValueError()
                if frames[0]!=frames[1]:raise ValueError()
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('current intact evaluation header required') from exc
        return actor,self._merge((*checks.values(),row,report)),report,manifest

    def _finish_read(self,actor,checks,*,ident,kind,deadline=None):
        quota=self._quota(actor,'read');fresh=self._viewer(actor)
        expected=self._merge((*checks,*actor.rows,*fresh.rows))
        deadline=min(integer(actor.session.data['expires_at_ms']),deadline if deadline is not None else integer(actor.session.data['expires_at_ms']))
        def final_read():
            self._viewer(actor)
            if self.access.now()>=deadline:raise StoreUnavailable('evaluation read expired')
        self.access._commit_linked(kind,(quota,Write(Key('events','evaluation-access#'+str(uuid4())),None,{'evaluation_id':ident,'kind':kind,
            'user_id':actor.member.data['id'],'at_ms':self.access.now()})),tuple(expected.values()),before_commit=final_read)
        fresh=self._viewer(actor);expected=self._merge((*expected.values(),*fresh.rows));current=self.repository.snapshot(tuple(expected))
        if any(current[k]!=r for k,r in expected.items()):raise StoreConflict('evaluation read authority changed')
        if Role.REVIEWER not in fresh.principal.roles:self.access._recent_mfa(fresh)
        if self.access.now()>=deadline:raise StoreUnavailable('evaluation delivery expired')

    def summary(self,actor,ident):
        actor=self._viewer(actor);row=self._row(uuid(ident));value=self._base(actor,row);checks=[row];report=None
        try:
            origin=actor if Role.REVIEWER in actor.principal.roles else resolve(self.access,row.data)
            _,guard,report,_=self._sealed(origin,row);checks.extend(guard.values())
        except (Denied,StoreConflict,StoreUnavailable,ResourceUnavailable):pass
        value.update(result_header_current=report is not None,counts=None if report is None else json.loads(canonical(report.data['counts'])),
            held_reason=None if report is not None else 'REPORT_OR_SOURCE_HELD')
        if self._request(row).runner=='vision_replay_v1':value.update(pixel_measurement_performed=report is not None,physical_truth_verified=False)
        self._finish_read(actor,checks,ident=ident,kind='evaluation_summary',deadline=None if report is None else integer(report.data['expires_at_ms']))
        return value

    def selections(self,actor,ident):
        actor=self.access._fresh(actor,Role.REVIEWER);row=self._row(uuid(ident));request=self._request(row)
        if actor.member.data['id']!=row.data['requested_by']:raise Denied('original evaluation reviewer required')
        self._finish_read(actor,(row,),ident=ident,kind='evaluation_request');return request.model_dump(mode='json')

    def examples(self,actor,ident,*,start=0,limit=20):
        if type(start) is not int or start<0 or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded evaluation result page required')
        actor=self.access._fresh(actor,Role.REVIEWER);row=self._row(uuid(ident))
        if actor.member.data['id']!=row.data['requested_by']:raise Denied('original evaluation reviewer required')
        actor,checks,report,manifest=self._sealed(actor,row);count=integer(report.data['example_count'])
        if start>=count:raise ValueError('evaluation page starts outside report')
        keys=tuple(entry_key(ident,i) for i in range(max(0,start-1),min(count,start+limit)));rows=self.repository.snapshot(keys)
        request=self._request(row)
        def content(data):
            if request.runner=='vision_replay_v1':
                text=data['content_json']
                if (not isinstance(text,str) or not 1<=len(text.encode())<=32768 or 'content' in data):raise ValueError()
                value=json.loads(text)
                if canonical(value)!=text:raise ValueError()
                return value
            if 'content_json' in data:raise ValueError()
            return data['content']
        def entry(index):
            value=rows[entry_key(ident,index)]
            try:
                data=value.data
                if (value.revision!=1 or data['evaluation_id']!=ident or integer(data['index'])!=index or digest(content(data))!=data['content_sha256']
                        or digest({k:v for k,v in data.items() if k!='chain_sha256'})!=data['chain_sha256']):raise ValueError()
                return data
            except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('intact evaluation example required') from exc
        previous=report.data['seed_sha256'] if start==0 else entry(start-1)['chain_sha256'];result=[]
        for index in range(start,min(count,start+limit)):
            data=entry(index)
            if data['previous_chain_sha256']!=previous:raise StoreUnavailable('evaluation chain adjacency failed')
            previous=data['chain_sha256'];result.append({'index':index,**json.loads(canonical(content(data))),'content_sha256':data['content_sha256']})
        if start+len(result)==count and previous!=report.data['chain_sha256']:raise StoreUnavailable('evaluation final chain mismatch')
        actor,new,_,_=self._sealed(actor,row);checks=self._merge((*checks.values(),*new.values(),*rows.values()))
        self.datasets._access(actor,manifest,tuple(checks.values()),'evaluation_examples_read',start,start+len(result)-1,
            deadline=integer(report.data['expires_at_ms']),consumer_id=ident)
        return {'id':ident,'report_sha256':report.data['sha256'],'examples':result,'next_index':None if start+len(result)==count else start+len(result),'diagnostic_only':True,'promotion_eligible':False}

    def list(self,actor,*,limit=20,cursor=None):
        actor=self._viewer(actor)
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded evaluation catalog required')
        rows,last=self.repository.query(prefix='evaluation-catalog#',limit=limit,start_resource=None if cursor is None else 'evaluation-catalog#'+uuid(cursor))
        checks=[];result=[]
        for catalog in rows:
            row=self._row(uuid(catalog.data['id']));checks.extend((catalog,row));result.append(self._base(actor,row))
        self._finish_read(actor,checks,ident=None,kind='evaluation_catalog')
        return {'evaluations':result,'next_cursor':None if last is None else last.split('#',1)[1]}

    def options(self,actor):
        actor=self._viewer(actor)
        self._finish_read(actor,actor.rows,ident=None,kind='evaluation_options')
        return {'runners':['decision_replay_v1',*(['vision_replay_v1'] if self.vision is not None else [])],
            'max_examples':min(1000,self.config.max_steps),'vision_case_window_ms':None if self.vision is None else self.vision.config.max_case_ms,
            'promotion_available':False,'physical_truth_verified':False}

    def _end(self,actor,ident,expected_version,idempotency_key,retire,reason):
        actor=self._viewer(actor);row=self._row(uuid(ident));role=Role.REVIEWER if actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles else Role.OWNER
        actor=self.access._fresh(actor,role)
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact evaluation version required')
        operation=('evaluation-retire:' if retire else 'evaluation-cancel:')+ident
        idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,{'expected_version':expected_version,'reason':reason})
        if prior is not None:return self.job(actor,ident)
        if row.revision!=expected_version:raise StoreConflict('evaluation changed')
        if (retire and row.data['status'] not in {'completed','retired'}) or (not retire and row.data['status'] in {'completed','retired'}):raise StoreConflict('completed evaluation requires explicit retirement')
        runtime=self._runtime();epoch=self.purposes.head();target='retired' if retire else 'cancelled';writes=[]
        if row.data['status']!=target:
            writes.append(Write(row.key,row.revision,{**row.data,'status':target,'lease_token':None,'lease_until_ms':0,'lease_runtime':None}))
            if retire:writes.append(self.purposes.advance(epoch))
        self.access._record(actor,operation,idem,body_hash,{'id':ident},(*writes,self._quota(actor,'end')),(row,runtime,epoch),required_role=role,
            event_details={'evaluation_id':ident,'status':target,'reason':reason})
        return self.job(actor,ident)

    def cancel(self,actor,ident,*,expected_version,idempotency_key):return self._end(actor,ident,expected_version,idempotency_key,False,'cancelled-by-request')

    def retire(self,actor,ident,*,request,expected_version,idempotency_key):
        if not isinstance(request,Consequence) or request.acknowledged is not True:raise Denied('explicit evaluation retirement acknowledgment required')
        return self._end(actor,ident,expected_version,idempotency_key,True,request.reason)
