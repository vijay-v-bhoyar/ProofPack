"""Leased, epoch-bound dataset metadata; never training or independent benchmark proof."""
from dataclasses import asdict, dataclass
import hashlib
import json
import time
from uuid import uuid4
from pydantic import Field, model_validator

from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import RUNTIME, ResourceUnavailable
from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.erasure import job_key
from proofpack.evidence.job_authority import issue
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable
from proofpack.recipes.models import Contract, Identifier
from proofpack.review.datasets import Split
from proofpack.review.labels import UUIDText, head_key, label_revision_key
from proofpack.runtime.control import DATA, integer, uuid, sha


class DatasetLimited(RuntimeError): pass
class SplitConflict(StoreConflict): pass


@dataclass(frozen=True)
class DatasetConfig:
    max_examples: int
    jobs_per_minute: int
    step_attempts_per_minute: int
    lifetime_ms: int
    lease_ms: int
    max_steps: int
    reads_per_minute: int

    def __post_init__(self):
        if any(type(v) is not int or not lo <= v <= hi for v, lo, hi in (
            (self.max_examples,1,1000),(self.jobs_per_minute,1,20),(self.step_attempts_per_minute,1,120),
            (self.lifetime_ms,1000,3600000),(self.lease_ms,1000,60000),(self.max_steps,1,10000),(self.reads_per_minute,1,120))):
            raise ValueError('explicit bounded dataset configuration required')


class PermissionBinding(Contract):
    id: UUIDText
    state_version: int = Field(ge=1, le=9007199254740991)


class Selection(Contract):
    label_id: UUIDText
    label_revision: int = Field(ge=1, le=9007199254740991)
    split: Split
    permissions: tuple[PermissionBinding,...] = Field(min_length=1,max_length=2)

    @model_validator(mode='after')
    def distinct(self):
        if len({p.id for p in self.permissions}) != len(self.permissions): raise ValueError('distinct permission bindings required')
        return self


class ManifestRequest(Contract):
    selections: tuple[Selection,...] = Field(min_length=1,max_length=1000)
    historical_diagnostic_acknowledged: bool
    frozen_holdout_acknowledged: bool

    @model_validator(mode='after')
    def valid(self):
        if len({x.label_id for x in self.selections}) != len(self.selections): raise ValueError('distinct selected labels required')
        if not self.historical_diagnostic_acknowledged or (any(x.split==Split.FROZEN_TEST for x in self.selections) and not self.frozen_holdout_acknowledged):
            raise ValueError('explicit diagnostic and applicable frozen-data limitations required')
        return self


class Consequence(Contract):
    acknowledged: bool
    reason: Identifier


def manifest_key(ident): return Key('state','dataset-manifest#'+uuid(ident))
def entry_key(ident,index): return Key('state','dataset-example#'+uuid(ident)+'#'+str(integer(index)).zfill(4))
def group_key(ident): return Key('state','dataset-group#'+sha(ident))


class DatasetManifests:
    def __init__(self, labels, improvement, config):
        if (not isinstance(config,DatasetConfig) or labels.access is not improvement.access or labels.runtime is not improvement.runtime
                or labels.repository is not improvement.repository): raise ValueError('shared dataset authority and explicit bounds required')
        self.labels=labels;self.improvement=improvement;self.config=config;self.access=labels.access;self.runtime=labels.runtime
        self.repository=labels.repository;self.purposes=labels.purposes
        self.configuration=digest({'bounds':asdict(config),'improvement':asdict(improvement.config),'storage':improvement.configuration})

    def _runtime(self):
        row=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(row): raise StoreUnavailable('current dataset runtime required')
        return row

    def _row(self,ident):
        row=self.repository.snapshot((job_key(ident),))[job_key(ident)]
        if row is None or row.data.get('kind')!='dataset_manifest': raise ResourceUnavailable('dataset unavailable')
        return row

    def _request(self,row):
        try:
            text=row.data['request_json']
            if len(text.encode())>262144 or hashlib.sha256(text.encode()).hexdigest()!=row.data['request_sha256']: raise ValueError()
            value=ManifestRequest.model_validate_json(text)
            if len(value.selections)!=integer(row.data['example_count']): raise ValueError()
            return value
        except (KeyError,TypeError,ValueError) as exc: raise StoreUnavailable('intact dataset selection required') from exc

    def _quota(self,actor,kind):
        key=Key('state','dataset-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute: raise StoreUnavailable('dataset allowance clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        maximum=self.config.jobs_per_minute if kind=='create' else self.config.reads_per_minute if kind=='read' else self.config.step_attempts_per_minute
        if count>=maximum: raise DatasetLimited('dataset allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def create(self,actor,*,request,idempotency_key):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if not isinstance(request,ManifestRequest): raise ValueError('typed dataset selections required')
        if len(request.selections)>min(self.config.max_examples,self.config.max_steps): raise DatasetLimited('dataset example/step capacity exceeded')
        body=request.model_dump(mode='json');text=canonical(body)
        if len(text.encode())>262144: raise DatasetLimited('dataset request size exceeded')
        idem,body_hash,prior=self.access._idempotency(actor,'dataset-create',idempotency_key,body)
        if prior is not None:return self.job(actor,prior.data['result']['id'])
        runtime=self._runtime();epoch=self.purposes.head();now=self.access.now();ident=str(uuid4());seed=digest({'dataset_id':ident,'request_sha256':hashlib.sha256(text.encode()).hexdigest()})
        data={'id':ident,'kind':'dataset_manifest','requested_by':actor.member.data['id'],'configuration':self.configuration,
            'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,'environment':self.runtime.environment,
            'data_epoch':integer(epoch.data['epoch']),'created_at_ms':now,'expires_at_ms':min(now+self.config.lifetime_ms,integer(actor.session.data['expires_at_ms'])),
            'request_json':text,'request_sha256':hashlib.sha256(text.encode()).hexdigest(),'example_count':len(request.selections),
            'status':'queued','processed':0,'steps_reserved':0,'chain_sha256':seed,'seed_sha256':seed,'validation_runtime':None,
            'effective_deadline_ms':min(now+self.config.lifetime_ms,integer(actor.session.data['expires_at_ms'])),
            'splits':{s.value:0 for s in Split},'manifest_sha256':None,'failure_reason':None,'lease_token':None,'lease_until_ms':0,'lease_runtime':None}
        data['processing_authority']=issue(self.access,actor,data,Role.REVIEWER)
        self.access._record(actor,'dataset-create',idem,body_hash,{'id':ident},
            (Write(job_key(ident),None,data),Write(Key('state','dataset-catalog#'+ident),None,{'id':ident}),self._quota(actor,'create')),
            (runtime,epoch),required_role=Role.REVIEWER,event_details={'dataset_id':ident,'request_sha256':data['request_sha256'],'example_count':len(request.selections)})
        return self.job(actor,ident)

    def _guard(self,actor,row):
        actor=self.access._fresh(actor,Role.REVIEWER);runtime=self._runtime();epoch=self.purposes.head();data=row.data
        if (data['configuration']!=self.configuration or data['artifact_sha256']!=self.runtime.artifact_sha256
                or data['controls_sha256']!=self.runtime.controls_sha256 or data['environment']!=self.runtime.environment
                or integer(data['data_epoch'])!=integer(epoch.data['epoch'])
                or not integer(data['created_at_ms'])<=self.access.now()<min(integer(data['expires_at_ms']),integer(data['effective_deadline_ms']))):
            raise StoreConflict('dataset binding or lifetime changed')
        return actor,runtime,epoch

    @staticmethod
    def _group(row):
        try:
            if (row is None or row.data['id']!=row.key.resource.split('#',1)[1] or row.data['category'] not in {'kit','session','operator'}
                    or row.data['split'] not in {s.value for s in Split} or integer(row.data['generation'])<1
                    or digest({k:v for k,v in row.data.items() if k!='sha256'})!=row.data['sha256']): raise ValueError()
        except (KeyError,TypeError,ValueError) as exc: raise StoreUnavailable('intact dataset group required') from exc
        return row

    def _example(self,actor,selection,gate=lambda:None):
        gate()
        value=self.labels.get(actor,selection.label_id,revision=selection.label_revision)
        if value['latest_revision']!=selection.label_revision or value['independence_verified'] is not False or value['physical_truth_verified'] is not False:
            raise StoreConflict('current unqualified label revision required')
        head=self.repository.snapshot((head_key(selection.label_id),))[head_key(selection.label_id)]
        if head is None or integer(head.data['latest_revision'])!=selection.label_revision:raise StoreConflict('current label head required')
        revision=self.labels._revision(head,selection.label_revision)
        if revision.data['sha256']!=value['sha256']:raise StoreConflict('dataset label changed')
        source=value['source_context'];needed={x['asset_id'] for x in source['sources']};covered=set();checks=[head,revision];permissions=[];deadline=9007199254740991
        for binding in selection.permissions:
            gate()
            phead,grant=self.improvement._load(binding.id);subset=needed & {x['id'] for x in grant.data['scope']['assets']}
            if grant.data.get('derived_review_metadata_allowed') is not True:raise Denied('explicit derived review metadata permission required')
            if not subset:raise Denied('each dataset permission must cover a selected source')
            actor,rows,expires=self.improvement.authorize(actor,binding.id,asset_ids=tuple(sorted(subset)),expected_version=binding.state_version)
            checks.extend((phead,grant,*rows.values()));covered.update(subset);deadline=min(deadline,expires)
            permissions.append({'id':binding.id,'state_version':binding.state_version,'grant_sha256':grant.data['sha256']})
        if covered!=needed:raise Denied('all dataset sources require separate improvement permission')
        content={'label_id':value['id'],'label_revision':selection.label_revision,'label_sha256':value['sha256'],
            'source_context_sha256':value['source_context_sha256'],'split':selection.split.value,'data_origin':source['data_origin'],
            'sources':[{k:x[k] for k in ('asset_id','sha256')} for x in source['sources']],
            'permissions':permissions,'groups':[], 'physical_truth_verified':False,'independence_verified':False,
            'outcome':value['outcome'],'ground_truth_counts':value['ground_truth_counts'],'method':value['method'],'duration_ms':integer(value['duration_ms']),
            'prior_exposure_unknown':True,'independent_benchmark_qualified':False}
        assignments=[]
        for category,name in (('kit','kit_group'),('session','session_group'),('operator','operator_group')):
            ident=digest({'category':category,'group':source[name]});key=group_key(ident);row=self.repository.snapshot((key,))[key]
            if row is not None:
                self._group(row)
                if row.data['split']!=selection.split.value:raise SplitConflict('dataset group split conflict')
                checks.append(row);generation=integer(row.data['generation'])
            else:
                generation=1;record={'id':ident,'category':category,'split':selection.split.value,'generation':1,'original_split':selection.split.value,'created_at_ms':self.access.now()}
                record['sha256']=digest(record);assignments.append(Write(key,None,record))
            content['groups'].append({'id':ident,'category':category,'generation':generation})
        return json.loads(canonical(content)),checks,assignments,deadline

    def source_case(self,actor,manifest,sealed,index,gate=lambda:None):
        """Current exact prepared example and its complete authorization snapshots."""
        gate();actor,binding,current=self._sealed(actor,manifest)
        if current!=sealed:raise StoreConflict('dataset receipt changed')
        if type(index) is not int or not 0<=index<integer(sealed.data['example_count']):raise ValueError('bounded dataset example index required')
        selection=self._request(manifest).selections[index]
        content,checks,assignments,deadline=self._example(actor,selection,gate)
        if assignments:raise StoreUnavailable('retained dataset group assignments required')
        keys=tuple(entry_key(manifest.data['id'],i) for i in range(max(0,index-1),index+1));rows=self.repository.snapshot(keys)
        source=self._entry(rows[entry_key(manifest.data['id'],index)],manifest.data['id'],index)
        previous=sealed.data['seed_sha256'] if index==0 else self._entry(rows[keys[0]],manifest.data['id'],index-1)['chain_sha256']
        if (source['previous_chain_sha256']!=previous or source['content_sha256']!=digest(content)
                or (index+1==integer(sealed.data['example_count']) and source['chain_sha256']!=sealed.data['chain_sha256'])):
            raise StoreUnavailable('exact intact dataset example required')
        label=self.labels.get(actor,selection.label_id,revision=selection.label_revision)
        if label['sha256']!=content['label_sha256'] or label['source_context_sha256']!=content['source_context_sha256']:
            raise StoreConflict('dataset label source changed')
        gate()
        return content,label,source,self._merge((*binding.values(),*checks,*rows.values())),min(deadline,integer(sealed.data['expires_at_ms']))

    def _lease(self,ident,token,started,gate):
        gate();row=self._row(ident);runtime=self._runtime()
        if (row.data['status']!='processing' or row.data['lease_token']!=token or row.data['lease_runtime']!=asdict(self.runtime.handle)
                or self.access.now()>=integer(row.data['lease_until_ms']) or not 0<=time.monotonic_ns()-started<self.config.lease_ms*1000000):
            raise StoreConflict('current dataset lease required')
        return row,runtime

    def _commit_transition(self,actor,lease,*,kind,writes,checks,started,deadline,gate,failure_reason=None):
        # This event is an atomic discovery link, not a new reservation or grant.
        event={'kind':kind,'dataset_id':lease.data['id'],'request_sha256':lease.data['request_sha256'],
            'index':integer(lease.data['processed']),'prior_job_revision':lease.revision,'at_ms':self.access.now()}
        if failure_reason is not None:event['failure_reason']=failure_reason
        audit=Write(Key('events','dataset-transition#'+str(uuid4())),None,event)
        def final():
            gate();self.access._fresh(actor,Role.REVIEWER)
            current,_=self._lease(lease.data['id'],lease.data['lease_token'],started,gate)
            if current!=lease:raise StoreConflict('dataset lease changed during linked preparation')
            # No SDK/authority call follows these nonrenewable checks.
            if (self.access.now()>=min(integer(deadline),integer(lease.data['expires_at_ms']),
                    integer(lease.data['effective_deadline_ms']),integer(lease.data['lease_until_ms']),
                    integer(actor.session.data['expires_at_ms']))
                    or not 0<=time.monotonic_ns()-started<self.config.lease_ms*1000000):
                raise StoreUnavailable('dataset linked commit deadline expired')
        self.access._commit_linked(kind,(*writes,audit),checks,before_commit=final)

    def advance(self,actor,ident,*,expected_version,idempotency_key,execution_gate=None):
        if execution_gate is not None and not callable(execution_gate):raise ValueError('trusted dataset checkpoint required')
        def gate():
            if execution_gate is not None:execution_gate()
        gate();row=self._row(uuid(ident));actor=self.access._fresh(actor,Role.REVIEWER)
        if actor.member.data['id']!=row.data['requested_by']:raise Denied('dataset requestor required')
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact dataset job version required')
        idem,body_hash,prior=self.access._idempotency(actor,'dataset-step:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        actor,runtime,epoch=self._guard(actor,row);request=self._request(row)
        if (row.revision!=expected_version or row.data['status'] not in {'queued','processing'}
                or (row.data['status']=='processing' and self.access.now()<integer(row.data['lease_until_ms']))):raise StoreConflict('available dataset step required')
        def admission():
            gate()
            if not integer(row.data['created_at_ms'])<=self.access.now()<min(integer(row.data['expires_at_ms']),integer(row.data['effective_deadline_ms']),integer(actor.session.data['expires_at_ms'])):
                raise StoreUnavailable('dataset admission deadline expired')
        if integer(row.data['steps_reserved'])>=self.config.max_steps:
            self.access._record(actor,'dataset-step:'+ident,idem,body_hash,{'id':ident},
                (Write(row.key,row.revision,{**row.data,'status':'failed','failure_reason':'STEP_BUDGET_EXHAUSTED'}),self._quota(actor,'step')),
                (runtime,epoch),required_role=Role.REVIEWER,before_commit=admission)
            return self.job(actor,ident)
        data=json.loads(canonical(row.data));current=asdict(self.runtime.handle)
        if data['validation_runtime']!=current:
            data.update(processed=0,chain_sha256=data['seed_sha256'],splits={s.value:0 for s in Split},validation_runtime=current,effective_deadline_ms=data['expires_at_ms'])
        token=str(uuid4());started=time.monotonic_ns()
        data.update(status='processing',steps_reserved=integer(data['steps_reserved'])+1,lease_token=token,
            lease_until_ms=min(data['expires_at_ms'],self.access.now()+self.config.lease_ms),lease_runtime=current,
            processing_authority=issue(self.access,actor,row.data,Role.REVIEWER))
        result=self.access._record(actor,'dataset-step:'+ident,idem,body_hash,{'id':ident,'attempt':token},
            (Write(row.key,row.revision,data),self._quota(actor,'step')),(runtime,epoch),required_role=Role.REVIEWER,before_commit=admission)
        if result.get('attempt')!=token:return self.job(actor,ident)
        lease,runtime=self._lease(ident,token,started,gate);index=integer(lease.data['processed'])
        try:
            gate();content,checks,assignments,expires=self._example(actor,request.selections[index],gate);gate()
        except (Denied,ResourceUnavailable,StoreUnavailable,StoreConflict,ValueError) as exc:
            lease,runtime=self._lease(ident,token,started,gate);actor=self.access._fresh(actor,Role.REVIEWER)
            reason='SPLIT_CONFLICT' if isinstance(exc,SplitConflict) else 'SOURCE_OR_PERMISSION_HELD'
            gate();current,current_runtime=self._lease(ident,token,started,gate)
            if current!=lease:raise StoreConflict('dataset failure lease changed before commit')
            if (self.access.now()>=min(integer(lease.data['expires_at_ms']),integer(lease.data['effective_deadline_ms']),integer(actor.session.data['expires_at_ms']))
                    or not 0<=time.monotonic_ns()-started<self.config.lease_ms*1000000):
                raise StoreUnavailable('dataset failure deadline expired')
            self._commit_transition(actor,lease,kind='dataset-source-failed',writes=(Write(lease.key,lease.revision,{**lease.data,'status':'failed','failure_reason':reason,'lease_token':None,'lease_until_ms':0,'lease_runtime':None}),),checks=(*actor.rows,current_runtime),started=started,deadline=lease.data['effective_deadline_ms'],gate=gate,failure_reason=reason)
            return self.job(actor,ident)
        lease,runtime=self._lease(ident,token,started,gate);actor,runtime,epoch=self._guard(actor,lease);data=json.loads(canonical(lease.data))
        effective=min(integer(data['effective_deadline_ms']),expires)
        if self.access.now()>=effective:raise StoreUnavailable('dataset source expired')
        record={'schema_version':1,'dataset_id':ident,'index':index,'content':content,'content_sha256':digest(content),'previous_chain_sha256':data['chain_sha256']}
        record['chain_sha256']=digest(record);key=entry_key(ident,index);existing=self.repository.snapshot((key,))[key];writes=list(assignments)
        if existing is None:writes.append(Write(key,None,record))
        elif existing.revision!=1 or canonical(existing.data)!=canonical(record):raise StoreUnavailable('dataset entry cannot be overwritten')
        else:checks.append(existing)
        data.update(processed=index+1,chain_sha256=record['chain_sha256'],effective_deadline_ms=effective,status='queued',lease_token=None,lease_until_ms=0,lease_runtime=None)
        data['splits'][content['split']]+=1
        if index+1==integer(data['example_count']):
            sealed={k:data[k] for k in ('id','request_sha256','example_count','chain_sha256','seed_sha256','configuration','artifact_sha256','controls_sha256','environment','data_epoch','created_at_ms','validation_runtime','splits')}
            sealed.update(schema_version=1,expires_at_ms=effective,prior_exposure_unknown=True,independent_benchmark_qualified=False)
            sealed['sha256']=digest(sealed);writes.append(Write(manifest_key(ident),None,sealed));data.update(status='completed',manifest_sha256=sealed['sha256'])
        expected=self._merge((*checks,*actor.rows,runtime,epoch));gate();actor=self.access._fresh(actor,Role.REVIEWER)
        current,current_runtime=self._lease(ident,token,started,gate)
        if current!=lease:raise StoreConflict('dataset lease changed before commit')
        expected=self._merge((*expected.values(),*actor.rows,current_runtime));gate()
        # Linked preparation below is followed by its own final nonrenewable guard.
        if (self.access.now()>=min(effective,integer(lease.data['lease_until_ms']),integer(actor.session.data['expires_at_ms']))
                or not 0<=time.monotonic_ns()-started<self.config.lease_ms*1000000):
            raise StoreUnavailable('dataset commit deadline expired')
        self._commit_transition(actor,lease,kind='dataset-example-committed',writes=(Write(lease.key,lease.revision,data),*writes),checks=tuple(r for k,r in expected.items() if k not in {w.key for w in writes} and k!=lease.key),started=started,deadline=effective,gate=gate)
        return self.job(actor,ident)

    @staticmethod
    def _merge(rows):
        values={}
        for row in rows:
            if row is None:raise StoreUnavailable('dataset dependency missing')
            if row.key in values and values[row.key]!=row:raise StoreConflict('dataset dependency changed')
            values[row.key]=row
        if len(values)>90:raise StoreUnavailable('bounded dataset commit required')
        return values

    def _sealed(self,actor,row):
        actor,runtime,epoch=self._guard(actor,row);key=manifest_key(row.data['id']);sealed=self.repository.snapshot((key,))[key]
        try:
            if (row.data['status']!='completed' or sealed is None or sealed.revision!=1 or sealed.data['id']!=row.data['id']
                    or digest({k:v for k,v in sealed.data.items() if k!='sha256'})!=sealed.data['sha256']
                    or sealed.data['sha256']!=row.data['manifest_sha256'] or sealed.data['chain_sha256']!=row.data['chain_sha256']
                    or sealed.data['validation_runtime']!=asdict(self.runtime.handle) or self.access.now()>=integer(sealed.data['expires_at_ms'])):raise ValueError()
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('current intact dataset receipt required') from exc
        return actor,self._merge((*actor.rows,row,sealed,runtime,epoch)),sealed

    def job(self,actor,ident):
        actor=self.access._fresh(actor);role=Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER
        actor=self.access._fresh(actor,role);row=self._row(uuid(ident));usable=False;available=False
        if role==Role.REVIEWER:
            try:
                self._guard(actor,row);available=True
                self._sealed(actor,row);usable=True
            except (Denied,StoreConflict,StoreUnavailable):pass
        data=row.data;remaining=max(0,integer(data['lease_until_ms'])-self.access.now());self.access._fresh(actor,role)
        can_end=actor.member.data['id']==data['requested_by'] and Role.REVIEWER in actor.principal.roles
        if not can_end and Role.OWNER in actor.principal.roles:
            try:self.access._fresh(actor,Role.OWNER);can_end=True
            except Denied:pass
        return {'id':ident,'kind':'dataset_manifest','state_version':row.revision,'status':data['status'],'example_count':integer(data['example_count']),
            'prepared_count':integer(data['processed']),'steps_reserved':integer(data['steps_reserved']),'splits':json.loads(canonical(data['splits'])),
            'manifest_sha256':data['manifest_sha256'],'remaining_ms':max(0,integer(data['expires_at_ms'])-self.access.now()),'lease_remaining_ms':remaining,
            'receipt_usable':usable,'failure_reason':data['failure_reason'],'prior_exposure_unknown':True,'independent_benchmark_qualified':False,
            'can_advance':bool(available and actor.member.data['id']==data['requested_by'] and data['status'] in {'queued','processing'} and remaining==0),
            'can_cancel':bool(can_end and data['status'] in {'queued','processing','failed'}),'can_retire':bool(can_end and data['status']=='completed')}

    def _access(self,actor,row,checks,kind,first,last,*,deadline=None,consumer_id=None):
        if consumer_id is not None:consumer_id=uuid(consumer_id)
        quota=self._quota(actor,'read');actor=self.access._fresh(actor,Role.REVIEWER);event=Key('events','dataset-access#'+str(uuid4()))
        expected=self._merge((*checks,*actor.rows))
        deadline=min(integer(actor.session.data['expires_at_ms']),deadline if deadline is not None else integer(actor.session.data['expires_at_ms']))
        def final_read():
            self.access._fresh(actor,Role.REVIEWER)
            if self.access.now()>=deadline:raise StoreUnavailable('dataset read deadline expired')
        self.access._commit_linked(kind,(Write(event,None,{'kind':kind,'dataset_id':row.data['id'],'manifest_sha256':row.data['manifest_sha256'],
            'user_id':actor.member.data['id'],'access_version':integer(actor.member.data['access_version']),'first_index':first,'last_index':last,
            'at_ms':self.access.now(),'prior_exposure_unknown':True,**({'consumer_job_id':consumer_id} if consumer_id is not None else {})}),quota),tuple(expected.values()),before_commit=final_read)
        # Audit records admission, even when delivery is subsequently withheld.
        actor=self.access._fresh(actor,Role.REVIEWER)
        expected=self._merge((*expected.values(),*actor.rows))
        current=self.repository.snapshot(tuple(expected))
        if any(current[key]!=value for key,value in expected.items()):raise StoreConflict('dataset read dependencies changed')
        if self.access.now()>=deadline:raise StoreUnavailable('dataset delivery deadline expired')

    def selections(self,actor,ident):
        actor=self.access._fresh(actor,Role.REVIEWER);row=self._row(uuid(ident));request=self._request(row);runtime=self._runtime();epoch=self.purposes.head()
        self._access(actor,row,(row,runtime,epoch),'dataset_request_read',0,len(request.selections)-1)
        return request.model_dump(mode='json')

    def examples(self,actor,ident,*,start=0,limit=20):
        if type(start) is not int or start<0 or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded dataset page required')
        row=self._row(uuid(ident));actor,checks,sealed=self._sealed(actor,row);count=integer(sealed.data['example_count'])
        if start>=count:raise ValueError('dataset page starts outside manifest')
        keys=tuple(entry_key(ident,i) for i in range(max(0,start-1),min(count,start+limit)));rows=self.repository.snapshot(keys);result=[]
        previous=sealed.data['seed_sha256'] if start==0 else self._entry(rows[entry_key(ident,start-1)],ident,start-1)['chain_sha256']
        for index in range(start,min(count,start+limit)):
            data=self._entry(rows[entry_key(ident,index)],ident,index)
            if data['previous_chain_sha256']!=previous:raise StoreUnavailable('dataset chain adjacency failed')
            previous=data['chain_sha256'];result.append({'index':index,**json.loads(canonical(data['content'])),'content_sha256':data['content_sha256']})
        if start+len(result)==count and previous!=sealed.data['chain_sha256']:raise StoreUnavailable('dataset final chain mismatch')
        checks=self._merge((*checks.values(),*rows.values()));actor,new,_=self._sealed(actor,row);checks=self._merge((*checks.values(),*new.values()))
        self._access(actor,row,tuple(checks.values()),'dataset_examples_read',start,start+len(result)-1,deadline=integer(sealed.data['expires_at_ms']))
        return {'dataset_id':ident,'manifest_sha256':sealed.data['sha256'],'examples':result,'next_index':None if start+len(result)==count else start+len(result),
            'prior_exposure_unknown':True,'independent_benchmark_qualified':False}

    @staticmethod
    def _entry(row,ident,index):
        try:
            if row is None or row.revision!=1:raise ValueError()
            data=row.data
            if (data['schema_version']!=1 or data['dataset_id']!=ident or integer(data['index'])!=index
                    or digest(data['content'])!=data['content_sha256'] or digest({k:v for k,v in data.items() if k!='chain_sha256'})!=data['chain_sha256']):raise ValueError()
            return data
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('intact dataset example required') from exc

    def _end(self,actor,ident,expected_version,idempotency_key,retire,reason):
        actor=self.access._fresh(actor);row=self._row(uuid(ident));role=Role.REVIEWER if actor.member.data['id']==row.data['requested_by'] and Role.REVIEWER in actor.principal.roles else Role.OWNER
        actor=self.access._fresh(actor,role)
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact dataset version required')
        operation=('dataset-retire:' if retire else 'dataset-cancel:')+ident
        idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,{'expected_version':expected_version,'reason':reason})
        if prior is not None:return self.job(actor,ident)
        if row.revision!=expected_version:raise StoreConflict('dataset changed')
        target='retired' if retire else 'cancelled'
        if (retire and row.data['status'] not in {'completed','retired'}) or (not retire and row.data['status'] in {'completed','retired'}):raise StoreConflict('use explicit dataset retirement for completed data')
        epoch=self.purposes.head();runtime=self._runtime();writes=[]
        if row.data['status']!=target:
            writes.append(Write(row.key,row.revision,{**row.data,'status':target,'lease_token':None,'lease_until_ms':0,'lease_runtime':None}))
            if retire:writes.append(self.purposes.advance(epoch))
        self.access._record(actor,operation,idem,body_hash,{'id':ident},(*writes,self._quota(actor,'end')),(row,epoch,runtime),required_role=role,
            event_details={'dataset_id':ident,'status':target,'reason':reason})
        return self.job(actor,ident)

    def cancel(self,actor,ident,*,expected_version,idempotency_key):return self._end(actor,ident,expected_version,idempotency_key,False,'cancelled-by-request')

    def retire(self,actor,ident,*,request,expected_version,idempotency_key):
        if not isinstance(request,Consequence) or request.acknowledged is not True:raise Denied('explicit dataset retirement acknowledgment required')
        return self._end(actor,ident,expected_version,idempotency_key,True,request.reason)

    def group(self,actor,ident):
        actor=self.purposes.candidate(actor);key=group_key(ident);row=self._group(self.repository.snapshot((key,))[key]);self.purposes.candidate(actor)
        return {**json.loads(canonical(row.data)),'state_version':row.revision,'can_declassify':row.data['split']!='DEVELOPMENT','independent_benchmark_qualified':False}

    def declassify(self,actor,ident,*,request,expected_version,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER)
        if not isinstance(request,Consequence) or request.acknowledged is not True or type(expected_version) is not int or expected_version<1:raise Denied('explicit exact-version development declassification required')
        idem,body_hash,prior=self.access._idempotency(actor,'dataset-declassify:'+sha(ident),idempotency_key,{'request':request.model_dump(mode='json'),'expected_version':expected_version})
        if prior is not None:return self.group(actor,ident)
        key=group_key(ident);row=self._group(self.repository.snapshot((key,))[key]);epoch=self.purposes.head();runtime=self._runtime()
        if row.revision!=expected_version:raise StoreConflict('dataset group changed')
        writes=[]
        if row.data['split']!='DEVELOPMENT':
            data={**row.data,'split':'DEVELOPMENT','generation':integer(row.data['generation'])+1,'reason':request.reason,'changed_at_ms':self.access.now()};data.pop('sha256');data['sha256']=digest(data)
            writes.extend((Write(key,row.revision,data),self.purposes.advance(epoch),Write(Key('events','dataset-declassification#'+str(uuid4())),None,
                {'group_id':ident,'from_split':row.data['split'],'to_split':'DEVELOPMENT','at_ms':self.access.now(),'reason':request.reason})))
        self.access._record(actor,'dataset-declassify:'+ident,idem,body_hash,{'id':ident},(*writes,self._quota(actor,'end')),(row,epoch,runtime),
            event_details={'group_id':ident,'to_split':'DEVELOPMENT','reason':request.reason})
        return self.group(actor,ident)

    def list(self,actor,*,limit=20,cursor=None):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded dataset catalog required')
        rows,last=self.repository.query(prefix='dataset-catalog#',limit=limit,start_resource=None if cursor is None else 'dataset-catalog#'+uuid(cursor))
        return {'datasets':[self.job(actor,row.data['id']) for row in rows],'next_cursor':None if last is None else last.split('#',1)[1]}
