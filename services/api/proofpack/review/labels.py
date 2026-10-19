"""Versioned operational human judgments; no independent truth or policy authority."""
import hashlib
import json
from typing import Annotated,Literal
from uuid import uuid4

from pydantic import Field,model_validator

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.capture.service import observation_key
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.evidence.originals import original_asset_id,original_capture_enabled,original_permission_binding,validate_original_source
from proofpack.recipes.models import Contract,PartClass,Recipe
from proofpack.recipes.service import revision_key as recipe_revision_key
from proofpack.runtime.control import DATA,integer,sha,uuid
from proofpack.stations.service import inspection_key
from proofpack.capture.provenance import inspection_context
from proofpack.vision.worker_result import WorkerResult

UUIDText=Annotated[str,Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]


class ReviewTuple(Contract):
    before_observation_id:UUIDText
    action_id:UUIDText|None=None
    after_observation_id:UUIDText|None=None

    @model_validator(mode='after')
    def paired(self):
        if (self.action_id is None)!=(self.after_observation_id is None):raise ValueError('paired action and after observation required')
        if self.after_observation_id==self.before_observation_id:raise ValueError('distinct ordered observations required')
        return self


class GroundCount(Contract):
    part_class:PartClass
    count:int=Field(ge=0,le=30)


class LabelRequest(ReviewTuple):
    source_context_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    data_epoch:int=Field(ge=1)
    outcome:Literal['resolved','unresolved','incorrect_finding']
    ground_truth_counts:tuple[GroundCount,...]=Field(min_length=1,max_length=4)
    method:Literal['physical_manual_check','reference_comparison','synthetic_fixture']
    duration_ms:int=Field(ge=1,le=3600000)
    independence_declared:bool
    note:str=Field(min_length=1,max_length=240)

    @model_validator(mode='after')
    def bounded(self):
        if len({item.part_class for item in self.ground_truth_counts})!=len(self.ground_truth_counts) or sum(item.count for item in self.ground_truth_counts)>30:
            raise ValueError('distinct bounded ground truth required')
        if self.outcome=='resolved' and self.action_id is None:raise ValueError('resolved requires a correction tuple')
        if not self.note.strip() or any(ord(c)<32 for c in self.note):raise ValueError('bounded plain review note required')
        return self


def head_key(ident):return Key('state','label#'+uuid(ident))
def label_revision_key(ident,revision):return Key('state','label-revision#'+uuid(ident)+'#'+str(integer(revision)))


class OutcomeLabels:
    def __init__(self,purposes,*,writes_per_minute,max_duration_ms,review_validity_ms):
        if (type(writes_per_minute) is not int or not 1<=writes_per_minute<=100
                or type(max_duration_ms) is not int or not 1<=max_duration_ms<=3600000
                or type(review_validity_ms) is not int or not 1<=review_validity_ms<=60000):raise ValueError('explicit bounded review configuration required')
        self.purposes=purposes;self.access=purposes.access;self.repository=purposes.repository;self.runtime=purposes.runtime
        self.writes_per_minute=writes_per_minute;self.max_duration_ms=max_duration_ms;self.review_validity_ms=review_validity_ms

    def _snapshot(self,actor,tuple_:ReviewTuple):
        actor=self.purposes.candidate(actor)
        beforekey=observation_key(tuple_.before_observation_id);first=self.repository.snapshot((beforekey,))[beforekey]
        if first is None:raise ResourceUnavailable('review observation unavailable')
        try:
            workkey=inspection_key(first.data['inspection_id']);initial=self.repository.snapshot((workkey,))[workkey]
            if initial is None:raise ValueError('inspection provenance missing')
            revkey=recipe_revision_key(initial.data['recipe_id'],integer(initial.data['recipe_revision']))
            keys=[beforekey,workkey,revkey,DATA,RUNTIME]
            if tuple_.action_id is not None:keys.extend((Key('state','action#'+uuid(tuple_.action_id)),observation_key(tuple_.after_observation_id)))
            rows=self.repository.snapshot(tuple(keys));source_rows=[];manifest=[];results=[]
            if rows[beforekey]!=first or rows[workkey]!=initial:raise StoreConflict('review source changed')
            if rows[revkey] is None or rows[revkey].revision!=1:raise ValueError('immutable recipe required')
            recipe=Recipe.model_validate_json(rows[revkey].data['recipe_json'])
            if hashlib.sha256(rows[revkey].data['recipe_json'].encode()).hexdigest()!=rows[revkey].data['sha256']:raise ValueError('recipe integrity failed')
            artifact=sha(initial.data['artifact_sha256']);observations=[rows[beforekey]]
            if tuple_.action_id is not None:
                action=rows[Key('state','action#'+tuple_.action_id)];after=rows[observation_key(tuple_.after_observation_id)]
                if (action is None or after is None or action.data['observation_id']!=tuple_.before_observation_id
                        or action.data['status']!='acknowledged' or integer(after.data['sequence'])<=integer(first.data['sequence'])):
                    raise ValueError('acknowledged ordered tuple required')
                observations.append(after)
            for observation in observations:
                if observation is None or observation.data['status']!='completed' or observation.data['inspection_id']!=initial.data['id']:
                    raise ValueError('completed same-inspection observation required')
                result=WorkerResult.model_validate_json(observation.data['result_json'])
                if result.source_sha256!=sha(observation.data['source_sha256']):raise ValueError('observation hash mismatch')
                binding=inspection_context(initial.data,observation.data['sequence'],observation.data)
                if (digest(binding)!=sha(observation.data['context_sha256'])
                        or observation.data['station_id']!=initial.data['station_id']
                        or integer(observation.data['station_epoch'])!=integer(initial.data['station_epoch'])
                        or observation.data['runtime_instance_id']!=initial.data['runtime_instance_id']
                        or observation.data['originating_session_id']!=initial.data['originating_session_id']):raise ValueError('observation authority provenance mismatch')
                akey=Key('state','asset#'+uuid(observation.data['asset_id']));asset=self.repository.snapshot((akey,))[akey]
                if asset is None:raise ValueError('evidence asset unavailable')
                pkey=Key('state','purpose#'+uuid(asset.data['purpose_id']));source_rows.extend((asset,));purpose=self.repository.snapshot((pkey,))[pkey]
                if (purpose is None or asset.data['status']!='committed' or asset.data['read_denied'] is not False
                        or asset.data['observation_id']!=observation.data['id'] or asset.data['data_origin']!=recipe.data_origin.value
                        or asset.data['sha256']!=sha(observation.data['evidence_sha256']) or asset.data['context_sha256']!=observation.data['context_sha256']
                        or asset.data['input_sha256']!=result.source_sha256 or purpose.data['withdrawn'] is not False
                        or 'operation' not in purpose.data['allowed_uses']):raise ValueError('permitted bound evidence required')
                source_rows.append(purpose)
                manifest.append({'observation_id':observation.data['id'],'observation_version':observation.revision,
                    'asset_id':asset.data['id'],'asset_version':asset.revision,'sha256':asset.data['sha256'],
                    'purpose_id':asset.data['purpose_id'],'purpose_version':purpose.revision,
                    'expires_at_ms':min(integer(asset.data['expires_at_ms']),integer(purpose.data['expires_at_ms']))})
                if observation.data.get('retain_original_frame') is True:
                    originalkey=Key('state','asset#'+original_asset_id(observation.data['id']))
                    original=self.repository.snapshot((originalkey,))[originalkey]
                    if original is None:raise ValueError('selected original source missing')
                    validate_original_source(original,observation,asset)
                    allowed=self.purposes.permitted(original.data['purpose_id'],expires_at_ms=integer(original.data['expires_at_ms']))
                    if (allowed!=purpose or not original_capture_enabled(allowed,self.access)
                            or original_permission_binding((allowed,))!=observation.data.get('original_capture_purpose_binding')
                            or original.data['status']!='committed' or original.data['read_denied'] is not False):
                        raise ValueError('current selected original permission required')
                    source_rows.append(original)
                    manifest.append({'observation_id':observation.data['id'],'observation_version':observation.revision,
                        'asset_id':original.data['id'],'asset_version':original.revision,'sha256':original.data['sha256'],
                        'purpose_id':original.data['purpose_id'],'purpose_version':purpose.revision,
                        'expires_at_ms':min(integer(original.data['expires_at_ms']),integer(purpose.data['expires_at_ms'])),
                        'derivation':'original_transmitted_frame','input_sha256':result.source_sha256,
                        'context_sha256':observation.data['context_sha256'],'calibration_sha256':result.calibration_hash})
                results.append({'observation_id':observation.data['id'],'sequence':integer(observation.data['sequence']),
                    'findings':[item.value for item in result.findings],'reason_codes':list(result.reason_codes),
                    'quality_ok':result.quality_ok,'unknown_regions':result.unknown_regions,'calibration_sha256':result.calibration_hash})
            if len({item['calibration_sha256'] for item in results})!=1:raise ValueError('same calibration geometry required')
            for row in (*source_rows,*actor.rows):
                if row.key in rows and rows[row.key]!=row:raise StoreConflict('review source changed')
                rows[row.key]=row
            if not self.runtime.matches(rows[RUNTIME]) or rows[DATA] is None:raise Denied('current review runtime required')
            if integer(rows[DATA].data['epoch'])<1 or integer(rows[DATA].data.get('changed_at_ms',0))>self.access.now():raise ValueError('current data authority required')
            context={'tuple':tuple_.model_dump(mode='json'),'inspection_id':initial.data['id'],'recipe_id':recipe.recipe_id,
                'recipe_revision':recipe.revision,'recipe_sha256':rows[revkey].data['sha256'],'data_origin':recipe.data_origin.value,
                'artifact_sha256':artifact,'runtime_instance_id':initial.data['runtime_instance_id'],
                'inspection_bindings':{key:value for key,value in binding.items() if key!='sequence'},
                'kit_group':initial.data['kit_id'],'session_group':initial.data['originating_session_id'],
                'operator_group':initial.data['originating_user_id'],'sources':manifest,'observations':results,
                'expected_classes':[item.part_class_id.value for item in recipe.constraints]}
            if tuple_.action_id is not None:context['action']={'id':action.data['id'],'kind':action.data['kind'],'state_version':action.revision}
            deadline=min(item['expires_at_ms'] for item in manifest)
            self._final(actor,rows,deadline)
            return actor,rows,context,deadline
        except (KeyError,TypeError,ValueError,AttributeError) as exc:
            if isinstance(exc,StoreConflict):raise
            raise StoreUnavailable('review provenance or permission unavailable') from exc

    def _final(self,actor,rows,deadline):
        final=self.repository.snapshot(tuple(rows))
        if any(final[key]!=row for key,row in rows.items()):raise StoreConflict('review authority changed')
        self.purposes.candidate(actor)
        if self.access.now()>=deadline:raise StoreUnavailable('review source expired')

    def context(self,actor,tuple_:ReviewTuple):
        actor,rows,context,deadline=self._snapshot(actor,tuple_)
        return {**context,'source_context_sha256':digest(context),'data_epoch':integer(rows[DATA].data['epoch']),
            'remaining_validity_ms':min(self.review_validity_ms,deadline-self.access.now()),'max_duration_ms':self.max_duration_ms,
            'independence_verified':False,'physical_truth_verified':False,'optional_improvement':False}

    def write(self,actor,*,request:LabelRequest,idempotency_key,ident=None,expected_version=None):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if not isinstance(request,LabelRequest):raise ValueError('typed label required')
        if ident is not None and (type(expected_version) is not int or expected_version<1):raise ValueError('expected label head version required')
        body={'request':request.model_dump(mode='json'),'id':ident,'expected_version':expected_version}
        operation='label-create' if ident is None else 'label-revise:'+uuid(ident)
        idem,body_hash,replay=self.access._idempotency(actor,operation,idempotency_key,body)
        if replay is not None:return self.get(actor,replay.data['result']['id'],revision=integer(replay.data['result']['revision']))
        tuple_=ReviewTuple.model_validate_json(json.dumps({key:getattr(request,key) for key in ReviewTuple.model_fields}))
        actor,rows,context,deadline=self._snapshot(actor,tuple_)
        if (digest(context)!=request.source_context_sha256 or integer(rows[DATA].data['epoch'])!=request.data_epoch):raise StoreConflict('refresh current source review')
        if (request.duration_ms>self.max_duration_ms or not set(context['expected_classes'])<={item.part_class.value for item in request.ground_truth_counts}
                or (request.method=='physical_manual_check' and context['data_origin']!='physical')
                or (request.method=='synthetic_fixture' and context['data_origin']!='synthetic')):raise ValueError('review method, counts or duration outside scope')
        ident=str(uuid4()) if ident is None else uuid(ident);key=head_key(ident);head=self.repository.snapshot((key,))[key]
        previous=None;number=1
        if expected_version is not None or head is not None:
            if head is None or type(expected_version) is not int or head.revision!=expected_version:raise StoreConflict('label revision changed')
            previous=self._revision(head,integer(head.data['latest_revision']))
            if previous.data['tuple']!=context['tuple']:raise Denied('label revision cannot retarget source tuple')
            number=integer(head.data['latest_revision'])+1;rows[key]=head;rows[previous.key]=previous
        quota_key=Key('state','label-quota#'+actor.scope);quota=self.repository.snapshot((quota_key,))[quota_key];minute=self.access.now()//60000
        if quota is not None and integer(quota.data['minute'])>minute:raise StoreUnavailable('review allowance clock moved backwards')
        count=0 if quota is None or integer(quota.data['minute'])!=minute else integer(quota.data['count'])
        if count>=self.writes_per_minute:raise ReviewRateLimited('review write allowance exhausted')
        conflicts=[]
        if actor.member.data['id']==context['operator_group']:conflicts.append('originating_operator')
        if previous is not None and previous.data['reviewer_id']!=actor.member.data['id']:conflicts.append('different_revision_author')
        record={'id':ident,'revision':number,'tuple':context['tuple'],'source_context':context,'source_context_sha256':digest(context),
            'outcome':request.outcome,'ground_truth_counts':[item.model_dump(mode='json') for item in request.ground_truth_counts],
            'method':request.method,'duration_ms':request.duration_ms,'note':request.note,'reviewer_id':actor.member.data['id'],
            'independence_declared':request.independence_declared,'independence_verified':False,'physical_truth_verified':False,
            'conflict_codes':conflicts,'optional_improvement':False,'created_at_ms':self.access.now(),
            'previous_sha256':None if previous is None else previous.data['sha256'],'data_epoch_before':request.data_epoch}
        record['sha256']=digest(record);self._final(actor,rows,deadline);self.access._fresh(actor,Role.REVIEWER)
        try:
            committed=self.access._record(actor,operation,idem,body_hash,{'id':ident,'revision':number},
                (Write(key,None if head is None else head.revision,{'id':ident,'latest_revision':number,'sha256':record['sha256']}),
                 Write(label_revision_key(ident,number),None,record),self.purposes.advance(rows[DATA]),
                 Write(quota_key,None if quota is None else quota.revision,{'minute':minute,'count':count+1})),tuple(rows.values()),
                required_role=Role.REVIEWER,event_details={'label_id':ident,'revision':number,'source_context_sha256':record['source_context_sha256']},
                before_commit=lambda:self._final(actor,rows,deadline))
        except StoreConflict:
            # A concurrent identical request may have committed before this
            # request's final read-set check. Reuse only that exact receipt;
            # get() below still revalidates current source/role/time permission.
            existing=self.repository.snapshot((idem,))[idem]
            if existing is None or existing.data.get('body_hash')!=body_hash:raise
            self.access._fresh(actor,Role.REVIEWER)
            committed=existing.data['result']
        return self.get(actor,committed['id'],revision=integer(committed['revision']))

    def _revision(self,head,number):
        key=label_revision_key(head.data['id'],number);row=self.repository.snapshot((key,))[key]
        if row is None or row.revision!=1 or row.data['sha256']!=digest({k:v for k,v in row.data.items() if k!='sha256'}):raise StoreUnavailable('immutable label integrity unavailable')
        if integer(row.data['revision'])!=number or row.data['id']!=head.data['id']:raise StoreUnavailable('label revision mismatch')
        if number==integer(head.data['latest_revision']) and row.data['sha256']!=head.data['sha256']:raise StoreUnavailable('label head mismatch')
        return row

    def get(self,actor,ident,*,revision=None):
        actor=self.purposes.candidate(actor);key=head_key(ident);head=self.repository.snapshot((key,))[key]
        if head is None:raise ResourceUnavailable('label unavailable')
        number=integer(head.data['latest_revision']) if revision is None else revision
        if type(number) is not int or not 1<=number<=integer(head.data['latest_revision']):raise ResourceUnavailable('label revision unavailable')
        row=self._revision(head,number);tuple_=ReviewTuple.model_validate_json(canonical(row.data['tuple']))
        actor,rows,context,deadline=self._snapshot(actor,tuple_)
        if digest(context)!=row.data['source_context_sha256']:raise StoreUnavailable('label source changed')
        if number>1:
            previous=self._revision(head,number-1)
            if row.data['previous_sha256']!=previous.data['sha256']:raise StoreUnavailable('label lineage unavailable')
            rows[previous.key]=previous
        rows[key]=head;rows[row.key]=row;self._final(actor,rows,deadline)
        return {**json.loads(canonical(row.data)),'state_version':head.revision,'latest_revision':integer(head.data['latest_revision']),
            'remaining_validity_ms':min(self.review_validity_ms,deadline-self.access.now()),'historical':True,'machine_pass':False}

    def list(self,actor,*,limit=20,cursor=None):
        actor=self.purposes.candidate(actor)
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded label page required')
        start=None if cursor is None else head_key(cursor).resource
        heads,last=self.repository.query(prefix='label#',limit=limit,start_resource=start);result=[]
        for row in heads:
            try:
                current=self.get(actor,row.data['id']);result.append({key:current[key] for key in ('id','revision','state_version','outcome','reviewer_id','source_context_sha256','independence_verified')})
            except (StoreUnavailable,StoreConflict):continue
        self.purposes.candidate(actor)
        return {'labels':result,'next_cursor':None if last is None else last[len('label#'):]}


class ReviewRateLimited(RuntimeError):pass
