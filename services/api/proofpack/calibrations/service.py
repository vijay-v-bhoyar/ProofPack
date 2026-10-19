"""Immutable calibration drafts and actual diagnostic reports; no live-pass writer."""
import json
import time
from uuid import uuid4

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.models import Enrollment,QualificationRequest
from proofpack.calibrations.dependencies import active_calibration,physical_assurance,canonical,digest
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.runtime.control import DATA,integer,sha,uuid
from proofpack.vision.calibration import CalibrationProfile
from proofpack.vision.worker import WorkerBusy,WorkerUnavailable


class CalibrationRateLimited(RuntimeError):pass


def catalog_key(ident):return Key('state','calibration#'+uuid(ident))
def revision_key(ident,number):
    if type(number) is not int or number<1:raise ValueError('positive calibration revision required')
    return Key('state','calibration-revision#'+uuid(ident)+'#'+str(number))
def active_key(ident):return Key('state','calibration-active#'+uuid(ident))
def report_key(ident):return Key('state','calibration-report#'+uuid(ident))
def job_key(ident):return Key('state','calibration-job#'+uuid(ident))


class CalibrationService:
    def __init__(self,references,*,max_runs_per_minute,max_diagnostic_ms):
        if type(max_runs_per_minute) is not int or not 1<=max_runs_per_minute<=100 or type(max_diagnostic_ms) is not int or not 1000<=max_diagnostic_ms<=60000:
            raise ValueError('explicit bounded calibration allowance/window required')
        self.references=references;self.purposes=references.purposes;self.access=references.access;self.runtime=references.runtime
        self.repository=references.repository;self.registry=references.registry;self.objects=references.objects
        self.max_runs_per_minute=max_runs_per_minute;self.max_diagnostic_ms=max_diagnostic_ms

    def _authority(self,actor):
        actor=self.access._fresh(actor,Role.OWNER);data=self.purposes.head();runtime=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(runtime):raise Denied('current calibration runtime required')
        return actor,data,runtime

    def _quota(self,actor,data,runtime):
        key=Key('state','calibration-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('calibration allowance clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        if count>=self.max_runs_per_minute:raise CalibrationRateLimited('calibration allowance exhausted')
        self.access._fresh(actor,Role.OWNER)
        self.access._commit((Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1}),),(*actor.rows,data,runtime))

    def _merge(self,*groups):
        rows={}
        for group in groups:
            for row in group:
                if row is None:continue
                if row.key in rows and rows[row.key]!=row:raise StoreConflict('calibration authority changed')
                rows[row.key]=row
        return rows

    def _check(self,actor,rows,deadline=None,started=None):
        fresh=self.access._fresh(actor,Role.OWNER);expected=self._merge(rows.values(),fresh.rows)
        current=self.repository.snapshot(tuple(expected))
        if any(current[key]!=row for key,row in expected.items()):raise StoreConflict('calibration context changed')
        self.access._fresh(fresh,Role.OWNER)
        if deadline is not None and (self.access.now()>=deadline or (time.monotonic_ns()-started)//1000000>=self.max_diagnostic_ms):raise StoreUnavailable('calibration diagnostic expired')
        return fresh

    def _sources(self,actor,ids,origin):
        rows={};manifest=[];receipts={};deadline=None
        for ident in dict.fromkeys(ids):
            snapshot,asset,receipt,expires=self.references.snapshot(actor,ident)
            if asset.data['data_origin']!=origin:raise Denied('calibration source origin mismatch')
            rows=self._merge(rows.values(),snapshot.values());purpose=snapshot[Key('state','purpose#'+asset.data['purpose_id'])]
            manifest.append({'asset_id':ident,'purpose_id':asset.data['purpose_id'],'asset_state_version':asset.revision,
                'purpose_state_version':purpose.revision,'sha256':asset.data['sha256']})
            receipts[ident]=receipt;deadline=expires if deadline is None else min(deadline,expires)
        return rows,manifest,receipts,deadline

    def _reserve(self,actor,*,operation,idempotency_key,body,ident,kind,data,runtime,head=None):
        idem,body_hash,replay=self.access._idempotency(actor,operation,idempotency_key,body)
        if replay is not None:return idem,body_hash,None,self.job(actor,replay.data['result']['job_id'])
        jid=str(uuid4());now=self.access.now();job={'id':jid,'calibration_id':ident,'kind':kind,'status':'processing','created_at_ms':now,
            'deadline_ms':now+self.max_diagnostic_ms,'artifact_sha256':self.runtime.artifact_sha256,'environment':self.runtime.environment,
            'runtime_epoch':integer(runtime.data['runtime_epoch']),'data_epoch':integer(data.data['epoch']),'owner_user_id':actor.member.data['id']}
        writes=[Write(job_key(jid),None,job)]
        if head is not None:writes.append(Write(head.key,head.revision,{**head.data,'last_job_id':jid,'report_id':None,'status':'qualifying' if kind=='qualification' else 'enrolling'}))
        result=self.access._record(actor,operation,idem,body_hash,{'id':ident,'job_id':jid},tuple(writes),
            (*(() if head is None else (head,)),data,runtime),event_details={'calibration_id':ident,'job_id':jid})
        if result['job_id']!=jid:return idem,body_hash,None,self.job(actor,result['job_id'])
        return idem,body_hash,jid,None

    def _fail(self,jid):
        try:
            key=job_key(jid);row=self.repository.snapshot((key,))[key]
            if row is None or row.data['status']!='processing':return
            hkey=catalog_key(row.data['calibration_id']);head=self.repository.snapshot((hkey,))[hkey]
            writes=[Write(key,row.revision,{**row.data,'status':'failed','reason':'diagnostic_unavailable_or_authority_changed'})]
            if head is not None and head.data['last_job_id']==jid and head.data['status'] in {'enrolling','qualifying'}:
                writes.append(Write(hkey,head.revision,{**head.data,'status':'qualification_failed' if row.data['kind']=='qualification' else 'enrollment_failed','report_id':None}))
            self.repository.transact(tuple(writes))
        except (StoreConflict,StoreUnavailable):pass

    def _job_rows(self,jid,idem,body_hash,ident):
        headkey=catalog_key(ident);key=job_key(jid);rows=self.repository.snapshot((key,idem,headkey))
        if rows[key] is None or rows[key].data['status']!='processing' or rows[idem] is None or rows[idem].data['body_hash']!=body_hash:
            raise StoreConflict('calibration operation changed')
        return rows

    def _pending_head(self,ident,jid,original):
        row=self.repository.snapshot((catalog_key(ident),))[catalog_key(ident)]
        if row is None or row.revision!=original.revision+1 or row.data['last_job_id']!=jid or row.data['status'] not in {'enrolling','qualifying'}:
            raise StoreConflict('calibration operation superseded')
        return row

    def job(self,actor,ident):
        self.purposes.candidate(actor);key=job_key(ident);row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('calibration job unavailable')
        self.purposes.candidate(actor)
        status=row.data['status']
        if status=='processing' and self.access.now()>=integer(row.data['deadline_ms']):status='expired'
        return {'id':ident,'calibration_id':row.data['calibration_id'],'status':status,'kind':row.data['kind'],
            'created_at_ms':integer(row.data['created_at_ms']),'remaining_ms':max(0,integer(row.data['deadline_ms'])-self.access.now()),
            'reason':row.data.get('reason'),'report_id':row.data.get('report_id')}

    def enroll(self,actor,*,request:Enrollment,idempotency_key,ident=None,expected_version=None):
        actor,data,runtime=self._authority(actor)
        if not isinstance(request,Enrollment):raise ValueError('typed enrollment required')
        body={'request':request.model_dump(mode='json'),'id':ident,'expected_version':expected_version}
        operation='calibration-create' if ident is None else 'calibration-save:'+uuid(ident)
        _,_,previous=self.access._idempotency(actor,operation,idempotency_key,body)
        if previous is not None:return self.job(actor,previous.data['result']['job_id'])
        head=None;number=1
        if ident is not None:
            head=self.repository.snapshot((catalog_key(ident),))[catalog_key(ident)]
            if head is None:raise ResourceUnavailable('calibration unavailable')
            if type(expected_version) is not int or head.revision!=expected_version:raise StoreConflict('calibration draft changed')
            number=integer(head.data['latest_revision'])+1
        else:ident=str(uuid4())
        self._quota(actor,data,runtime)
        idem,body_hash,jid,replay=self._reserve(actor,operation=operation,idempotency_key=idempotency_key,body=body,ident=ident,
            kind='enrollment',data=data,runtime=runtime,head=head)
        if replay is not None:return replay
        started=time.monotonic_ns()
        try:
            rows,manifest,receipts,expires=self._sources(actor,[request.reference_asset_id],request.data_origin.value)
            pending=None if head is None else self._pending_head(ident,jid,head)
            rows=self._merge(rows.values(),(data,runtime,pending));deadline=min(expires,integer(self.repository.snapshot((job_key(jid),))[job_key(jid)].data['deadline_ms']))
            with self.registry.diagnostic(runtime_id=self.runtime.instance_id) as worker:
                actor=self._check(actor,rows,deadline,started);payload=self.objects.get(receipts[request.reference_asset_id])
                actor=self._check(actor,rows,deadline,started)
                diagnostic=worker.calibration(payload,parameters={'mode':'enroll','profile_id':ident,'revision':number,
                    'camera_id':request.camera_id,'mat_version':request.mat_version,'data_origin':request.data_origin.value,'settings':request.settings.model_dump(mode='json')})
                actor=self._check(actor,rows,deadline,started)
            state=self._job_rows(jid,idem,body_hash,ident);job=state[job_key(jid)];current=state[catalog_key(ident)]
            if (head is None and current is not None) or (head is not None and current!=pending):
                raise StoreConflict('calibration enrollment superseded')
            profile=diagnostic.profile if diagnostic.accepted else None
            revision={'request_json':canonical(request.model_dump(mode='json')),'profile_json':None if profile is None else profile.model_dump_json(),
                'profile_sha256':None if profile is None else profile.content_hash,'diagnostic_json':diagnostic.model_dump_json(),
                'reference_manifest':manifest,'data_epoch':integer(data.data['epoch']),'environment':self.runtime.environment,
                'artifact_sha256':self.runtime.artifact_sha256,'created_at_ms':self.access.now()}
            catalog={'id':ident,'name':request.name,'camera_id':request.camera_id,'latest_revision':number,'last_job_id':jid,
                'report_id':None,'status':'draft' if diagnostic.accepted else 'enrollment_failed','retired':False,
                'created_by':actor.member.data['id'] if current is None else current.data['created_by']}
            self.access._commit_linked('calibration_enrolled',(Write(catalog_key(ident),None if current is None else current.revision,catalog),Write(revision_key(ident,number),None,revision),
                Write(job.key,job.revision,{**job.data,'status':'completed','enrollment_accepted':diagnostic.accepted}),
                Write(Key('events','calibration#'+str(uuid4())),None,{'kind':'calibration_enrolled','calibration_id':ident,'revision':number,'accepted':diagnostic.accepted,
                    'profile_sha256':revision['profile_sha256'],'actor_scope':actor.scope,'at_ms':self.access.now()})),
                tuple(self._merge(rows.values(),actor.rows,state.values()).values()),before_commit=lambda:self._check(actor,rows,deadline,started))
            return self.job(actor,jid)
        except BaseException as exc:
            self._fail(jid)
            if isinstance(exc,WorkerBusy):raise CalibrationRateLimited('shared decoder capacity exhausted') from exc
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('calibration decoder unavailable') from exc
            raise

    def draft(self,actor,ident):
        actor=self.purposes.candidate(actor);key=catalog_key(ident);head=self.repository.snapshot((key,))[key]
        if head is None:raise ResourceUnavailable('calibration unavailable')
        rev=revision_key(ident,integer(head.data['latest_revision']));rows=self.repository.snapshot((key,rev))
        if rows[key]!=head or rows[rev] is None or rows[rev].revision!=1:raise StoreConflict('calibration draft changed')
        self.purposes.candidate(actor);record=rows[rev].data
        collected=self._merge(rows.values(),actor.rows);deadline=0
        try:
            active_rows,active,deadline=active_calibration(self.repository,self.access,self.runtime,ident)
            collected=self._merge(collected.values(),active_rows.values())
            current={'effective_approved':self.access.now()<deadline,'active_revision':integer(json.loads(active.data['profile_json'])['revision']) if 'profile_json' in active.data else None}
        except (StoreUnavailable,StoreConflict):current={'effective_approved':False,'active_revision':None}
        final=self.repository.snapshot(tuple(collected))
        if any(final[key]!=row for key,row in collected.items()):raise StoreConflict('calibration changed during read')
        self.purposes.candidate(actor)
        current['effective_approved']=bool(current['effective_approved'] and self.access.now()<deadline)
        return {**head.data,'latest_revision':integer(head.data['latest_revision']),'state_version':head.revision,'current':current,
            'request':json.loads(record['request_json']),'profile':None if record['profile_json'] is None else json.loads(record['profile_json']),
            'profile_sha256':record['profile_sha256'],'enrollment':json.loads(record['diagnostic_json'])}

    def qualify(self,actor,*,ident,expected_version,request:QualificationRequest,idempotency_key):
        actor,data,runtime=self._authority(actor)
        if not isinstance(request,QualificationRequest):raise ValueError('typed diagnostic cases required')
        head=self.repository.snapshot((catalog_key(ident),))[catalog_key(ident)]
        if head is None:raise ResourceUnavailable('calibration unavailable')
        body={'id':ident,'expected_version':expected_version,'request':request.model_dump(mode='json')}
        # Resolve a completed retry before requiring the original now-advanced catalog version.
        idem,body_hash,replay=self.access._idempotency(actor,'calibration-qualify:'+ident,idempotency_key,body)
        if replay is not None:return self.job(actor,replay.data['result']['job_id'])
        if type(expected_version) is not int or head.revision!=expected_version or head.data['retired'] is not False:raise StoreConflict('current non-retired calibration draft required')
        revkey=revision_key(ident,integer(head.data['latest_revision']));rev=self.repository.snapshot((revkey,))[revkey]
        if rev is None or rev.revision!=1 or rev.data['profile_json'] is None:raise StoreUnavailable('successful enrollment required')
        profile=CalibrationProfile.model_validate_json(rev.data['profile_json'])
        if profile.content_hash!=rev.data['profile_sha256']:raise StoreUnavailable('profile integrity failed')
        self._quota(actor,data,runtime)
        idem,body_hash,jid,replayed=self._reserve(actor,operation='calibration-qualify:'+ident,idempotency_key=idempotency_key,body=body,ident=ident,
            kind='qualification',data=data,runtime=runtime,head=head)
        if replayed is not None:return replayed
        started=time.monotonic_ns()
        try:
            enrolled=json.loads(rev.data['request_json'])['reference_asset_id']
            rows,manifest,receipts,expires=self._sources(actor,[enrolled,*[item.asset_id for item in request.cases]],profile.data_origin.value)
            pending=self._pending_head(ident,jid,head)
            rows=self._merge(rows.values(),(rev,data,runtime,pending));deadline=min(expires,integer(self.repository.snapshot((job_key(jid),))[job_key(jid)].data['deadline_ms']));results=[]
            with self.registry.diagnostic(runtime_id=self.runtime.instance_id) as worker:
                for case in request.cases:
                    actor=self._check(actor,rows,deadline,started);payload=self.objects.get(receipts[case.asset_id])
                    actor=self._check(actor,rows,deadline,started)
                    result=worker.calibration(payload,parameters={'mode':'check','profile':profile.model_dump(mode='json')})
                    results.append({'asset_id':case.asset_id,'expected':case.expected,'matched':result.accepted==(case.expected=='supported'),'diagnostic_json':result.model_dump_json()})
            actor=self._check(actor,rows,deadline,started);state=self._job_rows(jid,idem,body_hash,ident);current=state[catalog_key(ident)];job=state[job_key(jid)]
            if current!=pending:raise StoreConflict('qualification superseded')
            passed=all(item['matched'] for item in results)
            report={'id':jid,'calibration_id':ident,'revision':profile.revision,'profile_sha256':profile.content_hash,'passed':passed,'results':results,
                'reference_manifest':manifest,'data_epoch':integer(data.data['epoch']),'environment':self.runtime.environment,'artifact_sha256':self.runtime.artifact_sha256,
                'expires_at_ms':expires,'created_at_ms':self.access.now(),'reviewer_id':actor.member.data['id'],'independence_verified':False,'physical_truth_verified':False}
            report['sha256']=digest(report)
            self.access._commit_linked('calibration_qualified',(Write(report_key(jid),None,report),Write(current.key,current.revision,{**current.data,'status':'qualified' if passed else 'qualification_failed','report_id':jid}),
                Write(job.key,job.revision,{**job.data,'status':'completed','report_id':jid}),
                Write(Key('events','calibration#'+str(uuid4())),None,{'kind':'calibration_qualified','calibration_id':ident,'report_id':jid,'passed':passed,'report_sha256':report['sha256'],
                    'actor_scope':actor.scope,'at_ms':self.access.now()})),tuple(self._merge(rows.values(),actor.rows,state.values()).values()),before_commit=lambda:self._check(actor,rows,deadline,started))
            return self.job(actor,jid)
        except BaseException as exc:
            self._fail(jid)
            if isinstance(exc,WorkerBusy):raise CalibrationRateLimited('shared decoder capacity exhausted') from exc
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('calibration decoder unavailable') from exc
            raise

    def _report(self,actor,ident,rid):
        self.purposes.candidate(actor);key=report_key(rid);row=self.repository.snapshot((key,))[key]
        if row is None or row.data['calibration_id']!=ident:raise ResourceUnavailable('calibration report unavailable')
        data=row.data
        if row.revision!=1 or data['sha256']!=digest({k:v for k,v in data.items() if k!='sha256'}):raise StoreUnavailable('calibration report integrity failed')
        rows,manifest,receipts,expires=self._sources(actor,[item['asset_id'] for item in data['reference_manifest']],
            json.loads(data['results'][0]['diagnostic_json'])['profile']['data_origin'])
        if manifest!=data['reference_manifest'] or self.access.now()>=integer(data['expires_at_ms']):raise StoreUnavailable('calibration report dependencies unavailable')
        return row,rows,receipts,min(expires,integer(data['expires_at_ms']))

    def report(self,actor,ident,rid):
        actor=self.purposes.candidate(actor);row,rows,receipts,deadline=self._report(actor,ident,rid)
        head=self.repository.snapshot((catalog_key(ident),))[catalog_key(ident)];data=self.purposes.head()
        expected=self._merge(rows.values(),actor.rows,(row,head,data));final=self.repository.snapshot(tuple(expected))
        if any(final[key]!=item for key,item in expected.items()):raise StoreConflict('calibration report authority changed')
        self.purposes.candidate(actor)
        if self.access.now()>=deadline:raise StoreUnavailable('calibration report expired')
        physical=json.loads(row.data['results'][0]['diagnostic_json'])['profile']['data_origin']=='physical'
        return {**row.data,'results':[{'asset_id':item['asset_id'],'expected':item['expected'],'matched':item['matched'],
                'diagnostic':json.loads(item['diagnostic_json'])} for item in row.data['results']],
            'revision':integer(row.data['revision']),'data_epoch':integer(row.data['data_epoch']),
            'expires_at_ms':integer(row.data['expires_at_ms']),'created_at_ms':integer(row.data['created_at_ms']),
            'remaining_validity_ms':max(0,deadline-self.access.now()),'state_version':None if head is None else head.revision,
            'eligible_for_approval':bool(head is not None and head.data['report_id']==rid and head.data['retired'] is False and row.data['passed']
                and integer(head.data['latest_revision'])==integer(row.data['revision'])
                and not physical and self.runtime.environment!='beta'
                and row.data['environment']==self.runtime.environment and row.data['artifact_sha256']==self.runtime.artifact_sha256
                and integer(row.data['data_epoch'])==integer(data.data['epoch'])),'requires_physical_assurance':physical}

    def list(self,actor,*,view='approved',limit=20,cursor=None):
        actor=self.access._fresh(actor) if view=='approved' else self.purposes.candidate(actor)
        if view not in {'approved','candidates'} or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded calibration view required')
        start=None if cursor is None else catalog_key(cursor).resource
        rows,last=self.repository.query(prefix='calibration#',limit=limit,start_resource=start);result=[]
        for row in rows:
            if view=='candidates':
                result.append({'id':row.data['id'],'name':row.data['name'],'camera_id':row.data['camera_id'],'state_version':row.revision,
                    'latest_revision':integer(row.data['latest_revision']),'status':row.data['status'],'retired':row.data['retired']})
            else:
                try:
                    bindings,active,deadline=active_calibration(self.repository,self.access,self.runtime,row.data['id'])
                    expected=self._merge(bindings.values(),actor.rows);final=self.repository.snapshot(tuple(expected))
                    if any(final[key]!=item for key,item in expected.items()):raise StoreConflict('calibration changed')
                    self.access._fresh(actor);remaining=deadline-self.access.now()
                    if remaining>0:result.append({'id':row.data['id'],'name':active.data.get('name',row.data['name']),
                        'camera_id':active.data.get('camera_id',row.data['camera_id']),'state_version':active.revision,'remaining_validity_ms':remaining})
                except (StoreUnavailable,StoreConflict):continue
        if view=='approved':self.access._fresh(actor)
        else:self.purposes.candidate(actor)
        return {'calibrations':result,'next_cursor':None if last is None else last[len('calibration#'):]}

    def approve(self,actor,*,ident,expected_version,report_id,idempotency_key,physical_assurance_id=None):
        actor,data,runtime=self._authority(actor);body={'id':ident,'expected_version':expected_version,'report_id':report_id,'physical_assurance_id':physical_assurance_id}
        idem,body_hash,replay=self.access._idempotency(actor,'calibration-approve',idempotency_key,body)
        if replay is not None:return self.draft(actor,ident)
        head=self.repository.snapshot((catalog_key(ident),))[catalog_key(ident)]
        if head is None or type(expected_version) is not int or head.revision!=expected_version or head.data['report_id']!=report_id or head.data['retired'] is not False:raise StoreConflict('current reviewed calibration report required')
        report,sources,receipts,deadline=self._report(actor,ident,report_id);revkey=revision_key(ident,integer(head.data['latest_revision']));rev=self.repository.snapshot((revkey,))[revkey]
        if rev is None or rev.revision!=1 or rev.data['profile_json'] is None:raise StoreUnavailable('immutable qualified profile required')
        profile=CalibrationProfile.model_validate_json(rev.data['profile_json'])
        if (report.data['passed'] is not True or report.data['profile_sha256']!=profile.content_hash or integer(report.data['revision'])!=profile.revision
                or report.data['environment']!=self.runtime.environment or report.data['artifact_sha256']!=self.runtime.artifact_sha256
                or integer(report.data['data_epoch'])!=integer(data.data['epoch'])):raise Denied('matching successful current calibration report required')
        if self.runtime.environment=='beta' and profile.data_origin.value!='physical':raise Denied('physical qualification required for beta')
        assurance_rows={}
        if profile.data_origin.value=='physical':
            if physical_assurance_id is None:raise Denied('reviewed physical ruler/lens/source evidence required')
            assurance_rows,expires=physical_assurance(self.repository,self.access,self.runtime,physical_assurance_id,profile,report.data['sha256'],
                report.data['reference_manifest'],integer(data.data['epoch']),sources,
                (head.data['created_by'],report.data['reviewer_id'],actor.member.data['id']))
            deadline=min(deadline,expires)
        for receipt in receipts.values():self.objects.validate(receipt)
        akey=active_key(ident);active=self.repository.snapshot((akey,))[akey];dependency_id=str(uuid4());new_version=1 if active is None else active.revision+1
        rows=self._merge(sources.values(),actor.rows,(data,runtime,head,rev,report,active),assurance_rows.values());self._check(actor,rows,deadline,time.monotonic_ns())
        dependency={'environment':self.runtime.environment,'profile_sha256':profile.content_hash,'profile_state_version':new_version,
            'data_epoch':integer(data.data['epoch']),'reference_manifest':report.data['reference_manifest'],'expires_at_ms':deadline,
            'report_id':report_id,'report_sha256':report.data['sha256'],'physical_assurance_id':physical_assurance_id}
        approved={'id':ident,'name':head.data['name'],'camera_id':profile.camera_id,'status':'approved','environment':self.runtime.environment,
            'data_origin':profile.data_origin.value,'profile_json':profile.model_dump_json(),'profile_sha256':profile.content_hash,
            'dependency_receipt_id':dependency_id,'physical_assurance_id':physical_assurance_id}
        approved.update(enrolled_by=head.data['created_by'],qualified_by=report.data['reviewer_id'],approved_by=actor.member.data['id'])
        self.access._record(actor,'calibration-approve',idem,body_hash,{'id':ident},
            (Write(akey,None if active is None else active.revision,approved),Write(Key('state','calibration-dependencies#'+dependency_id),None,dependency),
             Write(head.key,head.revision,{**head.data,'status':'approved'})),tuple(rows.values()),
            event_details={'calibration_id':ident,'report_id':report_id,'profile_sha256':profile.content_hash,'independence_verified':False})
        return self.draft(actor,ident)

    def retire(self,actor,*,ident,expected_version,reason,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER)
        if not isinstance(reason,str) or not 1<=len(reason)<=120 or any(ord(c)<32 for c in reason):raise ValueError('bounded retirement reason required')
        body={'id':ident,'expected_version':expected_version,'reason':reason};idem,body_hash,replay=self.access._idempotency(actor,'calibration-retire',idempotency_key,body)
        if replay is not None:return self.draft(actor,ident)
        key=catalog_key(ident);akey=active_key(ident);rows=self.repository.snapshot((key,akey));head,active=rows[key],rows[akey]
        if head is None:raise ResourceUnavailable('calibration unavailable')
        if type(expected_version) is not int or head.revision!=expected_version:raise StoreConflict('calibration changed')
        writes=[Write(key,head.revision,{**head.data,'retired':True,'status':'retired','report_id':None})]
        if active is not None:writes.append(Write(akey,active.revision,{**active.data,'status':'retired'}))
        self.access._record(actor,'calibration-retire',idem,body_hash,{'id':ident},tuple(writes),tuple(row for row in rows.values() if row is not None),
            event_details={'calibration_id':ident,'reason':reason})
        return self.draft(actor,ident)
