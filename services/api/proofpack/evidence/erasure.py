"""Reviewed denial and resumable live-version removal; full erasure remains pending."""
from dataclasses import asdict
import json
import time
from uuid import uuid4

from proofpack.auth.policy import Denied,Role
from proofpack.evidence.job_authority import issue as processing_authority
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.objects import ObjectReceipt
from proofpack.evidence.erasure_models import ErasurePreview,ErasureConfirmation
from proofpack.evidence.erasure_objects import ErasureObjects
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.runtime.control import DATA,integer,sha,uuid


class ErasureLimited(RuntimeError):pass
def preview_key(ident):return Key('state','erasure-preview#'+uuid(ident))
def job_key(ident):return Key('state','maintenance-job#'+uuid(ident))


class AssetErasure:
    def __init__(self,purposes,frames,references,*,review_ms,jobs_per_minute,lease_ms,version_page_size):
        for value,low,high in ((review_ms,1,60000),(jobs_per_minute,1,100),(lease_ms,1000,60000)):
            if type(value) is not int or not low<=value<=high:raise ValueError('explicit bounded erasure configuration required')
        self.objects=ErasureObjects(frames,references,page_size=version_page_size)
        if frames.config.deployment!=purposes.repository.deployment:raise ValueError('shared erasure deployment required')
        self.purposes=purposes;self.access=purposes.access;self.runtime=purposes.runtime;self.repository=purposes.repository
        self.review_ms=review_ms;self.jobs_per_minute=jobs_per_minute;self.lease_ms=lease_ms;self.storage=digest(asdict(frames.config))

    @staticmethod
    def _merge(*groups):
        rows={}
        for group in groups:
            for row in group:
                if row is None:continue
                if row.key in rows and rows[row.key]!=row:raise StoreConflict('erasure authority changed')
                rows[row.key]=row
        return rows

    def _quota(self,actor,kind):
        key=Key('state','erasure-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('erasure allowance clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        if count>=self.jobs_per_minute:raise ErasureLimited('erasure allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def _current(self):
        row=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(row):raise Denied('current runtime required for erasure admission')
        return row

    def _asset(self,ident):
        key=Key('state','asset#'+uuid(ident));row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('selected asset unavailable')
        data=row.data
        if data.get('storage_binding_sha256')!=self.storage:raise StoreUnavailable('verified original asset storage binding required')
        try:
            if data.get('kind')=='reference':kind='reference';receipt=ObjectReceipt(**{**data['object_receipt'],'byte_length':integer(data['object_receipt']['byte_length'])})
            elif data.get('derivation') in {'rectified_roi_jpeg','original_transmitted_frame'}:
                kind='frame';receipt=ObjectReceipt(ident,data['object_key'],data['object_version'],data['sha256'],data['context_sha256'],integer(data['byte_length']),data['content_type'])
            else:raise ValueError('supported asset namespace required')
            store=self.objects.store(kind);store._params(ident,receipt.version_id)
            if (receipt.asset_id!=ident or receipt.key!=store.key(ident) or receipt.source_sha256!=sha(data['sha256'])
                    or receipt.byte_length!=integer(data['byte_length']) or receipt.content_type!=data['content_type']):raise ValueError('exact asset receipt required')
            sha(receipt.context_sha256)
            return row,{'id':ident,'kind':kind,'sha256':data['sha256'],'asset_revision':row.revision,'receipt_sha256':digest(asdict(receipt))}
        except (KeyError,ValueError,TypeError) as exc:raise StoreUnavailable('owned asset identity unavailable') from exc

    @staticmethod
    def _scope(row):
        try:
            scope=row.data['scope']
            if (scope['schema_version']!=1 or scope['kind']!='selected_live_asset_versions' or digest(scope)!=sha(row.data['scope_sha256'])
                    or not isinstance(scope['assets'],list) or not 1<=len(scope['assets'])<=16
                    or len({a['id'] for a in scope['assets']})!=len(scope['assets'])):raise ValueError()
            for asset in scope['assets']:uuid(asset['id']);sha(asset['sha256']);sha(asset['receipt_sha256']);integer(asset['asset_revision'])
            sha(scope['storage_binding_sha256'])
            return scope
        except (KeyError,ValueError,TypeError) as exc:raise StoreUnavailable('immutable erasure scope unavailable') from exc

    def preview(self,actor,*,request,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER)
        if not isinstance(request,ErasurePreview):raise ValueError('typed selected asset scope required')
        idem,body_hash,prior=self.access._idempotency(actor,'erasure-preview',idempotency_key,request.model_dump(mode='json'))
        if prior is not None:return self.preview_read(actor,prior.data['result']['id'])
        runtime=self._current();data=self.purposes.head();assets=[];rows=[]
        for ident in sorted(request.asset_ids):
            row,selected=self._asset(ident)
            if row.data.get('status')!='committed' or row.data.get('deletion_job_id') is not None:raise StoreConflict('asset already absent or assigned to erasure')
            assets.append(selected);rows.append(row)
        scope={'schema_version':1,'kind':'selected_live_asset_versions','assets':assets,'storage_binding_sha256':self.storage}
        ident=str(uuid4());created_at=self.access.now();preview={'created_at_ms':created_at,'id':ident,'status':'preview','scope':scope,'scope_sha256':digest(scope),'data_epoch':integer(data.data['epoch']),
            'data_revision':data.revision,'expires_at_ms':created_at+self.review_ms,'owner_user_id':actor.member.data['id'],
            'owner_session_id':actor.session.data['id'],'owner_access_version':integer(actor.member.data['access_version']),'job_id':None}
        result=self.access._record(actor,'erasure-preview',idem,body_hash,{'id':ident},
            (Write(preview_key(ident),None,preview),self._quota(actor,'preview')),tuple(self._merge(actor.rows,rows,(data,runtime)).values()),
            event_details={'preview_id':ident,'scope_sha256':preview['scope_sha256'],'asset_count':len(assets)})
        return self.preview_read(actor,result['id'])

    def preview_read(self,actor,ident):
        actor=self.access._fresh(actor,Role.OWNER);key=preview_key(ident);row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('erasure preview unavailable')
        scope=self._scope(row);data=self.purposes.head();expected=self._merge(actor.rows,(row,data));valid=True
        for target in scope['assets']:
            try:
                asset,actual=self._asset(target['id']);valid=valid and actual==target;expected=self._merge(expected.values(),(asset,))
            except (StoreUnavailable,ResourceUnavailable):valid=False
        final=self.repository.snapshot(tuple(expected))
        if any(final[k]!=v for k,v in expected.items()):raise StoreConflict('erasure preview changed')
        actor=self.access._fresh(actor,Role.OWNER);remaining=max(0,integer(row.data['expires_at_ms'])-self.access.now())
        bound=(row.data['owner_user_id'],row.data['owner_session_id'],integer(row.data['owner_access_version']))==(actor.member.data['id'],actor.session.data['id'],integer(actor.member.data['access_version']))
        return {'id':ident,'state_version':row.revision,'scope':json.loads(canonical(scope)),'scope_sha256':row.data['scope_sha256'],
            'remaining_ms':remaining,'status':row.data['status'],'job_id':row.data['job_id'],
            'can_confirm':bool(valid and bound and remaining>0 and scope['storage_binding_sha256']==self.storage and row.data['status']=='preview'
                and data.revision==integer(row.data['data_revision']) and integer(data.data['epoch'])==integer(row.data['data_epoch'])),
            'erasure_complete':False,'remaining_duties':['dependent_metadata','orphans_and_restore','backups','recipient_copies']}

    def _review_fresh(self,preview,started_at_ms):
        if not max(started_at_ms,integer(preview.data['created_at_ms']))<=self.access.now()<integer(preview.data['expires_at_ms']):
            raise StoreConflict('review expired or clock reversed before irreversible commit')

    def confirm(self,actor,*,request,expected_version,idempotency_key):
        access,runtime_service,repository,purposes,objects=self.access,self.runtime,self.repository,self.purposes,self.objects
        frames,references=objects.frames,objects.references
        clients=(frames.client,references.client);storage=self.storage;clock=access.clock_ms
        settings=(self.review_ms,self.jobs_per_minute,self.lease_ms,objects.page_size)
        actor=self.access._fresh(actor,Role.OWNER)
        if not isinstance(request,ErasureConfirmation) or type(expected_version) is not int or expected_version<1:raise ValueError('typed exact erasure confirmation required')
        body={**request.model_dump(mode='json'),'expected_version':expected_version}
        idem,body_hash,prior=self.access._idempotency(actor,'erasure-confirm',idempotency_key,body)
        if prior is not None:return self.job(actor,prior.data['result']['id'])
        key=preview_key(request.preview_id);preview=self.repository.snapshot((key,))[key]
        if preview is None:raise ResourceUnavailable('erasure preview unavailable')
        scope=self._scope(preview);runtime=self._current();data=self.purposes.head()
        if (preview.revision!=expected_version or preview.data['status']!='preview' or preview.data['scope_sha256']!=request.confirmed_digest
                or scope['storage_binding_sha256']!=self.storage or self.access.now()>=integer(preview.data['expires_at_ms'])
                or data.revision!=integer(preview.data['data_revision']) or integer(data.data['epoch'])!=integer(preview.data['data_epoch'])):
            raise StoreConflict('fresh exact erasure review required')
        if (preview.data['owner_user_id'],preview.data['owner_session_id'],integer(preview.data['owner_access_version']))!=(actor.member.data['id'],actor.session.data['id'],integer(actor.member.data['access_version'])):
            raise Denied('original current review owner/session required')
        jid=str(uuid4());writes=[];rows=[];now=self.access.now()
        for target in scope['assets']:
            asset,actual=self._asset(target['id'])
            if actual!=target or asset.data.get('status')!='committed' or asset.data.get('deletion_job_id') is not None:raise StoreConflict('reviewed asset changed')
            rows.append(asset);writes.append(Write(asset.key,asset.revision,{**asset.data,'read_denied':True,'deletion_job_id':jid,'denied_at_ms':now}))
            tomb=Key('state','asset-erasure#'+digest({'deployment':self.repository.deployment,'asset_id':target['id']}));old=self.repository.snapshot((tomb,))[tomb]
            if old is not None:raise StoreConflict('asset erasure marker already exists')
            writes.append(Write(tomb,None,{'deny_reads':True,'scope_sha256':preview.data['scope_sha256'],'job_id':jid,'at_ms':now}))
        job={'id':jid,'kind':'asset_erasure','scope':scope,'scope_sha256':preview.data['scope_sha256'],'status':'queued','created_at_ms':now,
            'created_by':actor.member.data['id'],'lease_token':None,'lease_until_ms':0,'lease_runtime':None,'progress':{a['id']:{'live_versions_removed':False,'delete_acknowledgments':0,'checked_at_ms':None} for a in scope['assets']},'last_error':None}
        job['processing_authority']=processing_authority(self.access,actor,job,Role.OWNER)
        def final():
            if (self.access is not access or self.runtime is not runtime_service or self.repository is not repository
                    or self.purposes is not purposes or self.objects is not objects
                    or purposes.access is not access or purposes.runtime is not runtime_service or purposes.repository is not repository
                    or runtime_service.access is not access or access.repository is not repository or access.clock_ms is not clock
                    or objects.frames is not frames or objects.references is not references
                    or frames.client is not clients[0] or references.client is not clients[1] or self.storage!=storage):
                raise StoreConflict('original erasure confirmation dependencies changed')
            current_settings=(self.review_ms,self.jobs_per_minute,self.lease_ms,objects.page_size)
            if any(type(value) is not int for value in current_settings) or current_settings!=settings:
                raise StoreConflict('original erasure confirmation limits changed')
            try:
                if (digest(asdict(frames.config))!=storage or digest(asdict(references.config))!=storage
                        or digest(asdict(objects.config))!=storage):
                    raise StoreConflict('original erasure storage configuration changed')
            except (TypeError,ValueError,AttributeError) as exc:
                raise StoreConflict('intact original erasure storage configuration required') from exc
            if not runtime_service.matches(runtime):raise Denied('original erasure confirmation runtime required')
            access._fresh(actor,Role.OWNER)
            self._review_fresh(preview,now)
        result=self.access._record(actor,'erasure-confirm',idem,body_hash,{'id':jid},
            (*writes,Write(job_key(jid),None,job),Write(key,preview.revision,{**preview.data,'status':'committed','job_id':jid}),
             self.purposes.advance(data),self._quota(actor,'job')),tuple(self._merge(actor.rows,rows,(preview,data,runtime)).values()),
            event_details={'job_id':jid,'scope_sha256':job['scope_sha256'],'asset_count':len(scope['assets'])},before_commit=final)
        return self.job(actor,result['id'])

    def job(self,actor,ident):
        actor=self.access._fresh(actor,Role.OWNER);key=job_key(ident);row=self.repository.snapshot((key,))[key]
        if row is None or row.data.get('kind')!='asset_erasure':raise ResourceUnavailable('erasure job unavailable')
        scope=self._scope(row);expected=self._merge(actor.rows,(row,));final=self.repository.snapshot(tuple(expected))
        if any(final[k]!=v for k,v in expected.items()):raise StoreConflict('erasure job changed')
        self.access._fresh(actor,Role.OWNER);data=row.data;remaining=max(0,integer(data['lease_until_ms'])-self.access.now())
        return {'id':ident,'kind':'asset_erasure','state_version':row.revision,'status':data['status'],'scope_sha256':data['scope_sha256'],
            'assets':[{'id':a['id'],'kind':a['kind'],**json.loads(canonical(data['progress'][a['id']]))} for a in scope['assets']],
            'lease_remaining_ms':remaining,'last_error':data['last_error'],'target_matches_current_config':scope['storage_binding_sha256']==self.storage,
            'erasure_complete':False,'dependent_metadata_erased':False,'backups_erased':False,'downloaded_copies_recalled':False,
            'can_advance':bool(data['status']!='metadata_pending' and (data['status']!='processing' or remaining==0))}

    def _lease(self,jid,token,started):
        key=job_key(jid);rows=self.repository.snapshot((key,RUNTIME));row=rows[key]
        if row is None or row.data['status']!='processing' or row.data['lease_token']!=token or self.access.now()>=integer(row.data['lease_until_ms']):
            raise StoreConflict('current erasure service lease required')
        if not 0<=time.monotonic_ns()-started<self.lease_ms*1000000:raise StoreUnavailable('erasure step expired')
        if not self.runtime.matches(rows[RUNTIME]) or row.data.get('lease_runtime')!=asdict(self.runtime.handle):
            raise StoreConflict('current runtime incarnation required for erasure service lease')
        if self._scope(row)['storage_binding_sha256']!=self.storage:raise StoreUnavailable('original storage target required')
        return row

    def advance(self,actor,ident,*,expected_version,idempotency_key,execution_gate=None):
        if execution_gate is not None and not callable(execution_gate):raise ValueError('trusted execution checkpoint required')
        def gate():
            if execution_gate is not None:execution_gate()
        gate()
        actor=self.access._fresh(actor,Role.OWNER);ident=uuid(ident)
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact job version required')
        idem,body_hash,prior=self.access._idempotency(actor,'erasure-advance:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        key=job_key(ident);job=self.repository.snapshot((key,))[key]
        if job is None or job.data.get('kind')!='asset_erasure':raise ResourceUnavailable('erasure job unavailable')
        scope=self._scope(job);runtime=self._current()
        if job.revision!=expected_version or (job.data['status']=='processing' and self.access.now()<integer(job.data['lease_until_ms'])):raise StoreConflict('job changed or lease active')
        if scope['storage_binding_sha256']!=self.storage:raise StoreUnavailable('original storage target required')
        if job.data['status']=='metadata_pending':
            self.access._record(actor,'erasure-advance:'+ident,idem,body_hash,{'id':ident},(self._quota(actor,'step'),),(job,runtime))
            return self.job(actor,ident)
        token=str(uuid4());started=time.monotonic_ns()
        def lease_check():
            gate();return self._lease(ident,token,started)
        result=self.access._record(actor,'erasure-advance:'+ident,idem,body_hash,{'id':ident,'attempt':token},
            (Write(key,job.revision,{**job.data,'status':'processing','lease_token':token,'lease_until_ms':self.access.now()+self.lease_ms,'lease_runtime':asdict(self.runtime.handle),
                'processing_authority':processing_authority(self.access,actor,job.data,Role.OWNER)}),self._quota(actor,'step')),
            (job,runtime),before_commit=gate,event_details={'job_id':ident,'scope_sha256':job.data['scope_sha256']})
        if result.get('attempt')!=token:return self.job(actor,ident)
        lease=lease_check();target=next(a for a in scope['assets'] if not lease.data['progress'][a['id']]['live_versions_removed'])
        asset,actual=self._asset(target['id'])
        if asset.data.get('read_denied') is not True or asset.data.get('deletion_job_id')!=ident or any(actual[k]!=target[k] for k in ('id','kind','sha256','receipt_sha256')):
            raise StoreUnavailable('committed asset denial/identity required')
        error=None;acknowledged=0;removed=False
        try:
            lease_check();page=self.objects.list(target['kind'],target['id'])
            lease_check()
            if page.versions:
                acknowledged,partial=self.objects.delete(target['kind'],target['id'],page.versions)
                if partial:error='VERSION_DELETE_PARTIAL'
            else:removed=True
        except StoreUnavailable:error='STORAGE_OUTCOME_UNCONFIRMED'
        lease=lease_check();current=self.repository.snapshot((asset.key,))[asset.key]
        if current!=asset:raise StoreConflict('asset changed during erasure step')
        progress={**lease.data['progress'],target['id']:{'live_versions_removed':removed,
            'delete_acknowledgments':integer(lease.data['progress'][target['id']]['delete_acknowledgments'])+acknowledged,'checked_at_ms':self.access.now() if removed else None}}
        done=all(v['live_versions_removed'] for v in progress.values());writes=[]
        if removed:writes.append(Write(asset.key,asset.revision,{**asset.data,'status':'deleted','live_versions_checked_at_ms':self.access.now()}))
        runtime=self._current()
        # This exact service lease was authorized before storage work. Logout
        # denies the response/new work, but cannot strand admitted cleanup.
        checks=self._merge((runtime,asset) if not removed else (runtime,))
        self.access._commit_linked('asset_erasure_progress',(Write(key,lease.revision,{**lease.data,'status':'metadata_pending' if done else 'queued','lease_token':None,'lease_until_ms':0,'lease_runtime':None,'progress':progress,'last_error':error}),
            *writes,Write(Key('events','erasure#'+str(uuid4())),None,{'job_id':ident,'scope_sha256':lease.data['scope_sha256'],'asset_id':target['id'],
                'live_versions_removed':removed,'delete_acknowledgments':acknowledged,'at_ms':self.access.now(),'error':error})),tuple(checks.values()),before_commit=lease_check)
        return self.job(actor,ident)
