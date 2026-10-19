"""Durable historical manifests and freshly authorized in-memory ZIP delivery."""
from dataclasses import asdict
import base64
import hashlib
import hmac
import io
import json
import time
from threading import BoundedSemaphore
from uuid import uuid4
from zipfile import ZipFile,ZipInfo,ZIP_STORED

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.erasure import job_key
from proofpack.evidence.job_authority import issue as processing_authority
from proofpack.evidence.export_models import ExportRequest,ExportTicketRequest
from proofpack.evidence.originals import original_asset_id
from proofpack.evidence.handoff_export import source as handoff_source, summary as handoff_summary, state as handoff_state, lineage as handoff_lineage, copies as handoff_copies
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.runtime.control import integer,uuid,sha
from proofpack.stations.service import inspection_key
from proofpack.planner.policy import ActionKind
from proofpack.vision.correction import basis as correction_basis, target_indices


def _measured_summary(raw):
    text=raw.get('result_json')
    if raw.get('correction_basis_sha256') is None and not (isinstance(text,str) and '"correction_reason"' in text):return None
    try:
        value,signature=correction_basis(text,raw.get('evidence_sha256'))
        if signature is None or signature!=raw.get('correction_basis_sha256') or value['source_sha256']!=raw.get('source_sha256'):
            raise ValueError('matching recorded correction basis required')
        return {'basis_sha256':signature,'targets':{kind.value:target_indices(value,kind.value)
            for kind in (ActionKind.SEPARATE_REGION,ActionKind.PLACE_FLAT)}}
    except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('intact measured observation required for export') from exc


class ExportLimited(RuntimeError):pass
def manifest_key(ident):return Key('state','export-manifest#'+uuid(ident))
def ticket_key(ident):return Key('state','export-ticket#'+uuid(ident))


class InspectionExports:
    def __init__(self,assets,*,jobs_per_minute,job_lifetime_ms,lease_ms,page_size,max_scan_rows,max_records,max_assets,ticket_ms,download_ms,max_concurrent):
        bounds=((jobs_per_minute,1,20),(job_lifetime_ms,1000,3600000),(lease_ms,1000,60000),(page_size,1,25),
            (max_scan_rows,1,5000),(max_records,1,512),(max_assets,1,3),(ticket_ms,1,60000),(download_ms,1,30000),(max_concurrent,1,2))
        if any(type(v) is not int or not lo<=v<=hi for v,lo,hi in bounds):raise ValueError('explicit bounded export configuration required')
        self.assets=assets;self.purposes=assets.purposes;self.access=assets.access;self.repository=assets.repository;self.runtime=assets.runtime
        self.jobs_per_minute=jobs_per_minute;self.job_lifetime_ms=job_lifetime_ms;self.lease_ms=lease_ms;self.page_size=page_size
        self.max_scan_rows=max_scan_rows;self.max_records=max_records;self.max_assets=max_assets;self.ticket_ms=ticket_ms;self.download_ms=download_ms
        self.slots=BoundedSemaphore(max_concurrent)
        self._tick=time.monotonic_ns
        self.configuration=digest({'objects':asdict(assets.frames.config),'bounds':[v for v,_,_ in bounds],
            'notice_version':self.access.config.notice_version,'notice_sha256':hashlib.sha256(self.access.config.notice_text.encode()).hexdigest(),
            'capability_key_sha256':hashlib.sha256(self.access.config.capability_key).hexdigest(),
            'asset_read_bounds':[assets.reads_per_minute,assets.read_window_ms],'support_handoff_schema':1})

    @staticmethod
    def _merge(*groups):
        rows={}
        for group in groups:
            for row in group:
                if row is None:continue
                if row.key in rows and rows[row.key]!=row:raise StoreConflict('export authority changed')
                rows[row.key]=row
        return rows

    def _runtime(self):
        row=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(row):raise StoreUnavailable('current export runtime required')
        return row

    def _scope(self,actor,ident):
        actor=self.access._fresh(actor);key=inspection_key(ident);work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection export unavailable')
        if Role.REVIEWER in actor.principal.roles:actor=self.access._fresh(actor,Role.REVIEWER);role=Role.REVIEWER
        elif Role.OPERATOR in actor.principal.roles and work.data['originating_user_id']==actor.member.data['id']:
            actor=self.access._fresh(actor,Role.OPERATOR);role=Role.OPERATOR
        else:raise Denied('reviewer or originating operator export scope required')
        if self.access.now()>=integer(work.data['created_at_ms'])+30*86400000:raise ResourceUnavailable('inspection metadata retention expired')
        return actor,work,role

    def _quota(self,actor,kind):
        key=Key('state','export-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('export allowance clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        if count>=self.jobs_per_minute:raise ExportLimited('export allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def _row(self,ident):
        row=self.repository.snapshot((job_key(ident),))[job_key(ident)]
        if row is None or row.data.get('kind')!='inspection_export':raise ResourceUnavailable('export job unavailable')
        return row

    def context(self,actor,ident):
        actor,work,_=self._scope(actor,uuid(ident));self._runtime();latest=None
        if work.data.get('latest_observation_id'):
            key=Key('state','observation#'+uuid(work.data['latest_observation_id']));row=self.repository.snapshot((key,))[key]
            if row is not None and row.data['inspection_id']==ident and row.data['status']=='completed':latest=row.data['asset_id']
        self.access._fresh(actor)
        current=self.repository.snapshot((work.key,))[work.key]
        if current!=work:raise StoreConflict('export inspection changed')
        return {'inspection_id':ident,'state_version':work.revision,'state_as_recorded':work.data['state'],'latest_asset_id':latest,
            'max_assets':self.max_assets,'historical':True,'current_approval':False,'can_create':work.data.get('pending_sequence') is None}

    def list(self,actor,ident,*,cursor=None):
        actor,work,_=self._scope(actor,uuid(ident));start=None
        if cursor is not None:
            try:
                encoded,signature=cursor.split('.')
                if not hmac.compare_digest(signature,self.access._token('export-list',encoded)):raise ValueError()
                value=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
                if value['user_id']!=actor.member.data['id'] or value['inspection_id']!=ident or self.access.now()>=integer(value['expires_at_ms']):raise ValueError()
                start='maintenance-job#'+uuid(value['last_id'])
            except (ValueError,KeyError,TypeError):raise ValueError('current scoped export cursor required')
        rows,last=self.repository.query(prefix='maintenance-job#',limit=20,start_resource=start)
        results=[{'id':row.data['id'],'state_version':row.revision,'status':row.data['status'],'created_at_ms':integer(row.data['created_at_ms'])}
            for row in rows if row.data.get('kind')=='inspection_export' and row.data['requested_by']==actor.member.data['id'] and row.data['inspection_id']==ident]
        next_cursor=None
        if last:
            value={'user_id':actor.member.data['id'],'inspection_id':ident,'last_id':last.split('#')[-1],'expires_at_ms':self.access.now()+60000}
            encoded=base64.urlsafe_b64encode(canonical(value).encode()).decode().rstrip('=');next_cursor=encoded+'.'+self.access._token('export-list',encoded)
        self._scope(actor,ident)
        return {'inspection_id':ident,'jobs':results,'next_cursor':next_cursor,'historical':True,'current_approval':False}

    def _refs(self,refs,actor,role,deadline=None,*,work=None):
        result=[]
        for offset in range(0,len(refs),90):
            if deadline is not None:deadline()
            self.access._fresh(actor,role)
            part=refs[offset:offset+90];keys=tuple(Key(x['table'],x['resource']) for x in part);rows=self.repository.snapshot(keys)
            for ref,key in zip(part,keys,strict=True):
                row=rows[key]
                if row is None or row.revision!=integer(ref['revision']) or digest(row.data)!=sha(ref['sha256']):raise StoreConflict('export source changed or disappeared')
                if key.resource.startswith('inspection-handoff#'):
                    if work is None:raise StoreUnavailable('inspection-bound support export scope required')
                    handoff_source(self.access,actor,row,work.data['id'],work.data['originating_user_id'])
                result.append(row)
            if deadline is not None:deadline()
        return result

    @staticmethod
    def _ref(row):return {'table':row.key.table,'resource':row.key.resource,'revision':row.revision,'sha256':digest(row.data)}

    def _manifest_record(self,row):
        key=manifest_key(row.data['id']);record=self.repository.snapshot((key,))[key]
        try:
            if (record is None or len(record.data['json'].encode())>262144 or record.data['sha256']!=row.data['manifest_sha256']
                    or hashlib.sha256(record.data['json'].encode()).hexdigest()!=sha(row.data['manifest_sha256'])):raise ValueError()
            value=json.loads(record.data['json'])
            if (value['schema_version']!=1 or value['export_job_id']!=row.data['id'] or value['inspection_id']!=row.data['inspection_id']
                    or value['inspection_revision']!=integer(row.data['inspection_revision']) or value['historical'] is not True
                    or value['current_approval'] is not False or value['capture_authenticity_verified'] is not False
                    or row.data.get('support_handoff_schema')!=1
                    or value.get('support_handoff_state')!=row.data['handoff_state']
                    or value.get('support_handoffs')!=sorted(row.data['handoffs'],key=lambda r:(r['request']['source_inspection_revision'],r['id']))):raise ValueError()
            return record
        except (KeyError,TypeError,ValueError):raise StoreUnavailable('intact bound export manifest required')

    def _guard(self,actor,row,*,sources=True,deadline=None):
        if deadline is not None:deadline()
        data=row.data;actor,work,role=self._scope(actor,data['inspection_id'])
        if data.get('support_handoff_schema')!=1:raise StoreUnavailable('current complete support export schema required')
        try:state_matches=canonical(data['handoff_state'])==canonical(handoff_state(work))
        except (KeyError,TypeError,ValueError):state_matches=False
        if not state_matches:raise StoreUnavailable('saved support state must match the actual bound inspection')
        if deadline is not None:deadline()
        if actor.member.data['id']!=data['requested_by']:raise Denied('export requestor required')
        runtime=self._runtime();epoch=self.purposes.head()
        if (data['configuration']!=self.configuration or data['artifact_sha256']!=self.runtime.artifact_sha256
                or data['controls_sha256']!=self.runtime.controls_sha256 or data['environment']!=self.runtime.environment
                or integer(data['data_epoch'])!=integer(epoch.data['epoch']) or work.revision!=integer(data['inspection_revision'])
                or digest(work.data)!=data['inspection_sha256']):raise StoreConflict('export binding changed')
        if not integer(data['created_at_ms'])<=self.access.now()<integer(data['expires_at_ms']):raise StoreUnavailable('export job expired')
        if data['status'] in {'cancelled','failed'}:raise StoreConflict('export job is terminal without delivery')
        verified=self._refs(data['refs'],actor,role,deadline,work=work) if sources else []
        mutable=handoff_copies(data,verified) if sources else []
        rows=self._merge(actor.rows,(row,work,runtime,epoch),mutable)
        for selected in data['selected']:
            if deadline is not None:deadline()
            actor,scope,asset,source,_,receipt,_,_=self.assets._snapshot(actor,selected['id'],binary=True)
            if (source is None or source.key!=work.key or asset.revision!=integer(selected['revision'])
                    or receipt.source_sha256!=selected['sha256'] or receipt.byte_length!=integer(selected['byte_length']) or receipt.content_type!=selected['content_type']):raise StoreConflict('selected export binding changed')
            rows=self._merge(rows.values(),scope.values())
        if data['status']=='completed':
            manifest=self._manifest_record(row);rows=self._merge(rows.values(),(manifest,))
        if deadline is not None:deadline()
        return actor,role,rows

    def create(self,actor,ident,*,request,expected_version,idempotency_key):
        if not isinstance(request,ExportRequest) or type(expected_version) is not int or expected_version<1:raise ValueError('typed reviewed export scope required')
        actor,work,role=self._scope(actor,uuid(ident))
        body={'inspection_id':ident,'expected_version':expected_version,**request.model_dump(mode='json')}
        idem,body_hash,prior=self.access._idempotency(actor,'inspection-export',idempotency_key,body)
        if prior is not None:return self.job(actor,prior.data['result']['id'])
        if work.revision!=expected_version or work.data.get('pending_sequence') is not None:raise StoreConflict('current nonpending inspection version required')
        if len(request.selected_asset_ids)>self.max_assets:raise ValueError('selected media limit exceeded')
        runtime=self._runtime();data=self.purposes.head();rows=self._merge(actor.rows,(work,runtime,data));selected=[];deadline=self.access.now()+self.job_lifetime_ms
        for ident in request.selected_asset_ids:
            actor,scope,asset,source,_,receipt,expires,_=self.assets._snapshot(actor,uuid(ident),binary=True)
            if source is None or source.key!=work.key:raise Denied('selected frame must belong to this inspection')
            rows=self._merge(rows.values(),scope.values());deadline=min(deadline,expires)
            selected.append({'id':ident,'revision':asset.revision,'sha256':receipt.source_sha256,'byte_length':receipt.byte_length,'content_type':receipt.content_type,
                'data_origin':asset.data['data_origin'],'physical_truth_verified':False})
        jid=str(uuid4());now=self.access.now()
        job={'id':jid,'kind':'inspection_export','requested_by':actor.member.data['id'],'inspection_id':work.data['id'],
            'inspection_revision':work.revision,'inspection_sha256':digest(work.data),'configuration':self.configuration,
            'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,'environment':self.runtime.environment,
            'data_epoch':integer(data.data['epoch']),'created_at_ms':now,'expires_at_ms':deadline,'status':'queued','stage':0,'cursor':None,'scanned':0,'scan_reserved':0,'scan_allowance':0,
            'refs':[self._ref(work)],'observations':[],'events':[],'decisions':[],'selected':selected,
            'support_handoff_schema':1,'handoffs':[],'handoff_state':handoff_state(work),
            'lease_token':None,'lease_until_ms':0,'lease_runtime':None,'manifest_sha256':None,'failure_reason':None}
        job['processing_authority']=processing_authority(self.access,actor,job,role)
        self.access._record(actor,'inspection-export',idem,body_hash,{'id':jid},(Write(job_key(jid),None,job),self._quota(actor,'create')),
            tuple(rows.values()),required_role=role,event_details={'job_id':jid,'inspection_id':work.data['id'],'historical':True})
        return self.job(actor,jid)

    def job(self,actor,ident):
        actor=self.access._fresh(actor);row=self._row(uuid(ident));data=row.data;requestor=actor.member.data['id']==data['requested_by']
        if not requestor:actor=self.access._fresh(actor,Role.OWNER)
        else:actor,_,_=self._scope(actor,data['inspection_id'])
        can_use=False
        if requestor:
            try:self._guard(actor,row);can_use=True
            except (Denied,StoreUnavailable,StoreConflict,ResourceUnavailable):pass
        self.access._fresh(actor,Role.OWNER if not requestor else None)
        lease=max(0,integer(data['lease_until_ms'])-self.access.now())
        return {'id':ident,'kind':'inspection_export','state_version':row.revision,'status':data['status'],
            'inspection_id':data['inspection_id'],'inspection_revision':integer(data['inspection_revision']),
            'historical':True,'current_approval':False,'remaining_ms':max(0,integer(data['expires_at_ms'])-self.access.now()),
            'lease_remaining_ms':lease,'scanned_rows':integer(data['scanned']),'record_count':len(data['refs']),
            'scan_rows_reserved':integer(data['scan_reserved']),
            'selected_asset_ids':[x['id'] for x in data['selected']] if requestor else [],'manifest_sha256':data['manifest_sha256'],
            'can_advance':bool(can_use and data['status'] in {'queued','processing'} and (data['status']!='processing' or lease==0)),
            'can_issue_ticket':bool(can_use and data['status']=='completed'),'can_cancel':data['status']!='cancelled','failure_reason':data['failure_reason']}

    def _lease(self,ident,token,started):
        row=self._row(ident);runtime=self._runtime()
        if (row.data['status']!='processing' or row.data['lease_token']!=token or row.data['lease_runtime']!=asdict(self.runtime.handle)
                or self.access.now()>=integer(row.data['lease_until_ms']) or not 0<=time.monotonic_ns()-started<self.lease_ms*1000000):raise StoreConflict('current export lease required')
        return row,runtime

    def _manifest(self,actor,job,work,*,checkpoint=None):
        data=job.data;rows={};media=[];deadline=integer(data['expires_at_ms'])
        observed={x['id']:x for x in data['observations']}
        if len(observed)!=len(data['observations']) or (work.data.get('latest_observation_id') is not None and work.data['latest_observation_id'] not in observed):
            raise StoreUnavailable('complete observation lineage required for export')
        completed_assets=set()
        for ob in observed.values():
            if ob['status']!='completed':continue
            events=[e for e in data['events'] if e['kind']=='observation_completed' and e.get('observation_id')==ob['id']]
            if len(events)!=1 or events[0].get('asset_id')!=ob['asset_id'] or integer(events[0].get('sequence'))!=integer(ob['sequence']):raise StoreUnavailable('bound completion event required for export')
            measured=ob.get('measured_correction');event=events[0]
            if measured is not None:
                if event.get('correction_basis_sha256')!=measured['basis_sha256']:raise StoreUnavailable('bound measured completion event required for export')
                if event.get('action_id') is not None:
                    kind=event.get('action_kind');targets=event.get('target_candidate_indices')
                    if (not isinstance(kind,str) or kind not in {k.value for k in ActionKind}
                            or not isinstance(targets,list) or len(targets)>30 or any(type(n) is not int or not 0<=n<30 for n in targets)
                            or targets!=measured['targets'].get(kind,[])
                            or (kind in measured['targets'] and not targets)):
                        raise StoreUnavailable('bound measured action targets required for export')
                elif 'action_kind' in event or 'target_candidate_indices' in event:raise StoreUnavailable('measured action identity required for export')
            elif any(name in event for name in ('correction_basis_sha256','action_kind','target_candidate_indices')):
                raise StoreUnavailable('measured event requires bound observation for export')
            completed_assets.add(ob['asset_id'])
            if ob.get('retain_original_frame') is True:
                original=uuid(ob['original_asset_id']);original_sha=sha(ob['original_evidence_sha256'])
                if (original!=original_asset_id(ob['id']) or original==ob['asset_id']
                        or original_sha!=sha(ob['source_sha256']) or events[0].get('original_asset_id')!=original
                        or events[0].get('original_sha256')!=original_sha):raise StoreUnavailable('bound original completion event required for export')
                completed_assets.add(original)
        if any(x['id'] not in completed_assets for x in data['selected']):raise StoreUnavailable('selected media missing from completed history')
        decisions={x['id']:x for x in data['decisions']};seen=set();previous=work.data.get('latest_disposition_id')
        while previous is not None:
            if previous in seen or previous not in decisions:raise StoreUnavailable('complete human decision lineage required')
            seen.add(previous);previous=decisions[previous]['previous_id']
        if len(decisions)!=len(data['decisions']) or seen!=set(decisions):raise StoreUnavailable('unlinked human decisions cannot be exported')
        for selected in data['selected']:
            if checkpoint is not None:checkpoint()
            actor,scope,asset,source,_,receipt,expires,_=self.assets._snapshot(actor,selected['id'],binary=True)
            if (source is None or source.key!=work.key or asset.revision!=integer(selected['revision']) or receipt.source_sha256!=selected['sha256']):raise StoreConflict('selected export source changed')
            rows=self._merge(rows.values(),scope.values());deadline=min(deadline,expires)
            media.append({**selected,'file':'media/'+selected['id']+('.jpg' if selected['content_type']=='image/jpeg' else '.png'),'omitted':False})
        selected_ids={x['id'] for x in media}
        for ob in data['observations']:
            for omitted_id in (ob['asset_id'],ob.get('original_asset_id')):
                if omitted_id is not None and omitted_id not in selected_ids:
                    if checkpoint is not None:checkpoint()
                    key=Key('state','asset#'+uuid(omitted_id));asset=self.repository.snapshot((key,))[key]
                    unavailable=asset is None or asset.data.get('read_denied') is not False or asset.data.get('status')!='committed'
                    media.append({'id':omitted_id,'omitted':True,'reason':'unavailable_or_deleted' if unavailable else 'not_selected'})
        support,recorded_support=handoff_lineage(work,data['handoffs'],data['events'])
        if recorded_support!=data['handoff_state']:raise StoreUnavailable('bound support export state required')
        manifest={'schema_version':1,'export_job_id':data['id'],'inspection_id':data['inspection_id'],'inspection_revision':integer(data['inspection_revision']),
            'created_at_ms':integer(data['created_at_ms']),'historical':True,'current_approval':False,'capture_authenticity_verified':False,
            'optional_improvement':False,'optional_publicity':False,'state_as_recorded':work.data['state'],'human_disposition':work.data.get('disposition'),
            'kit_reference':work.data['kit_id'],'data_origins':sorted({x['data_origin'] for x in data['selected']}),
            'origin_scope':'selected recorded assets only; omitted media origin not assessed','physical_truth_verified':False,
            'original_bindings':{name:work.data[name] for name in ('recipe_id','recipe_revision','recipe_active_version','calibration_profile_id','calibration_state_version',
                'policy_state_version','runtime_epoch','runtime_instance_id','artifact_sha256','control_version','data_epoch')},
            'artifact_sha256':data['artifact_sha256'],'controls_sha256':data['controls_sha256'],'data_epoch':integer(data['data_epoch']),
            'observations':sorted(data['observations'],key=lambda x:(x['sequence'],x['id'])),
            'events':sorted(data['events'],key=lambda x:(x['at_ms'],x['id'])),'event_order':'at_ms_then_event_id; chronology within equal milliseconds is unknown',
            'human_decisions':sorted(data['decisions'],key=lambda x:(x['at_ms'],x['id'])),'media':media,
            'support_handoffs':support,'support_handoff_state':recorded_support,
            'sources':[{'kind':x['resource'].split('#')[0],'id':x['resource'].split('#')[-1],'revision':integer(x['revision']),'sha256':x['sha256']} for x in data['refs']],
            'source_digest_note':'Source digests identify private server records; sanitized fields alone do not reproduce those digests.'}
        text=canonical(manifest)
        if len(text.encode())>262144:raise ExportLimited('export manifest size limit exceeded')
        return text,rows,deadline

    def advance(self,actor,ident,*,expected_version,idempotency_key,execution_gate=None):
        if execution_gate is not None and not callable(execution_gate):raise ValueError('trusted execution checkpoint required')
        def gate():
            if execution_gate is not None:execution_gate()
        gate()
        ident=uuid(ident);job=self._row(ident);actor,_,role=self._scope(actor,job.data['inspection_id'])
        if actor.member.data['id']!=job.data['requested_by']:raise Denied('export requestor required')
        if type(expected_version) is not int or expected_version<1:raise ValueError('exact export job version required')
        idem,body_hash,prior=self.access._idempotency(actor,'export-step:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        actor,role,checks=self._guard(actor,job,deadline=gate)
        if job.revision!=expected_version or job.data['status'] not in {'queued','processing'} or (job.data['status']=='processing' and self.access.now()<integer(job.data['lease_until_ms'])):raise StoreConflict('current available export job required')
        token=str(uuid4());started=time.monotonic_ns()
        def lease_check():
            gate();return self._lease(ident,token,started)
        allowance=min(self.page_size,max(0,self.max_scan_rows-integer(job.data['scan_reserved'])))
        if allowance==0:
            self.access._record(actor,'export-step:'+ident,idem,body_hash,{'id':ident},
                (Write(job.key,job.revision,{**job.data,'status':'failed','failure_reason':'EXPORT_LIMIT_EXCEEDED','lease_token':None,'lease_until_ms':0,'lease_runtime':None}),self._quota(actor,'step')),
                tuple(r for k,r in checks.items() if k!=job.key),required_role=role,before_commit=gate,event_details={'job_id':ident})
            return self.job(actor,ident)
        result=self.access._record(actor,'export-step:'+ident,idem,body_hash,{'id':ident,'attempt':token},
            (Write(job.key,job.revision,{**job.data,'status':'processing','lease_token':token,'lease_until_ms':min(integer(job.data['expires_at_ms']),self.access.now()+self.lease_ms),
                'lease_runtime':asdict(self.runtime.handle),'scan_reserved':integer(job.data['scan_reserved'])+allowance,'scan_allowance':allowance,
                'processing_authority':processing_authority(self.access,actor,job.data,role)}),self._quota(actor,'step')),
            tuple(r for k,r in checks.items() if k!=job.key),required_role=role,before_commit=gate,event_details={'job_id':ident})
        if result.get('attempt')!=token:return self.job(actor,ident)
        lease,runtime=lease_check();data=json.loads(canonical(lease.data));stage=integer(data['stage'])
        prefixes=[('state','observation#'),('events','access#'),('events','capture#'),('state','human-disposition#'+data['inspection_id']+'#'),
            ('state','inspection-handoff#'+data['inspection_id']+'#')]
        table,prefix=prefixes[stage];self.access._fresh(actor,role)
        gate()
        page,cursor=self.repository.query(prefix=prefix,table=table,limit=allowance,start_resource=data['cursor'])
        gate()
        if len(page)>allowance or (cursor is not None and cursor==data['cursor']):raise StoreUnavailable('bounded progressing export page required')
        data['scanned']=integer(data['scanned'])+len(page);failure=None
        refs={(x['table'],x['resource']):x for x in data['refs']}
        for source in page:
            raw=source.data;details=raw.get('details',{})
            if stage==4 and raw.get('inspection_id')!=data['inspection_id']:raise StoreUnavailable('foreign record in scoped support history')
            if raw.get('inspection_id',details.get('inspection_id'))!=data['inspection_id']:continue
            if stage==1 and (raw['kind']=='inspection-export' or raw['kind'].startswith('export-')):continue
            ref=self._ref(source);previous=refs.get((ref['table'],ref['resource']))
            if previous is not None and previous!=ref:raise StoreConflict('export source changed during collection')
            if previous is not None:continue
            refs[(ref['table'],ref['resource'])]=ref
            if stage==0:
                if raw['status'] not in {'completed','failed','expired','cancelled'}:failure='SOURCE_NOT_TERMINAL';break
                observed={'id':uuid(raw['id']),'sequence':integer(raw['sequence']),'status':raw['status'],'asset_id':None if raw.get('asset_id') is None else uuid(raw['asset_id'])}
                if raw['status']=='completed':
                    measured=_measured_summary(raw)
                    if measured is not None:observed['measured_correction']=measured
                if raw.get('retain_original_frame') is True and raw['status']=='completed':
                    observed.update(retain_original_frame=True,original_asset_id=uuid(raw['original_asset_id']),
                        original_evidence_sha256=sha(raw['original_evidence_sha256']),source_sha256=sha(raw['source_sha256']))
                data['observations'].append(observed)
            elif stage in {1,2}:
                if not isinstance(raw['kind'],str) or not 1<=len(raw['kind'])<=100:raise StoreUnavailable('export event type unavailable')
                if raw['kind']=='observation_completed' and raw.get('correction_basis_sha256') is not None and raw.get('action_id') is not None:
                    action_id=uuid(raw['action_id']);key=Key('state','action#'+action_id)
                    action=self.repository.snapshot((key,))[key]
                    if (action is None or action.data.get('id')!=action_id or action.data.get('observation_id')!=raw.get('observation_id')
                            or action.data.get('correction_basis_sha256')!=raw['correction_basis_sha256']
                            or action.data.get('kind')!=raw.get('action_kind') or action.data.get('target_candidate_indices')!=raw.get('target_candidate_indices')):
                        raise StoreUnavailable('actual recorded correction action required for export')
                    action_ref=self._ref(action);action_identity=(action_ref['table'],action_ref['resource'])
                    if action_identity in refs and refs[action_identity]!=action_ref:raise StoreConflict('recorded correction action changed during export')
                    refs[action_identity]=action_ref
                fields={'id':source.key.resource.split('#')[-1],'kind':raw['kind'],'at_ms':integer(raw['at_ms'])}
                for name in ('observation_id','asset_id','action_id','sequence','state','decision_id','disposition','recipe_id','recipe_revision','station_id','original_asset_id','original_sha256',
                        'correction_basis_sha256','action_kind','target_candidate_indices','handoff_id','decision','machine_approval'):
                    if name in raw:fields[name]=raw[name]
                    elif name in details:fields[name]=details[name]
                data['events'].append(fields)
            elif stage==3:
                try:
                    intact=(raw.get('machine_approval') is False and raw.get('independent_truth_verified') is False
                        and sha(raw.get('sha256'))==digest({k:v for k,v in raw.items() if k!='sha256'}))
                except (KeyError,TypeError,ValueError):intact=False
                if not intact:raise StoreUnavailable('intact human decision record required')
                data['decisions'].append({name:raw[name] for name in ('id','previous_id','disposition','reason','human_check_confirmed','at_ms','sha256')})
            else:
                work=checks[inspection_key(data['inspection_id'])]
                bound=handoff_source(self.access,actor,source,data['inspection_id'],work.data['originating_user_id'])
                data['handoffs'].append(handoff_summary(bound))
                data['expires_at_ms']=min(integer(data['expires_at_ms']),integer(bound.data['metadata_expires_at_ms']))
        data['refs']=list(refs.values());data['cursor']=cursor
        if cursor is None:data['stage']=stage+1
        if data['scanned']>self.max_scan_rows or len(refs)>self.max_records or len(canonical(data).encode())>350000:failure='EXPORT_LIMIT_EXCEEDED'
        lease,runtime=lease_check();actor,role,checks=self._guard(actor,lease,deadline=gate)
        # Completed historical records are immutable; permitted removal/redaction must
        # advance DATA. Check all collected hashes before the epoch-guarded commit.
        if failure is None:
            verified=self._refs(data['refs'],actor,role,gate,work=checks[inspection_key(data['inspection_id'])])
            mutable=handoff_copies(data,verified)
            checks=self._merge(checks.values(),mutable)
        writes=[]
        if failure is None and data['stage']==len(prefixes):
            try:text,source_rows,deadline=self._manifest(actor,type(lease)(lease.key,lease.revision,data),checks[inspection_key(data['inspection_id'])],checkpoint=gate)
            except ExportLimited:failure='EXPORT_LIMIT_EXCEEDED'
        if failure is None and data['stage']==len(prefixes):
            checks=self._merge(checks.values(),source_rows.values());data['manifest_sha256']=hashlib.sha256(text.encode()).hexdigest();data['expires_at_ms']=deadline
            writes.append(Write(manifest_key(ident),None,{'id':ident,'json':text,'sha256':data['manifest_sha256']}));data['status']='completed'
        else:data['status']='failed' if failure else 'queued'
        if failure:data={**lease.data,'scanned':data['scanned'],'status':'failed','failure_reason':failure}
        data.update(lease_token=None,lease_until_ms=0,lease_runtime=None)
        lease_check();actor=self.access._fresh(actor,role)
        def final_commit():
            self.access._fresh(actor,role);lease_check();gate()
        self.access._commit_linked('export_progress',(Write(lease.key,lease.revision,data),*writes,Write(Key('events','export#'+str(uuid4())),None,{'kind':'export_progress','job_id':ident,'status':data['status'],'at_ms':self.access.now()})),
            tuple(r for k,r in self._merge(checks.values(),actor.rows,(runtime,)).items() if k!=lease.key),before_commit=final_commit)
        return self.job(actor,ident)

    def cancel(self,actor,ident,*,expected_version,idempotency_key):
        row=self._row(uuid(ident));actor=self.access._fresh(actor)
        if actor.member.data['id']==row.data['requested_by']:actor,_,role=self._scope(actor,row.data['inspection_id'])
        else:actor=self.access._fresh(actor,Role.OWNER);role=Role.OWNER
        idem,body_hash,prior=self.access._idempotency(actor,'export-cancel:'+ident,idempotency_key,{'expected_version':expected_version})
        if prior is not None:return self.job(actor,ident)
        if type(expected_version) is not int or row.revision!=expected_version:raise StoreConflict('exact export version required')
        writes=() if row.data['status']=='cancelled' else (Write(row.key,row.revision,{**row.data,'status':'cancelled','lease_token':None,'lease_until_ms':0,'lease_runtime':None}),)
        self.access._record(actor,'export-cancel:'+ident,idem,body_hash,{'id':ident},writes,(row,) if not writes else (),required_role=role,event_details={'job_id':ident})
        return self.job(actor,ident)

    def _capability(self,tid,job,session):return self.access._token('export-ticket',tid+'|'+job+'|'+session)

    def ticket(self,actor,ident,*,request,expected_version,idempotency_key):
        if not isinstance(request,ExportTicketRequest):raise ValueError('typed historical ticket acknowledgment required')
        row=self._row(uuid(ident));actor,role,checks=self._guard(actor,row);operation='export-ticket:'+ident
        body={'expected_version':expected_version,**request.model_dump(mode='json')};idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is None:
            if type(expected_version) is not int or row.revision!=expected_version or row.data['status']!='completed':raise StoreConflict('current completed export required')
            tid=str(uuid4());token=self._capability(tid,ident,actor.session.data['id']);now=self.access.now()
            value={'id':tid,'job_id':ident,'job_revision':row.revision,'user_id':actor.member.data['id'],'session_id':actor.session.data['id'],'access_version':integer(actor.member.data['access_version']),
                'capability_sha256':hashlib.sha256(token.encode()).hexdigest(),'created_at_ms':now,'expires_at_ms':min(integer(row.data['expires_at_ms']),now+self.ticket_ms),'consumed':False,'ready':False}
            result=self.access._record(actor,operation,idem,body_hash,{'id':tid},(Write(ticket_key(tid),None,value),self._quota(actor,'ticket')),tuple(checks.values()),required_role=role,event_details={'job_id':ident,'ticket_id':tid})
        else:result=prior.data['result']
        ticket=self.repository.snapshot((ticket_key(result['id']),))[ticket_key(result['id'])];value=ticket.data
        if value['session_id']!=actor.session.data['id'] or value['user_id']!=actor.member.data['id']:raise Denied('original export ticket session required')
        self._guard(actor,self._row(ident));remaining=max(0,integer(value['expires_at_ms'])-self.access.now())
        return {'id':value['id'],'job_id':ident,'ticket':value['id']+'.'+self._capability(value['id'],ident,value['session_id']),
            'remaining_ms':remaining,'usable':bool(not value['consumed'] and remaining>0),'historical':True,'current_approval':False}

    def download(self,actor,ident,capability):
        if not self.slots.acquire(blocking=False):raise ExportLimited('archive construction busy')
        started=self._tick()
        def budget():
            if not 0<=self._tick()-started<self.download_ms*1000000:raise StoreUnavailable('export construction deadline exceeded')
        try:
            if not isinstance(capability,str) or len(capability)>128 or capability.count('.')!=1:raise Denied('session-bound export ticket required')
            tid,token=capability.split('.');uuid(tid);row=self._row(uuid(ident));actor,role,checks=self._guard(actor,row,deadline=budget)
            key=ticket_key(tid);ticket=self.repository.snapshot((key,))[key]
            if ticket is None:raise Denied('export ticket unavailable')
            value=ticket.data
            if (row.data['status']!='completed' or value['job_id']!=ident or value['job_revision']!=row.revision or value['consumed'] is not False
                    or value['user_id']!=actor.member.data['id'] or value['session_id']!=actor.session.data['id'] or integer(value['access_version'])!=integer(actor.member.data['access_version'])
                    or not integer(value['created_at_ms'])<=self.access.now()<integer(value['expires_at_ms'])
                    or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(),value['capability_sha256'])):raise Denied('fresh unused export ticket required')
            def final_admit():
                self.access._fresh(actor,role);budget()
                if self.access.now()>=integer(value['expires_at_ms']):raise Denied('fresh unused export ticket required')
            self.access._commit_linked('export_download_admitted',(Write(key,ticket.revision,{**value,'consumed':True}),self._quota(actor,'download'),
                Write(Key('events','export#'+str(uuid4())),None,{'kind':'export_download_admitted','job_id':ident,'ticket_id':tid,'at_ms':self.access.now()})),tuple(checks.values()),before_commit=final_admit)
            consumed=self.repository.snapshot((key,))[key];record=self._manifest_record(row)
            manifest=json.loads(record.data['json']);output=io.BytesIO();media={x['id']:x for x in manifest['media'] if not x['omitted']}
            def deadline():
                budget()
                if self.access.now()>=integer(value['expires_at_ms']):raise StoreUnavailable('export delivery expired')
            with ZipFile(output,'w',compression=ZIP_STORED) as archive:
                archive.writestr(ZipInfo('manifest.json'),record.data['json'].encode())
                for selected in row.data['selected']:
                    deadline();payload,receipt,version,_,_=self.assets.read(actor,selected['id'],binary=True)
                    if receipt.source_sha256!=selected['sha256'] or version!=integer(selected['revision']):raise StoreConflict('export image changed')
                    filename='media/'+uuid(selected['id'])+('.jpg' if selected['content_type']=='image/jpeg' else '.png')
                    if media[selected['id']]['file']!=filename:raise StoreUnavailable('owned archive entry required')
                    archive.writestr(ZipInfo(filename),payload)
                    if output.tell()>8388608:raise ExportLimited('archive size exceeded')
            payload=output.getvalue()
            if len(payload)>8388608:raise ExportLimited('archive size exceeded')
            actor,role,final=self._guard(actor,self._row(ident),deadline=deadline);final=self._merge(checks.values(),final.values(),(consumed,record))
            for selected in row.data['selected']:
                actor,scope,asset,source,_,receipt,_,_=self.assets._snapshot(actor,selected['id'],binary=True)
                if source is None or source.data['id']!=row.data['inspection_id'] or asset.revision!=integer(selected['revision']) or receipt.source_sha256!=selected['sha256']:raise StoreConflict('export source changed before delivery')
                final=self._merge(final.values(),scope.values())
            actor=self.access._fresh(actor,role)
            def final_ready():
                self.access._fresh(actor,role);deadline()
            self.access._commit_linked('export_download_ready',(Write(key,consumed.revision,{**consumed.data,'ready':True}),Write(Key('events','export#'+str(uuid4())),None,
                {'kind':'export_download_ready','job_id':ident,'ticket_id':tid,'sha256':hashlib.sha256(payload).hexdigest(),'at_ms':self.access.now()})),
                tuple(r for k,r in self._merge(final.values(),actor.rows).items() if k!=key),before_commit=final_ready)
            deadline();_,_,last=self._guard(actor,self._row(ident),deadline=deadline);self._refs(row.data['refs'],actor,role,deadline,work=last[inspection_key(row.data['inspection_id'])])
            current=self.repository.snapshot(tuple(last))
            if any(current[k]!=v for k,v in last.items()):raise StoreConflict('export authority changed before response')
            self.access._fresh(actor,role);deadline()
            return payload,row.data['manifest_sha256'],max(0,integer(value['expires_at_ms'])-self.access.now())
        finally:self.slots.release()
