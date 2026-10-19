"""Capture authority and byte provenance. Admission is not verified evidence."""
import hashlib
import hmac
import json
from proofpack.capture.provenance import inspection_context,policy_provenance
import re
from threading import Lock
import time
from uuid import uuid4

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import digest
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.runtime.control import integer,uuid
from proofpack.stations.service import inspection_key,merge,StationRateLimited
from proofpack.vision.worker import WorkerUnavailable
from proofpack.evidence.originals import ORIGINAL_MAX_ATTEMPTS,original_permission_binding


def permit_key(ident):return Key('state','capture-permit#'+uuid(ident))
def observation_key(ident):return Key('state','observation#'+uuid(ident))


class CaptureService:
    def __init__(self,stations,*,worker_guard=None,tick_ns=None):
        self.stations=stations;self.access=stations.access;self.repository=stations.repository
        self.tick_ns=tick_ns or time.monotonic_ns
        self.worker_guard=worker_guard
        self.dependency_snapshot=None
        self.original_capture_guard=None
        self._last_tick=None;self._tick_lock=Lock()

    def tick(self):
        with self._tick_lock:
            value=self.tick_ns()
            if type(value) is not int or value<0 or (self._last_tick is not None and value<self._last_tick):
                raise StoreUnavailable('trusted monotonic capture clock required')
            self._last_tick=value;return value

    def _authority(self,actor,ident):
        actor=self.access._fresh(actor,Role.OPERATOR)
        actor,work,rows,recipe,cal,deadline=self.stations.inspection_authority(actor,ident)
        if work.data['originating_session_id']!=actor.session.data['id']:raise Denied('originating operator session required')
        if work.data['state'] in {'CLOSED','REVIEW_REQUIRED','ACTION_REQUIRED'}:raise StoreConflict('inspection cannot accept capture')
        if not callable(self.worker_guard):raise StoreUnavailable('warm station worker registry is not configured')
        try:ready=self.worker_guard(work.data['station_id'],integer(work.data['station_epoch']),work.data['runtime_instance_id'])
        except WorkerUnavailable as exc:raise StoreUnavailable('warm station worker unavailable; review station fence') from exc
        if ready is not None:
            raise StoreUnavailable('worker guard must verify server state, not return a readiness flag')
        if self.dependency_snapshot is not None:
            extra,expires=self.dependency_snapshot()
            rows=merge(rows,extra);deadline=min(deadline,integer(expires))
            current=self.repository.snapshot(tuple(row.key for row in rows))
            if any(current[row.key]!=row for row in rows):raise StoreConflict('capture purpose/authority changed')
            if self.access.now()>=deadline:raise Denied('capture purpose expired')
        return actor,work,rows,deadline

    def _permit_view(self,actor,result):
        actor,work,authority,deadline=self._authority(actor,result['inspection_id'])
        row=self.repository.snapshot((permit_key(result['permit_id']),))[permit_key(result['permit_id'])]
        tick=self.tick()
        usable=(row is not None and row.data['status']=='issued'
            and work.data.get('pending_permit_id')==result['permit_id']
            and row.data.get('policy_provenance')==work.data['policy_provenance']
            and row.data['issued_tick_ns']<=tick<min(row.data['expires_tick_ns'],row.data['observation_deadline_tick_ns'])
            and self.access.now()<deadline)
        if usable and row.data.get('retain_original_frame') is not False and 'retain_original_frame' in row.data:
            if row.data['retain_original_frame'] is not True or not callable(self.original_capture_guard):raise StoreUnavailable('intact original permit scope required')
            extra,expiry=self.original_capture_guard();deadline=min(deadline,expiry)
            usable=(original_permission_binding(extra)==row.data.get('original_capture_purpose_binding') and self.access.now()<deadline)
        self.access._fresh(actor,Role.OPERATOR);self.stations.guard_policy(work.data,authority)
        checks=merge(actor.rows,authority,() if row is None else (row,))
        final=self.repository.snapshot(tuple(item.key for item in checks))
        if any(final[item.key]!=item for item in checks):raise StoreConflict('capture permit policy changed during delivery')
        tick=self.tick()
        usable=bool(usable and self.access.now()<deadline and tick<min(row.data['expires_tick_ns'],row.data['observation_deadline_tick_ns']))
        return {**result,'inspection_state_version':work.revision,'usable':usable,
            'nonce':self.access._token('capture-permit',result['permit_id']) if usable else None,
            'remaining_acceptance_ms':max(0,min((integer(row.data['observation_deadline_tick_ns'])-tick)//1000000,
                deadline-self.access.now())) if usable else 0}

    def issue(self,actor,*,inspection_id,expected_version,expected_epoch,idempotency_key,retain_original_frame=False):
        if type(expected_version) is not int or expected_version<1 or type(expected_epoch) is not int or expected_epoch<0:
            raise ValueError('inspection version and station epoch required')
        if type(retain_original_frame) is not bool:raise ValueError('explicit original selection must be boolean')
        actor,work,authority,deadline=self._authority(actor,inspection_id)
        body={'expected_version':expected_version,'expected_epoch':expected_epoch}
        if retain_original_frame:body['retain_original_frame']=True
        operation='capture-permit:'+inspection_id
        idem,body_hash,replay=self.access._idempotency(actor,operation,idempotency_key,body)
        if replay is not None:return self._permit_view(actor,replay.data['result'])
        if work.revision!=expected_version or work.data['station_epoch']!=expected_epoch:raise StoreConflict('inspection/fence changed')
        if work.data.get('pending_sequence') is not None:raise StoreConflict('one admitted frame is already pending')
        original_binding=None
        if retain_original_frame:
            if not callable(self.original_capture_guard):raise Denied('original retention is not configured')
            extra,expiry=self.original_capture_guard();authority=merge(authority,extra);deadline=min(deadline,expiry)
            original_binding=original_permission_binding(extra)
            if not 0<=integer(work.data.get('original_attempts_reserved',0))<ORIGINAL_MAX_ATTEMPTS:raise StationRateLimited('original frame attempt budget exhausted')
        tick=self.tick();old_id=work.data.get('pending_permit_id');writes=();checks=()
        if old_id is not None:
            key=permit_key(old_id);old=self.repository.snapshot((key,))[key]
            if old is None:raise StoreUnavailable('pending permit unavailable')
            if old.data['status']!='issued':raise StoreConflict('pending permit needs reconciliation')
            if tick<min(old.data['expires_tick_ns'],old.data['observation_deadline_tick_ns']):raise StoreConflict('one fresh permit is already pending')
            writes=(Write(key,old.revision,{**old.data,'status':'expired'}),);checks=(old,)
        ident=str(uuid4());nonce=self.access._token('capture-permit',ident)
        cap_tick=tick+(deadline-self.access.now())*1000000
        if cap_tick<=tick:raise Denied('capture dependencies expired')
        data={'id':ident,'inspection_id':inspection_id,'station_id':work.data['station_id'],'station_epoch':expected_epoch,
            'runtime_instance_id':work.data['runtime_instance_id'],'runtime_epoch':integer(work.data['runtime_epoch']),
            'sequence':integer(work.data['latest_input_sequence'])+1,'nonce_sha256':digest(nonce),'status':'issued',
            'policy_provenance':policy_provenance(work.data['policy_provenance']),
            'issued_tick_ns':tick,'issued_at_ms':self.access.now(),'expires_tick_ns':min(tick+2000000000,cap_tick),
            'observation_deadline_tick_ns':min(tick+1000000000,cap_tick)}
        updated={**work.data,'pending_permit_id':ident,'state':'OBSERVING' if work.data['state'] in {'CREATED','INVALIDATED'} else work.data['state']}
        result={'inspection_id':inspection_id,'permit_id':ident,'sequence':data['sequence'],'operation':'permit_issued'}
        if retain_original_frame:
            data.update(retain_original_frame=True,original_capture_purpose_binding=original_binding)
            updated['original_attempts_reserved']=integer(work.data.get('original_attempts_reserved',0))+1
            result['retain_original_frame']=True
        def before_commit():
            self.stations.guard_policy(work.data,authority)
            if self.access.now()>=deadline or self.tick()>=min(data['expires_tick_ns'],data['observation_deadline_tick_ns']):raise Denied('capture permit expired before commit')
        committed=self.access._record(actor,operation,idem,body_hash,result,
            (*writes,Write(permit_key(ident),None,data),Write(work.key,work.revision,updated),self.stations._quota(work.data['station_id'])),
            merge(actor.rows,authority,checks),required_role=Role.OPERATOR,
            before_commit=before_commit,
            event_details={'inspection_id':inspection_id,'permit_id':ident,'sequence':data['sequence'],'station_epoch':expected_epoch})
        return self._permit_view(actor,committed)

    def _upload_quota(self,station_id):
        key=Key('state','upload-quota#'+uuid(station_id));row=self.repository.snapshot((key,))[key]
        second=self.access.now()//1000
        if row is not None and integer(row.data['second'])>second:raise StoreUnavailable('upload quota clock moved backwards')
        count=0 if row is None or integer(row.data['second'])!=second else integer(row.data['count'])
        if count>=3:raise StationRateLimited('station upload limit reached')
        return Write(key,None if row is None else row.revision,{'second':second,'count':count+1})

    def admit(self,actor,*,inspection_id,expected_version,permit_id,nonce,sequence,payload,idempotency_key=None,content_type=None):
        arguments={'inspection_id':inspection_id,'expected_version':expected_version,'permit_id':permit_id,'nonce':nonce,
            'sequence':sequence,'payload':payload,'idempotency_key':idempotency_key,'content_type':content_type}
        try:return self._admit(actor,**arguments)
        except (StoreConflict,Denied):
            if idempotency_key is None:raise
            actor=self.access._fresh(actor,Role.OPERATOR)
            _,_,existing=self._upload_operation(actor,**arguments)
            if existing is None:raise
            # One history lookup, never a new admission or replayed processing.
            return self._replayed_admission(actor,inspection_id,existing.data['result'])

    def _upload_operation(self,actor,*,inspection_id,expected_version,permit_id,nonce,sequence,payload,idempotency_key,content_type):
        return self.access._idempotency(actor,'observation-upload:'+inspection_id,idempotency_key,
            {'inspection_id':inspection_id,'expected_version':expected_version,'permit_id':permit_id,'nonce_sha256':digest(nonce),
             'sequence':sequence,'source_sha256':hashlib.sha256(payload).hexdigest(),'byte_length':len(payload),'content_type':content_type})

    def _admit(self,actor,*,inspection_id,expected_version,permit_id,nonce,sequence,payload,idempotency_key=None,content_type=None):
        """Internal byte admission; caller must still decode/store/verify or fail work."""
        if (type(expected_version) is not int or expected_version<1 or type(sequence) is not int or sequence<1
                or not isinstance(payload,bytes) or not 0<len(payload)<=2097152
                or not isinstance(nonce,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',nonce)):
            raise ValueError('bounded capture bytes/identity required')
        actor=self.access._fresh(actor,Role.OPERATOR)
        idem=None;body_hash=None
        if idempotency_key is not None:
            if content_type not in {'image/jpeg','image/png'}:raise ValueError('declared image type required')
            idem,body_hash,replay=self._upload_operation(actor,inspection_id=inspection_id,expected_version=expected_version,
                permit_id=permit_id,nonce=nonce,sequence=sequence,payload=payload,idempotency_key=idempotency_key,content_type=content_type)
            if replay is not None:return self._replayed_admission(actor,inspection_id,replay.data['result'])
        actor,work,authority,deadline=self._authority(actor,inspection_id)
        key=permit_key(permit_id);row=self.repository.snapshot((key,))[key];tick=self.tick()
        if work.revision!=expected_version or work.data.get('pending_permit_id')!=permit_id:raise StoreConflict('capture permit is not current')
        if (row is None or row.data['status']!='issued' or row.data['inspection_id']!=inspection_id
                or row.data['station_epoch']!=work.data['station_epoch']
                or row.data['runtime_instance_id']!=work.data['runtime_instance_id'] or row.data['runtime_epoch']!=work.data['runtime_epoch']
                or row.data['sequence']!=sequence or sequence!=integer(work.data['latest_input_sequence'])+1
                or not hmac.compare_digest(row.data['nonce_sha256'],digest(nonce))
                or not row.data['issued_tick_ns']<=tick<min(row.data['expires_tick_ns'],row.data['observation_deadline_tick_ns'])
                or self.access.now()>=deadline):raise Denied('valid fresh one-use capture permit required')
        if work.data.get('pending_sequence') is not None:raise StoreConflict('one frame is already pending')
        retained=row.data.get('retain_original_frame',False)
        if type(retained) is not bool:raise StoreUnavailable('intact original selection required')
        original_binding=None
        if retained:
            if row.data.get('retain_original_frame') is not True or not callable(self.original_capture_guard):raise Denied('current original selection required')
            extra,expiry=self.original_capture_guard();authority=merge(authority,extra);deadline=min(deadline,expiry)
            original_binding=original_permission_binding(extra)
            if (original_binding!=row.data.get('original_capture_purpose_binding') or content_type not in {'image/jpeg','image/png'}
                    or not 1<=integer(work.data.get('original_attempts_reserved',0))<=ORIGINAL_MAX_ATTEMPTS):raise Denied('bound original selection and image type required')
        ident=str(uuid4());sha256=hashlib.sha256(payload).hexdigest()
        if row.data.get('policy_provenance')!=work.data['policy_provenance']:raise Denied('capture permit policy changed')
        context=inspection_context(work.data,sequence)
        context_hash=hashlib.sha256(json.dumps(context,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        observation={'id':ident,'inspection_id':inspection_id,'permit_id':permit_id,'sequence':sequence,'status':'admitted',
            'station_id':work.data['station_id'],'station_epoch':integer(work.data['station_epoch']),
            'runtime_epoch':integer(work.data['runtime_epoch']),'originating_session_id':actor.session.data['id'],
            'policy_provenance':context['policy_provenance'],
            'accepted_tick_ns':tick,'permit_issued_tick_ns':integer(row.data['issued_tick_ns']),
            'accepted_at_ms':self.access.now(),'source_sha256':sha256,'byte_length':len(payload),'context_sha256':context_hash,
            'runtime_instance_id':work.data['runtime_instance_id'],'observation_deadline_tick_ns':integer(row.data['observation_deadline_tick_ns'])}
        if retained:observation.update(retain_original_frame=True,original_capture_purpose_binding=original_binding,content_type=content_type)
        writes=(Write(key,row.revision,{**row.data,'status':'consumed','observation_id':ident}),
            Write(observation_key(ident),None,observation),Write(work.key,work.revision,{**work.data,
                'pending_permit_id':None,'pending_sequence':sequence,'pending_observation_id':ident,'latest_input_sequence':sequence}),
            self._upload_quota(work.data['station_id']))
        event=Write(Key('events','capture#'+str(uuid4())),None,{'kind':'observation_admitted','inspection_id':inspection_id,
            'observation_id':ident,'sequence':sequence,'source_sha256':sha256,'at_ms':self.access.now()})
        # No idempotent replay can return a consumed capability as a new upload.
        self.access._fresh(actor,Role.OPERATOR)
        commit_tick=self.tick()
        if commit_tick>=min(row.data['expires_tick_ns'],row.data['observation_deadline_tick_ns']) or self.access.now()>=deadline:
            raise Denied('capture expired before admission commit')
        if idem is not None:
            writes=(*writes,Write(idem,None,{'body_hash':body_hash,'result':{'observation_id':ident,'inspection_id':inspection_id,'sequence':sequence},'at_ms':self.access.now()}))
        def final():
            self.access._fresh(actor,Role.OPERATOR)
            self.stations.guard_policy(work.data,authority)
            if self.tick()>=min(row.data['expires_tick_ns'],row.data['observation_deadline_tick_ns']) or self.access.now()>=deadline:
                raise Denied('capture expired before admission commit')
        self.access._commit_linked('observation_admitted',(*writes,event),merge(actor.rows,authority,(row,)),before_commit=final)
        fresh=(self.tick()<min(row.data['expires_tick_ns'],row.data['observation_deadline_tick_ns']) and self.access.now()<deadline)
        return {**observation,'inspection_state_version':work.revision+1,'verified':False,'evidence_durable':False,'fresh_for_processing':fresh,'replayed':False}

    def _replayed_admission(self,actor,inspection_id,result):
        actor=self.access._fresh(actor,Role.OPERATOR)
        key=inspection_key(inspection_id);work=self.repository.snapshot((key,))[key]
        if work is None or work.data['originating_session_id']!=actor.session.data['id']:raise Denied('originating operator session required')
        self.access._fresh(actor,Role.OPERATOR)
        return {'id':result['observation_id'],'inspection_id':inspection_id,'sequence':integer(result['sequence']),'replayed':True}
