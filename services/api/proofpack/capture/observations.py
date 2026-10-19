"""Warm preparation and withdrawal-only failure reconciliation.

Failure callbacks are internal service cleanup, never a public certification or
approval route. Successful measurement/evidence/verifier publication is separate.
"""
from uuid import uuid4
from threading import Lock

from proofpack.auth.policy import Denied,Role
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.runtime.control import RUNTIME,ALLOCATION,integer
from proofpack.stations.service import inspection_key,station_key,merge,StationRateLimited
from proofpack.vision.calibration import CalibrationProfile
from proofpack.evidence.originals import original_capture_enabled,ORIGINAL_MAX_ATTEMPTS
from proofpack.vision.worker import WorkerBusy,WorkerUnavailable
from proofpack.capture.service import observation_key

FAILURES=frozenset({'worker_unavailable','evidence_unavailable','provenance_mismatch','observation_expired','authority_changed'})


class ObservationService:
    def __init__(self,capture,registry,*,objects=None,purpose_id=None):
        if capture.worker_guard!=registry.guard:raise ValueError('observation service requires its actual registry guard')
        self.capture=capture;self.stations=capture.stations;self.registry=registry
        self.access=capture.access;self.repository=capture.repository
        if self.stations.worker_invalidator not in (None,registry.invalidate):raise ValueError('one worker registry per station service')
        self.stations.worker_invalidator=registry.invalidate
        if (objects is None)!=(purpose_id is None):raise ValueError('paired evidence store and operation purpose required')
        self.publisher=None
        self._upload_lock=Lock();self._uploads={}
        if objects is not None:
            from proofpack.capture.publication import ObservationPublication
            self.publisher=ObservationPublication(self,objects,purpose_id)

    def process(self,actor,*,observation_id,payload):
        if self.publisher is None:raise StoreUnavailable('evidence publication is not configured')
        return self.publisher.process(actor,observation_id=observation_id,payload=payload)

    def context(self,actor,inspection_id):
        actor,_=self._upload_scope(actor,inspection_id)
        actor,work,scope,recipe,cal,deadline=self.stations.inspection_authority(actor,inspection_id)
        try:profile=CalibrationProfile.model_validate_json(cal.data['profile_json'])
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('qualified capture geometry unavailable') from exc
        if (profile.content_hash!=cal.data['profile_sha256'] or profile.profile_id!=recipe.calibration_profile_id
                or profile.data_origin!=recipe.data_origin):
            raise StoreUnavailable('qualified capture geometry unavailable')
        import cv2
        import numpy as np
        plane=np.asarray(profile.plane_corners,np.float64).reshape(-1,2)
        reference=np.asarray(profile.enrolled_image_corners,np.float64).reshape(-1,2)
        transform,_=cv2.findHomography(plane,reference,method=0)
        if transform is None or not np.isfinite(transform).all():raise StoreUnavailable('capture geometry unavailable')
        corners=np.float64([[[0,0],[profile.output_width-1,0],[profile.output_width-1,profile.output_height-1],[0,profile.output_height-1]]])
        roi=cv2.perspectiveTransform(corners,transform).reshape(-1,2)
        if (not np.isfinite(roi).all() or (roi<0).any() or (roi[:,0]>=profile.frame_width).any()
                or (roi[:,1]>=profile.frame_height).any()):raise StoreUnavailable('capture work area unavailable')
        purpose,expiry=self.publisher.purpose_snapshot();rows=merge(actor.rows,scope,purpose,(work,))
        self.access._fresh(actor,Role.OPERATOR)
        self.stations.guard_policy(work.data,scope)
        final=self.repository.snapshot(tuple(row.key for row in rows))
        if any(final[row.key]!=row for row in rows):raise StoreConflict('capture context changed')
        remaining=min(deadline,expiry)-self.access.now()
        if remaining<=0:raise Denied('capture context expired')
        original_count=integer(work.data.get('original_attempts_reserved',0))
        if not 0<=original_count<=ORIGINAL_MAX_ATTEMPTS:raise StoreUnavailable('original frame budget unavailable')
        return {'context_version':1,'capture_transform':'center_crop_resize_no_upscale','inspection_id':inspection_id,
            'state_version':work.revision,'recipe_id':recipe.recipe_id,'recipe_name':recipe.name,'recipe_revision':recipe.revision,
            'constraints':[item.model_dump(mode='json') for item in recipe.constraints],
            'calibration_id':profile.profile_id,'calibration_sha256':profile.content_hash,'camera_label':profile.camera_id,
            'frame_width':profile.frame_width,'frame_height':profile.frame_height,
            'work_polygon':[[float(x/profile.frame_width),float(y/profile.frame_height)] for x,y in roi],
            'data_origin':recipe.data_origin.value,'policy_mode':'deterministic_policy','remaining_context_ms':remaining,
            'original_capture_retention_allowed':original_capture_enabled(purpose[0],self.access),
            'original_capture_remaining_attempts':ORIGINAL_MAX_ATTEMPTS-original_count}

    def status(self,actor,inspection_id):
        return self.stations.inspection(actor,inspection_id) if self.publisher is None else self.publisher.status(actor,inspection_id)

    def acknowledge(self,actor,**arguments):
        if self.publisher is None:raise StoreUnavailable('action publication is not configured')
        return self.publisher.acknowledge(actor,**arguments)

    def _upload_scope(self,actor,inspection_id):
        if self.publisher is None:raise StoreUnavailable('evidence publication is not configured')
        actor=self.access._fresh(actor,Role.OPERATOR)
        key=inspection_key(inspection_id);work=self.repository.snapshot((key,))[key]
        if work is None:raise StoreUnavailable('inspection unavailable')
        if work.data['originating_session_id']!=actor.session.data['id']:raise Denied('originating operator session required')
        return actor,work

    def begin_upload(self,actor,inspection_id):
        actor,work=self._upload_scope(actor,inspection_id)
        with self._upload_lock:
            if work.data['station_id'] in self._uploads.values():raise StoreConflict('one station upload is already active')
            if len(self._uploads)>=2:raise StationRateLimited('upload capacity reached')
            token=str(uuid4());self._uploads[token]=work.data['station_id'];return token

    def end_upload(self,token):
        with self._upload_lock:self._uploads.pop(token,None)

    def upload(self,actor,*,inspection_id,expected_version,idempotency_key,image):
        actor,work=self._upload_scope(actor,inspection_id)
        admitted=self.capture.admit(actor,inspection_id=inspection_id,expected_version=expected_version,
            permit_id=image.permit_id,nonce=image.nonce,sequence=image.sequence,payload=image.payload,
            idempotency_key=idempotency_key,content_type=image.content_type)
        if not admitted['replayed']:self.process(actor,observation_id=admitted['id'],payload=image.payload)
        actor,work=self._upload_scope(actor,inspection_id)
        key=observation_key(admitted['id']);observation=self.repository.snapshot((key,))[key]
        purpose,expiry=self.publisher.purpose_snapshot()
        if observation is None or observation.data['inspection_id']!=inspection_id:raise StoreUnavailable('observation unavailable')
        measurement=None
        if observation.data['status']=='completed':
            from proofpack.vision.worker_result import WorkerResult
            measured=WorkerResult.model_validate_json(observation.data['result_json'])
            measurement=measured.model_dump(mode='json',include={'candidates','findings','reason_codes','quality_ok','unknown_regions','scene_generation'})
        rows=merge(actor.rows,purpose,(work,observation));final=self.repository.snapshot(tuple(row.key for row in rows))
        if any(final[row.key]!=row for row in rows):raise StoreConflict('observation read authority changed')
        self.access._fresh(actor,Role.OPERATOR)
        if self.access.now()>=expiry:raise Denied('operation purpose expired')
        current=self.status(actor,inspection_id)
        if self.access.now()>=expiry:raise Denied('operation purpose expired')
        return {'observation_id':admitted['id'],'sequence':integer(observation.data['sequence']),
            'operation_status':observation.data['status'],'replayed':admitted['replayed'],'measurement':measurement,'status':current}

    def _scope(self,actor,inspection_id):
        actor=self.access._fresh(actor,Role.OPERATOR)
        actor,work,rows,recipe,cal,deadline=self.stations.inspection_authority(actor,inspection_id)
        if work.data['originating_session_id']!=actor.session.data['id']:raise Denied('originating operator session required')
        if work.data['state'] in {'CLOSED','REVIEW_REQUIRED','ACTION_REQUIRED'}:raise StoreConflict('inspection cannot prepare capture')
        return actor,work,rows,recipe,cal,deadline

    def prepare(self,actor,*,inspection_id,expected_version,idempotency_key):
        if type(expected_version) is not int or expected_version<1:raise ValueError('inspection version required')
        actor,work,rows,recipe,cal,deadline=self._scope(actor,inspection_id)
        operation='worker-prepare:'+inspection_id
        idem,digest,replay=self.access._idempotency(actor,operation,idempotency_key,{'expected_version':expected_version})
        if replay is None and work.revision!=expected_version:raise StoreConflict('inspection version changed')
        try:
            profile=CalibrationProfile.model_validate_json(cal.data['profile_json'])
            if (profile.profile_id!=recipe.calibration_profile_id or profile.data_origin!=recipe.data_origin
                    or profile.content_hash!=cal.data['profile_sha256']):raise ValueError('calibration profile mismatch')
        except (ValueError,TypeError,KeyError) as exc:raise StoreUnavailable('qualified immutable calibration profile required') from exc
        data=work.data;station=data['station_id'];epoch=integer(data['station_epoch']);runtime=data['runtime_instance_id']
        worker_id=None
        try:
            worker_id=self.registry.prepare(station_id=station,epoch=epoch,runtime_id=runtime,calibration_sha256=profile.content_hash)
            current,new_work,new_rows,new_recipe,new_cal,new_deadline=self._scope(actor,inspection_id)
            if (new_work.data['station_epoch']!=epoch or new_work.data['runtime_instance_id']!=runtime
                    or new_cal.data['profile_sha256']!=profile.content_hash):raise StoreConflict('worker context changed while warming')
            self.registry.guard(station,epoch,runtime)
        except (Denied,StoreConflict,StoreUnavailable,WorkerUnavailable) as exc:
            if worker_id is not None:
                try:self.registry.retire(station,worker_id=worker_id)
                except WorkerBusy:pass
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('warm worker unavailable; reviewed station restart required') from exc
            raise
        if replay is None:
            if new_work.revision!=work.revision:raise StoreConflict('inspection changed while warming')
            self.access._record(current,operation,idem,digest,{'inspection_id':inspection_id,'prepared_epoch':epoch},(),
                merge(current.rows,rows,new_rows),required_role=Role.OPERATOR,
                before_commit=lambda:self.stations.guard_policy(new_work.data,new_rows),
                event_details={'inspection_id':inspection_id,'station_id':station,'station_epoch':epoch,
                    'runtime_instance_id':runtime,'worker_id':worker_id,'calibration_sha256':profile.content_hash})
        self.access._fresh(current,Role.OPERATOR)
        self.stations.guard_policy(new_work.data,new_rows)
        if self.access.now()>=new_deadline:raise Denied('worker preparation authority expired')
        return {'inspection_id':inspection_id,'inspection_state_version':new_work.revision,'ready':True}

    def fail(self,observation_id,*,reason):
        """Withdraw this runtime's admitted work; never grants capture or a pass.

        Cleanup may record a fault after the source user logs out. It can only
        affect the exact still-pending observation/station context, and holds no
        publish/enable/restart authority. Superseded work is historical discard.
        """
        if reason not in FAILURES:raise ValueError('known observation failure required')
        key=observation_key(observation_id);first=self.repository.snapshot((key,))[key]
        if first is None:raise StoreUnavailable('admitted observation unavailable')
        if first.data['runtime_instance_id']!=self.stations.runtime.instance_id:raise Denied('owned runtime observation required')
        workkey=inspection_key(first.data['inspection_id']);skey=station_key(first.data['station_id'])
        rows=self.repository.snapshot((key,workkey,skey,RUNTIME,ALLOCATION))
        observation,work,station=rows[key],rows[workkey],rows[skey]
        if observation!=first:raise StoreConflict('observation changed during failure reconciliation')
        if observation.data['status'] not in {'admitted','processing'}:
            return {'observation_id':observation_id,'status':observation.data['status']}
        active=(self.stations.runtime.matches(rows[RUNTIME]) and work is not None and station is not None
            and work.data['state']!='CLOSED' and work.data.get('pending_observation_id')==observation_id
            and work.data.get('pending_sequence')==observation.data['sequence']
            and station.data['active_inspection_id']==work.data['id']
            and station.data['epoch']==observation.data['station_epoch']
            and self.stations._allocation(rows[ALLOCATION]).get(work.data['id'])==station.data['id'])
        status='failed' if active else 'discarded';writes=[]
        if active:
            review=reason!='observation_expired'
            writes.append(Write(workkey,work.revision,{**work.data,'state':'REVIEW_REQUIRED' if review else 'INVALIDATED',
                'pending_observation_id':None,'pending_sequence':None,'pending_permit_id':None,
                'deadline_tick_ns':0,'stable_ticks_ns':[],'failure_reason':reason}))
            if review:writes.append(Write(skey,station.revision,{**station.data,'epoch':integer(station.data['epoch'])+1}))
        writes.append(Write(key,observation.revision,{**observation.data,'status':status,'failure_reason':reason,'failed_at_ms':self.access.now()}))
        writes.append(Write(Key('events','capture#'+str(uuid4())),None,{'kind':'observation_failed','observation_id':observation_id,
            'inspection_id':observation.data['inspection_id'],'status':status,'reason':reason,'at_ms':self.access.now()}))
        # Revision conditions fence old callbacks against close/takeover/restart.
        self.access._commit_linked('observation_failed',tuple(writes),tuple(row for row in rows.values() if row is not None))
        if active and reason!='observation_expired':
            self.registry.invalidate(observation.data['station_id'],integer(observation.data['station_epoch']),observation.data['runtime_instance_id'])
        return {'observation_id':observation_id,'status':status}
