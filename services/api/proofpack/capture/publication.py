"""Evidence-first observation publication and effective status. No user assertions.

Configured object adapters are trusted server dependencies. Protocol tests must
not be represented as live S3 durability, physical qualification or beta approval.
"""
from dataclasses import replace,asdict
import hashlib
import json
from uuid import uuid4

from proofpack.calibrations.dependencies import digest as record_digest
from proofpack.auth.policy import Denied,Role
from proofpack.capture.service import observation_key
from proofpack.evidence.objects import ObjectReceipt
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.planner.policy import Action,ActionKind,acknowledge,choose_action,issue
from proofpack.runtime.control import integer,uuid
from proofpack.stations.service import inspection_key,merge
from proofpack.verifier.core import Authority,Finding,Inspection,Observation,State,verify
from proofpack.vision.calibration import CalibrationProfile
from proofpack.vision.worker import WorkerBusy,WorkerUnavailable
from proofpack.vision.worker_result import WorkerResult
from proofpack.vision.correction import validate_measurement, basis as correction_basis, verified_reference, target_indices
from proofpack.evidence.originals import original_capture_enabled,original_permission_binding,original_asset_id,ORIGINAL_MAX_ATTEMPTS,ORIGINAL_RETENTION_MS


def action_key(ident):return Key('state','action#'+uuid(ident))
def asset_key(ident):return Key('state','asset#'+uuid(ident))
def intent_key(ident):return Key('state','object-intent#'+uuid(ident))


class ObservationPublication:
    def __init__(self,service,objects,purpose_id):
        self.service=service;self.capture=service.capture;self.stations=service.stations
        self.access=service.access;self.repository=service.repository;self.objects=objects
        self.purpose_key=Key('state','purpose#'+uuid(purpose_id))
        if objects.config.deployment!=self.repository.deployment:raise ValueError('evidence deployment mismatch')
        if self.capture.dependency_snapshot is not None:raise ValueError('one publication purpose guard required')
        self.capture.dependency_snapshot=self.purpose_snapshot
        if self.capture.original_capture_guard is not None:raise ValueError('one original-capture guard required')
        self.capture.original_capture_guard=self.original_snapshot

    def purpose_snapshot(self):
        row=self.repository.snapshot((self.purpose_key,))[self.purpose_key]
        try:
            if (row is None or row.data['withdrawn'] is not False or not isinstance(row.data['allowed_uses'],list)
                    or 'operation' not in row.data['allowed_uses'] or self.access.now()>=integer(row.data['expires_at_ms'])):
                raise ValueError('operation purpose unavailable')
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('current operation purpose required') from exc
        original_capture_enabled(row,self.access)
        return (row,),integer(row.data['expires_at_ms'])

    def original_snapshot(self):
        rows,expiry=self.purpose_snapshot()
        if not original_capture_enabled(rows[0],self.access):raise Denied('separate original-capture purpose permission required')
        return rows,expiry

    def _fresh(self,observation,deadline):
        now=self.capture.tick()
        if (not integer(observation.data['accepted_tick_ns'])<=now<integer(observation.data['observation_deadline_tick_ns'])
                or self.access.now()>=deadline):raise Denied('observation expired before publication')
        return now

    def _authority(self,work):
        data=work.data
        until=integer(data['created_tick_ns'])+(integer(data['admission_expires_at_ms'])-integer(data['created_at_ms']))*1000000
        return Authority(runtime=integer(data['runtime_epoch']),control=integer(data['control_version']),data=integer(data['data_epoch']),
            station=integer(data['station_epoch']),recipe=integer(data['recipe_active_version']),calibration=integer(data['calibration_state_version']),
            policy=integer(data['policy_state_version']),access=integer(data['originating_access_version']),session=data['originating_session_id'],
            artifact=self.stations.runtime.artifact_sha256,enabled=True,operator_granted=True,dependencies_valid=True,valid_until_tick=until/1e9)

    def _inspection(self,work):
        data=work.data
        return Inspection(data['id'],self._authority(work),state=State(data['state']),version=integer(data.get('machine_version',1)),
            latest_input_sequence=integer(data['latest_input_sequence']),verified_sequence=integer(data['verified_sequence']),
            scene=integer(data.get('scene_generation',0)),stable_ticks=tuple(integer(t)/1e9 for t in data.get('stable_ticks_ns',[])),
            deadline_tick=integer(data.get('deadline_tick_ns',0))/1e9,corrections=integer(data['corrections']),disposition=data.get('disposition'))

    def _pending(self,actor,ident):
        key=observation_key(ident);observation=self.repository.snapshot((key,))[key]
        if observation is None:raise StoreUnavailable('observation unavailable')
        actor,work,scope,recipe,cal,deadline=self.service._scope(actor,observation.data['inspection_id'])
        if (observation.data['status']!='admitted' or work.data.get('pending_observation_id')!=ident
                or work.data.get('pending_sequence')!=observation.data['sequence']
                or work.data['latest_input_sequence']!=observation.data['sequence']
                or observation.data.get('policy_provenance')!=work.data['policy_provenance']):raise StoreConflict('observation is not pending admission')
        purpose,expiry=self.purpose_snapshot();deadline=min(deadline,expiry)
        return actor,work,observation,merge(scope,purpose,(observation,)),recipe,cal,deadline

    def process(self,actor,*,observation_id,payload):
        actor,work,observation,scope,recipe,cal,deadline=self._pending(actor,observation_id)
        objects=self.objects;config=objects.config;client=objects.client
        storage_binding=record_digest(asdict(config));endpoint=client.meta.endpoint_url;region=client.meta.region_name
        def storage_fresh():
            if (self.objects is not objects or objects.client is not client
                    or record_digest(asdict(objects.config))!=storage_binding
                    or client.meta.endpoint_url!=endpoint or client.meta.region_name!=region):
                raise StoreUnavailable('original capture storage target required')
        def intent_target(row):
            if row is None or row.data.get('storage_binding_sha256')!=storage_binding:
                raise StoreUnavailable('original capture intent target required')
        reason='provenance_mismatch'
        try:
            storage_fresh()
            if (not isinstance(payload,bytes) or len(payload)!=observation.data['byte_length']
                    or hashlib.sha256(payload).hexdigest()!=observation.data['source_sha256']):
                raise Denied('admitted byte provenance mismatch')
            reason='observation_expired'
            self._fresh(observation,deadline)
            reason='provenance_mismatch'
            profile=CalibrationProfile.model_validate_json(cal.data['profile_json'])
            if profile.content_hash!=cal.data['profile_sha256']:raise Denied('calibration profile provenance mismatch')
            reason='worker_unavailable'
            with self.service.registry.analyze(station_id=work.data['station_id'],epoch=integer(work.data['station_epoch']),
                    runtime_id=work.data['runtime_instance_id'],calibration_sha256=profile.content_hash) as binding:
                claimed={**observation.data,'status':'processing','worker_id':binding.worker_id}
                self.access._fresh(actor,Role.OPERATOR)
                self.stations.guard_policy(work.data,scope);self._fresh(observation,deadline)
                self.access._commit((Write(observation.key,observation.revision,claimed),),scope)
                observation=self.repository.snapshot((observation.key,))[observation.key]
                scope=tuple(row for row in scope if row.key!=observation.key)
                result=binding.worker.analyze(payload,recipe,profile,sequence=integer(observation.data['sequence']),inspection_id=work.data['id'])
                self._fresh(observation,deadline)
                if (result.source_sha256!=observation.data['source_sha256'] or result.calibration_hash!=profile.content_hash
                        or len(result.findings)!=len(recipe.constraints)):
                    raise Denied('worker result provenance or constraint coverage mismatch')
                geometry=validate_measurement(result,recipe,profile)
                evidence=result.evidence_bytes()
                reason='evidence_unavailable'
                if evidence is None:raise StoreUnavailable('cropped evidence unavailable')
                purpose,expiry=self.purpose_snapshot();deadline=min(deadline,expiry)
                self._fresh(observation,deadline)
                intent=Write(intent_key(observation_id),None,{'observation_id':observation_id,'asset_id':observation_id,'status':'reserved',
                    'storage_binding_sha256':storage_binding,
                    'key':objects.key(observation_id),'source_sha256':result.source_sha256,'crop_sha256':result.evidence_sha256,
                    'context_sha256':observation.data['context_sha256'],'purpose_id':self.purpose_key.resource[len('purpose#'):],
                    'user_id':work.data['originating_user_id'],'created_at_ms':self.access.now()})
                self.access._fresh(actor,Role.OPERATOR)
                self.stations.guard_policy(work.data,scope);self._fresh(observation,deadline)
                self.access._commit((intent,),merge(scope,purpose,(observation,)))
                storage_fresh()
                receipt=objects.put(asset_id=observation_id,payload=evidence,content_type='image/jpeg',context_sha256=observation.data['context_sha256'])
                storage_fresh()
                if receipt.source_sha256!=result.evidence_sha256:raise Denied('stored crop provenance mismatch')
                intentrow=self.repository.snapshot((intent.key,))[intent.key]
                intent_target(intentrow)
                self.access._commit((Write(intent.key,intentrow.revision,{**intentrow.data,'status':'uploaded','version_id':receipt.version_id}),))
                intentrow=self.repository.snapshot((intent.key,))[intent.key]
                intent_target(intentrow)
                original=None;original_intent=None
                if observation.data.get('retain_original_frame') is True:
                    allowed,original_expiry=self.original_snapshot();deadline=min(deadline,original_expiry)
                    if original_permission_binding(allowed)!=observation.data.get('original_capture_purpose_binding'):raise Denied('original permission binding changed')
                    if ((observation.data['content_type']=='image/jpeg' and not payload.startswith(b'\xff\xd8'))
                            or (observation.data['content_type']=='image/png' and not payload.startswith(b'\x89PNG\r\n\x1a\n'))):raise Denied('original image format mismatch')
                    oid=original_asset_id(observation_id);original_intent=Write(intent_key(oid),None,{'observation_id':observation_id,'asset_id':oid,
                        'status':'reserved','storage_binding_sha256':storage_binding,'key':objects.key(oid),'source_sha256':result.source_sha256,'context_sha256':observation.data['context_sha256'],
                        'purpose_id':self.purpose_key.resource[len('purpose#'):],'derivation':'original_transmitted_frame','user_id':work.data['originating_user_id'],'created_at_ms':self.access.now()})
                    self.access._fresh(actor,Role.OPERATOR);self._fresh(observation,deadline)
                    self.stations.guard_policy(work.data,scope);self._fresh(observation,deadline)
                    self.access._commit((original_intent,),merge(scope,allowed,(observation,)))
                    storage_fresh()
                    original=objects.put(asset_id=oid,payload=payload,content_type=observation.data['content_type'],context_sha256=observation.data['context_sha256'])
                    storage_fresh()
                    if (not isinstance(original,ObjectReceipt) or original.asset_id!=oid or original.key!=objects.key(oid)
                            or original.context_sha256!=observation.data['context_sha256'] or original.content_type!=observation.data['content_type']
                            or original.source_sha256!=result.source_sha256 or type(original.byte_length) is not int or original.byte_length!=len(payload)):
                        raise Denied('original storage provenance mismatch')
                    objects._params(oid,original.version_id)
                    original_intent=self.repository.snapshot((original_intent.key,))[original_intent.key]
                    intent_target(original_intent)
                    self.access._commit((Write(original_intent.key,original_intent.revision,{**original_intent.data,'status':'uploaded','version_id':original.version_id}),))
                    original_intent=self.repository.snapshot((original_intent.key,))[original_intent.key]
                    intent_target(original_intent)
                reason='authority_changed'
                actor,current,current_scope,current_recipe,current_cal,current_deadline=self.service._scope(actor,work.data['id'])
                purpose,expiry=self.purpose_snapshot();deadline=min(deadline,current_deadline,expiry)
                if (current.data.get('pending_observation_id')!=observation_id
                        or current.data.get('pending_sequence')!=observation.data['sequence']
                        or current.data['latest_input_sequence']!=observation.data['sequence']):raise StoreConflict('superseded observation')
                self.service.registry.guard(current.data['station_id'],integer(current.data['station_epoch']),current.data['runtime_instance_id'])
                reason='observation_expired';now=self._fresh(observation,deadline)
                authority=self._authority(current);pure=self._inspection(current)
                finding=Observation(observation_id,integer(observation.data['sequence']),result.scene_generation,
                    integer(observation.data['accepted_tick_ns'])/1e9,integer(observation.data['permit_issued_tick_ns'])/1e9,
                    tuple(result.findings),len(current_recipe.constraints),result.quality_ok,result.unknown_regions,True,authority)
                decision=verify(pure,finding,authority,now/1e9)
                satisfied=(all(value==Finding.SATISFIED for value in result.findings) and result.quality_ok and result.unknown_regions==0)
                stable=(list(current.data.get('stable_ticks_ns',[])) if current.data.get('scene_generation',0)==result.scene_generation else []) if satisfied else []
                if satisfied:stable.append(integer(observation.data['accepted_tick_ns']))
                if len(stable)>32:stable=[stable[0],*stable[-31:]]
                if decision.state==State.PASSED_CURRENT and (len(stable)<3 or stable[-1]-stable[0]<1000000000):
                    decision=replace(decision,state=State.OBSERVING,deadline_tick=0)
                action=None;action_write=()
                if not satisfied and decision.state==State.OBSERVING:
                    policy=self.stations.policy_definition(current.data,current_scope)
                    kind=choose_action(tuple(result.reason_codes),priority=policy.priority) if decision.corrections<2 else ActionKind.REVIEW
                    targets=target_indices(geometry,kind.value)
                    if kind in {ActionKind.SEPARATE_REGION,ActionKind.PLACE_FLAT} and not targets:kind=ActionKind.REVIEW
                    action=Action(str(uuid4()),kind,observation_id,result.scene_generation,decision.version)
                    decision=issue(decision,action,latest_observation_id=observation_id)
                    action_write=(Write(action_key(action.action_id),None,{'id':action.action_id,'kind':kind.value,'observation_id':observation_id,
                        'scene_generation':result.scene_generation,'source_machine_version':action.source_version,
                        'status':'pending' if decision.state==State.ACTION_REQUIRED else 'review','message':action.message,
                        'target_candidate_indices':targets,
                        'policy_state_version':current.data['policy_state_version'],'policy_provenance':current.data['policy_provenance']}),)
                    stable=[]
                deadline_ns=min(int(decision.deadline_tick*1e9),integer(observation.data['observation_deadline_tick_ns']),
                    integer(observation.data['accepted_tick_ns'])+1500000000) if decision.state==State.PASSED_CURRENT else 0
                metadata=result.model_dump_json(exclude={'evidence_jpeg_base64','evidence_sha256'})
                storage_fresh()
                if (intentrow.data.get('storage_binding_sha256')!=storage_binding
                        or (original_intent is not None and original_intent.data.get('storage_binding_sha256')!=storage_binding)):
                    raise StoreUnavailable('original capture intent target required')
                asset={'storage_binding_sha256':storage_binding,'id':receipt.asset_id,'status':'committed','read_denied':False,'sha256':receipt.source_sha256,
                    'input_sha256':result.source_sha256,'context_sha256':receipt.context_sha256,'object_key':receipt.key,'object_version':receipt.version_id,
                    'byte_length':receipt.byte_length,'content_type':receipt.content_type,'purpose_id':self.purpose_key.resource[len('purpose#'):],
                    'expires_at_ms':min(expiry,integer(observation.data['accepted_at_ms'])+7*86400000),'data_origin':current_recipe.data_origin.value,
                    'observation_id':observation_id,'derivation':'rectified_roi_jpeg'}
                completed={**observation.data,'status':'completed','result_json':metadata,'asset_id':receipt.asset_id,
                    'evidence_sha256':receipt.source_sha256,'completed_at_ms':self.access.now()}
                _,correction_sha=correction_basis(metadata,receipt.source_sha256)
                if correction_sha is not None:
                    asset['correction_basis_sha256']=correction_sha;completed['correction_basis_sha256']=correction_sha
                    if action_write:action_write[0].data['correction_basis_sha256']=correction_sha
                original_writes=();original_checks=()
                if original is not None:
                    allowed,_=self.original_snapshot()
                    if original_permission_binding(allowed)!=observation.data['original_capture_purpose_binding']:raise Denied('original permission changed before publication')
                    original_ids=current.data.get('original_asset_ids',[])
                    if (not isinstance(original_ids,list) or len(original_ids)>=ORIGINAL_MAX_ATTEMPTS or original.asset_id in original_ids):raise StoreConflict('bounded original history required')
                    original_asset={**asset,'id':original.asset_id,'sha256':original.source_sha256,'input_sha256':result.source_sha256,
                        'object_key':original.key,'object_version':original.version_id,'byte_length':original.byte_length,'content_type':original.content_type,
                        'derivation':'original_transmitted_frame','calibration_sha256':profile.content_hash,'replay_profile_json':profile.model_dump_json(),
                        'expires_at_ms':min(expiry,integer(observation.data['accepted_at_ms'])+ORIGINAL_RETENTION_MS)}
                    original_asset.pop('correction_basis_sha256',None)
                    completed.update(original_asset_id=original.asset_id,original_evidence_sha256=original.source_sha256)
                    original_writes=(Write(asset_key(original.asset_id),None,original_asset),Write(original_intent.key,original_intent.revision,{**original_intent.data,'status':'linked'}))
                    original_checks=(*allowed,original_intent)
                updated={**current.data,'state':decision.state.value,'machine_version':decision.version,'verified_sequence':decision.verified_sequence,
                    'scene_generation':decision.scene,'stable_ticks_ns':stable,'deadline_tick_ns':deadline_ns,'corrections':decision.corrections,
                    'pending_sequence':None,'pending_observation_id':None,'latest_observation_id':observation_id,
                    'current_action_id':None if action is None else action.action_id,'failure_reason':None}
                if original is not None:updated['original_asset_ids']=[*original_ids,original.asset_id]
                event=Write(Key('events','capture#'+str(uuid4())),None,{'kind':'observation_completed','inspection_id':current.data['id'],
                    'observation_id':observation_id,'sequence':integer(observation.data['sequence']),'asset_id':receipt.asset_id,
                    'input_sha256':result.source_sha256,'crop_sha256':receipt.source_sha256,'state':decision.state.value,
                    'action_id':None if action is None else action.action_id,'at_ms':self.access.now(),
                    'policy_state_version':current.data['policy_state_version'],'policy_provenance':current.data['policy_provenance']})
                if correction_sha is not None:
                    event.data['correction_basis_sha256']=correction_sha
                    if action is not None:
                        event.data.update(action_kind=action.kind.value,target_candidate_indices=action_write[0].data['target_candidate_indices'])
                if original is not None:event.data.update(original_asset_id=original.asset_id,original_sha256=original.source_sha256)
                def final():
                    self.access._fresh(actor,Role.OPERATOR);self._fresh(observation,deadline)
                    self.stations.guard_policy(current.data,current_scope);self._fresh(observation,deadline)
                    storage_fresh()
                self.access._commit_linked('observation_completed',(Write(current.key,current.revision,updated),Write(observation.key,observation.revision,completed),
                    Write(asset_key(receipt.asset_id),None,asset),Write(intent.key,intentrow.revision,{**intentrow.data,'status':'linked'}),event,*action_write,*original_writes),
                    merge(actor.rows,current_scope,purpose,(observation,intentrow),original_checks),before_commit=final)
            return self.status(actor,work.data['id'])
        except WorkerBusy as exc:raise StoreConflict('observation is already processing') from exc
        except (Denied,StoreConflict,StoreUnavailable,WorkerUnavailable,ValueError) as exc:
            if isinstance(exc,WorkerUnavailable):reason='worker_unavailable'
            elif isinstance(exc,(Denied,StoreConflict)) and reason!='provenance_mismatch':reason='authority_changed' if self.capture.tick()<observation.data['observation_deadline_tick_ns'] else 'observation_expired'
            try:self.service.fail(observation_id,reason=reason)
            except (StoreConflict,StoreUnavailable,Denied):pass
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('measurement unavailable; review station') from exc
            raise

    @staticmethod
    def _receipt(asset):
        data=asset.data
        return ObjectReceipt(data['id'],data['object_key'],data['object_version'],data['sha256'],data['context_sha256'],integer(data['byte_length']),data['content_type'])

    def status(self,actor,inspection_id):
        actor=self.access._fresh(actor);key=inspection_key(inspection_id);work=self.repository.snapshot((key,))[key]
        if work is None:raise StoreUnavailable('inspection unavailable')
        base={'id':inspection_id,'station_id':work.data['station_id'],'state_version':work.revision,'effective_state':work.data['state'],
            'last_observed_at':None,'expires_at':None,'remaining_lease_ms':0,'reason_codes':[],'action':None,'disposition':work.data.get('disposition')}
        if work.data['state']=='CLOSED':return base
        try:
            actor,work,scope,recipe,cal,deadline=self.stations.inspection_authority(actor,inspection_id)
            base['state_version']=work.revision;base['effective_state']=work.data['state']
            self.service.registry.guard(work.data['station_id'],integer(work.data['station_epoch']),work.data['runtime_instance_id'])
            ident=work.data.get('latest_observation_id')
            if ident is None:
                if work.data['state'] not in {'CREATED','OBSERVING','INVALIDATED'}:
                    raise StoreUnavailable('supporting observation missing')
                self.access._fresh(actor);self.stations.guard_policy(work.data,scope)
                current=self.repository.snapshot(tuple(row.key for row in scope))
                if any(current[row.key]!=row for row in scope):raise StoreConflict('empty status authority changed')
                return base
            obskey=observation_key(ident);obs=self.repository.snapshot((obskey,))[obskey]
            if (obs is None or obs.data['status']!='completed' or obs.data['sequence']!=work.data['verified_sequence']
                    or obs.data.get('policy_provenance')!=work.data['policy_provenance']):raise StoreUnavailable('completed bound policy evidence missing')
            akey=asset_key(obs.data['asset_id']);asset=self.repository.snapshot((akey,))[akey]
            purpose,expiry=self.purpose_snapshot()
            if (asset is None or asset.data['status']!='committed' or asset.data['read_denied'] is not False
                    or asset.data['sha256']!=obs.data['evidence_sha256'] or asset.data['input_sha256']!=obs.data['source_sha256']
                    or asset.data['context_sha256']!=obs.data['context_sha256'] or asset.data['purpose_id']!=self.purpose_key.resource[len('purpose#'):]
                    or self.access.now()>=asset.data['expires_at_ms']):raise StoreUnavailable('permitted evidence missing')
            original=None
            if obs.data.get('retain_original_frame') is True:
                okey=asset_key(original_asset_id(ident));original=self.repository.snapshot((okey,))[okey]
                if (original is None or original.data['id']!=obs.data.get('original_asset_id')
                        or original.data['derivation']!='original_transmitted_frame' or original.data['status']!='committed' or original.data['read_denied'] is not False
                        or original.data['sha256']!=obs.data.get('original_evidence_sha256') or original.data['sha256']!=obs.data['source_sha256']
                        or original.data['input_sha256']!=obs.data['source_sha256'] or original.data['context_sha256']!=obs.data['context_sha256']
                        or original.data['observation_id']!=ident or original.data['purpose_id']!=asset.data['purpose_id']
                        or self.access.now()>=integer(original.data['expires_at_ms'])):raise StoreUnavailable('selected original evidence missing')
                self.original_snapshot()
            result=WorkerResult.model_validate_json(obs.data['result_json'])
            correction=verified_reference(asset.data,obs.data)
            if original is not None and original.data['calibration_sha256']!=result.calibration_hash:raise StoreUnavailable('original calibration binding changed')
            base['last_observed_at']=integer(obs.data['accepted_at_ms']);base['reason_codes']=list(result.reason_codes)
            remaining=0
            if work.data['state']=='PASSED_CURRENT':
                self.objects.validate(self._receipt(asset))
                if original is not None:self.objects.validate(self._receipt(original))
                remaining=min((integer(work.data['deadline_tick_ns'])-self.capture.tick())//1000000,
                    deadline-self.access.now(),expiry-self.access.now(),integer(asset.data['expires_at_ms'])-self.access.now())
                if remaining<=0:raise Denied('current observation lease expired')
            action=None
            if work.data.get('current_action_id'):
                action=self.repository.snapshot((action_key(work.data['current_action_id']),))[action_key(work.data['current_action_id'])]
                if (action is None or action.data.get('policy_provenance')!=work.data['policy_provenance']
                        or action.data.get('policy_state_version')!=work.data['policy_state_version']):raise StoreUnavailable('current action policy provenance missing')
                if action.data.get('correction_basis_sha256') is not None:
                    if (correction is None or action.data['correction_basis_sha256']!=correction['basis_sha256']
                            or action.data['observation_id']!=obs.data['id'] or action.data['scene_generation']!=result.scene_generation
                            or action.data.get('target_candidate_indices')!=target_indices(correction,action.data['kind'])):
                        raise StoreUnavailable('current correction target/source binding changed')
            allrows=merge(actor.rows,scope,purpose,(obs,asset,action,original))
            self.access._fresh(actor);self.stations.guard_policy(work.data,scope)
            final=self.repository.snapshot(tuple(row.key for row in allrows))
            if any(final[row.key]!=row for row in allrows):raise StoreConflict('status authority changed')
            if self.access.now()>=min(deadline,expiry,integer(asset.data['expires_at_ms']),integer(original.data['expires_at_ms']) if original is not None else 9007199254740991):raise Denied('status authority expired')
            if work.data['state']=='PASSED_CURRENT':
                now=self.access.now()
                remaining=min(remaining,(integer(work.data['deadline_tick_ns'])-self.capture.tick())//1000000,
                    deadline-now,expiry-now,integer(asset.data['expires_at_ms'])-now,integer(original.data['expires_at_ms'])-now if original is not None else 2147483647)
                if remaining<=0:raise Denied('current observation lease expired')
                base['remaining_lease_ms']=remaining;base['expires_at']=now+remaining
            if action is not None:base['action']={'id':action.data['id'],'kind':action.data['kind'],'message':action.data['message'],'observation_id':action.data['observation_id'],
                'correction_reference_available':bool(work.data['state']=='ACTION_REQUIRED' and action.data.get('status')=='pending' and correction is not None and target_indices(correction,action.data['kind']))}
            return base
        except (Denied,StoreConflict,StoreUnavailable,WorkerUnavailable,KeyError,ValueError,TypeError):
            self.access._fresh(actor)
            return {**base,'effective_state':'INVALIDATED','remaining_lease_ms':0,'expires_at':None,'action':None,'reason_codes':['AUTHORITY_OR_EVIDENCE_UNAVAILABLE']}

    def acknowledge(self,actor,*,inspection_id,action_id,expected_version,idempotency_key):
        actor=self.access._fresh(actor,Role.OPERATOR)
        actor,work,scope,recipe,cal,deadline=self.stations.inspection_authority(actor,inspection_id)
        if work.data['originating_session_id']!=actor.session.data['id']:raise Denied('originating operator required')
        operation='action-ack:'+inspection_id+':'+uuid(action_id)
        idem,digest,replay=self.access._idempotency(actor,operation,idempotency_key,{'expected_version':expected_version})
        if replay is not None:return self.status(actor,inspection_id)
        if type(expected_version) is not int or expected_version!=work.revision:raise StoreConflict('inspection version changed')
        row=self.repository.snapshot((action_key(action_id),))[action_key(action_id)]
        if (row is None or row.data['status']!='pending' or work.data.get('current_action_id')!=action_id
                or work.data.get('latest_observation_id')!=row.data['observation_id']
                or row.data.get('policy_provenance')!=work.data['policy_provenance']
                or row.data.get('policy_state_version')!=work.data['policy_state_version']):raise StoreConflict('action is not current')
        observed=self.repository.snapshot((observation_key(row.data['observation_id']),))[observation_key(row.data['observation_id'])]
        if (observed is None or observed.data['status']!='completed' or observed.data['sequence']!=work.data['verified_sequence']
                or observed.data.get('policy_provenance')!=work.data['policy_provenance']):raise StoreConflict('action source policy evidence changed')
        action=Action(action_id,ActionKind(row.data['kind']),row.data['observation_id'],integer(row.data['scene_generation']),integer(row.data['source_machine_version']))
        decision=acknowledge(self._inspection(work),action,action_id)
        def final():
            self.stations.guard_policy(work.data,scope)
            if self.access.now()>=deadline:raise Denied('action acknowledgment authority expired')
        self.access._record(actor,operation,idem,digest,{'inspection_id':inspection_id,'action_id':action_id},
            (Write(work.key,work.revision,{**work.data,'state':decision.state.value,'machine_version':decision.version,
                'current_action_id':None,'stable_ticks_ns':[],'deadline_tick_ns':0}),
             Write(row.key,row.revision,{**row.data,'status':'acknowledged'}),self.stations._quota(work.data['station_id'])),
            merge(actor.rows,scope,(row,observed)),required_role=Role.OPERATOR,before_commit=final,
            event_details={'inspection_id':inspection_id,'action_id':action_id,'observation_id':row.data['observation_id']})
        return self.status(actor,inspection_id)
