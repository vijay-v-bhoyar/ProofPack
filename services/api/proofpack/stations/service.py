"""Durable station setup/ownership and CREATED inspection admission.

No frame, observation or pass is produced here. Calibration/policy dependency
records are private assurance inputs; their genuine writers remain separate work.
"""
import re
import time
from uuid import uuid4

from proofpack.calibrations.dependencies import digest as record_digest,canonical
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable,user_key
from proofpack.evidence.repository import Key,Row,StoreConflict,StoreUnavailable,Write
from proofpack.recipes.service import active_key as recipe_active_key
from proofpack.runtime.control import DATA,ALLOCATION,allocation_slots,integer,sha,uuid
from proofpack.capture.provenance import policy_provenance

POLICY=Key('state','policy-active')
DISPOSITIONS=frozenset({'rework','reject','cancelled','human_accepted'})


class StationRateLimited(RuntimeError):pass


def station_key(ident):return Key('state','station#'+uuid(ident))
def inspection_key(ident):return Key('state','inspection#'+uuid(ident))


def merge(*groups):
    rows={}
    for group in groups:
        for row in group:
            if row is None:continue
            if row.key in rows and rows[row.key]!=row:raise StoreConflict('authority changed across snapshots')
            rows[row.key]=row
    return tuple(rows.values())


class StationService:
    def __init__(self,access,runtime,recipes,*,tick_ns=None,policy_reader=None):
        if (runtime.access is not access or recipes.access is not access
                or runtime.environment!=recipes.environment or runtime.artifact_sha256!=recipes.artifact_sha256):
            raise ValueError('station dependencies must share access/environment/artifact')
        self.access=access;self.repository=access.repository;self.runtime=runtime;self.recipes=recipes
        self.tick_ns=tick_ns or time.monotonic_ns
        self.worker_invalidator=None
        if policy_reader is not None and (policy_reader.access is not access or policy_reader.runtime is not runtime
                or policy_reader.repository is not self.repository or not callable(policy_reader.read_current)):
            raise ValueError('policy reader must share exact station authority')
        self._policy_reader=policy_reader

    @property
    def policy_reader(self):return self._policy_reader

    def _policy_snapshot(self):
        from proofpack.planner.active import ActivePolicySnapshot
        from proofpack.planner.candidates import PolicyDraft
        reader=self.policy_reader
        if (reader is None or reader.access is not self.access or reader.runtime is not self.runtime
                or reader.repository is not self.repository):raise StoreUnavailable('trusted active policy reader required')
        value=reader.read_current()
        if (not isinstance(value,ActivePolicySnapshot) or not isinstance(value.dependencies,tuple)
                or not callable(value.final_guard) or type(value.expires_at_ms) is not int
                or not isinstance(value.policy,Row) or value.policy.key!=POLICY
                or any(not isinstance(row,Row) for row in value.dependencies)
                or len({row.key for row in value.dependencies})>90):raise StoreUnavailable('complete typed active policy snapshot required')
        rows=merge(value.dependencies,(value.policy,))
        if value.policy not in value.dependencies:raise StoreUnavailable('active head must be condition-bound')
        data=value.policy.data
        if (data.get('status')!='approved' or data.get('mode')!='deterministic_policy' or data.get('environment')!=self.runtime.environment
                or data.get('artifact_sha256')!=self.runtime.artifact_sha256 or data.get('controls_sha256')!=self.runtime.controls_sha256
                or value.definition!=PolicyDraft.model_validate_json(canonical(data['definition']))
                or value.expires_at_ms>integer(data['expires_at_ms']) or self.access.now()>=value.expires_at_ms):
            raise StoreUnavailable('current bound policy definition and original expiry required')
        self._policy_provenance(value.policy)
        value.final_guard()
        if reader is not self.policy_reader or self.access.now()>=value.expires_at_ms:raise StoreConflict('policy reader or lifetime changed')
        return value

    @staticmethod
    def _policy_provenance(policy):
        return policy_provenance(policy.data)

    def policy_definition(self,data,rows):
        from proofpack.planner.candidates import PolicyDraft
        policy=next((row for row in rows if row.key==POLICY),None)
        if (policy is None or policy.revision!=data['policy_state_version']
                or data.get('policy_provenance')!=self._policy_provenance(policy)):
            raise StoreConflict('inspection policy provenance changed')
        spec=PolicyDraft.model_validate_json(canonical(policy.data['definition']))
        if record_digest({'algorithm':spec.algorithm,'priority':[x.value for x in spec.priority]})!=policy.data['behavior_sha256']:
            raise StoreUnavailable('intact qualified policy behavior required')
        return spec

    def guard_policy(self,data,rows):
        value=self._policy_snapshot();expected={row.key:row for row in rows}
        if any(expected.get(row.key)!=row for row in value.dependencies):raise StoreConflict('bound policy source authority changed')
        self.policy_definition(data,rows)
        if value.policy!=expected.get(POLICY):raise StoreConflict('active policy changed before use')
        return value

    def _invalidate_worker(self,station_id,epoch):
        if self.worker_invalidator is not None and epoch>0:
            try:self.worker_invalidator(station_id,epoch,self.runtime.instance_id)
            except (OSError,RuntimeError) as exc:raise StoreUnavailable('station fenced; worker cleanup requires review') from exc

    @staticmethod
    def _version(value):
        if type(value) is not int or value<1:raise ValueError('positive station version required')

    @staticmethod
    def _name(value):
        if not isinstance(value,str) or not 1<=len(value)<=80 or any(ord(c)<32 for c in value):raise ValueError('bounded station name required')

    @staticmethod
    def _reason(value):
        if not isinstance(value,str) or not 1<=len(value)<=120 or any(ord(c)<32 for c in value):raise ValueError('bounded operation reason required')

    def _runtime(self):
        row=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(row):raise Denied('current runtime incarnation required')
        return row

    def _calibration(self,profile_id):
        from proofpack.calibrations.dependencies import active_calibration
        return active_calibration(self.repository,self.access,self.runtime,profile_id)

    def _quota(self,ident):
        key=Key('state','station-quota#'+uuid(ident));row=self.repository.snapshot((key,))[key]
        window=self.access.now()//1000
        if row is not None and integer(row.data['second'])>window:raise StoreUnavailable('station quota clock moved backwards')
        count=0 if row is None or integer(row.data['second'])!=window else integer(row.data['count'])
        if count>=8:raise StationRateLimited('station control limit reached')
        return Write(key,None if row is None else row.revision,{'second':window,'count':count+1})

    def view(self,actor,station_id):
        actor=self.access._fresh(actor);key=station_key(station_id)
        row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('station unavailable')
        self.access._fresh(actor)
        return {'id':station_id,'name':row.data['name'],'calibration_profile_id':row.data['calibration_profile_id'],
            'state_version':row.revision,'epoch':integer(row.data['epoch']),
            'owner_session_id':row.data['owner_session_id'],'active_inspection_id':row.data['active_inspection_id'],
            'owned_by_current_session':row.data['owner_session_id']==actor.session.data['id'],
            'heartbeat_at_ms':None if row.data['heartbeat_at_ms'] is None else integer(row.data['heartbeat_at_ms'])}

    def list(self,actor,*,limit=20,cursor=None):
        actor=self.access._fresh(actor)
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded station page required')
        start=None if cursor is None else station_key(cursor).resource
        rows,last=self.repository.query(prefix='station#',limit=limit,start_resource=start)
        result=[self.view(actor,row.data['id']) for row in rows]
        self.access._fresh(actor)
        return {'stations':result,'next_cursor':None if last is None else last[len('station#'):]}

    def _result(self,actor,result,role):
        self.access._fresh(actor,role)
        return {**result,'current':self.view(actor,result['station_id'])}

    def _replay(self,actor,operation,key,body,role):
        idem,digest,prior=self.access._idempotency(actor,operation,key,body)
        return idem,digest,None if prior is None else self._result(actor,prior.data['result'],role)

    def enroll(self,actor,*,name,calibration_profile_id,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER);self._name(name)
        idem,digest,replay=self._replay(actor,'station-enroll',idempotency_key,{'name':name,'calibration_profile_id':calibration_profile_id},Role.OWNER)
        if replay is not None:return replay
        deps,cal,deadline=self._calibration(calibration_profile_id);runtime=self._runtime();ident=str(uuid4())
        data={'id':ident,'name':name,'calibration_profile_id':calibration_profile_id,'epoch':0,
            'owner_session_id':None,'active_inspection_id':None,'heartbeat_at_ms':None}
        result={'station_id':ident,'epoch':0,'state_version':1,'operation':'enrolled'}
        committed=self.access._record(actor,'station-enroll',idem,digest,result,(Write(station_key(ident),None,data),),
            merge(actor.rows,deps.values(),(runtime,)),event_details={'station_id':ident,'calibration_profile_id':calibration_profile_id})
        return self._result(actor,committed,Role.OWNER)

    def _allocation(self,row):
        return allocation_slots(row)

    def _close_work(self,station,*,disposition,reason):
        if disposition is not None and disposition not in DISPOSITIONS:raise ValueError('bounded human disposition required')
        ident=station.data['active_inspection_id']
        if ident is None:return (),()
        key=inspection_key(ident);rows=self.repository.snapshot((station.key,key,ALLOCATION))
        if rows[station.key]!=station:raise StoreConflict('station changed during reconciliation')
        work=rows[key];allocation=rows[ALLOCATION];slots=self._allocation(allocation)
        if (work is None or work.data['station_id']!=station.data['id'] or slots.get(ident)!=station.data['id']
                or work.data['state']=='CLOSED'):raise StoreUnavailable('station work/allocation inconsistent')
        selected=disposition or work.data.get('disposition')
        if work.data['state'] in {'ACTION_REQUIRED','REVIEW_REQUIRED'} and selected is None:raise StoreConflict('unresolved work needs human disposition')
        slots.pop(ident)
        closed={**work.data,'state':'CLOSED','deadline_tick_ns':0,'pending_sequence':None,'disposition':selected,
            'close_reason':reason,'closed_at_ms':self.access.now()}
        return (Write(key,work.revision,closed),Write(ALLOCATION,allocation.revision,{'slots':slots})),tuple(rows.values())

    def change(self,actor,*,station_id,expected_version,operation,idempotency_key,
               expected_epoch=None,expected_owner_session_id=None,takeover_ack=False,reason=None,
               disposition=None,name=None,calibration_profile_id=None):
        if operation not in {'acquire','release','heartbeat','profile'}:raise ValueError('known station operation required')
        role=Role.OWNER if operation=='profile' else Role.OPERATOR
        actor=self.access._fresh(actor,role);self._version(expected_version);key=station_key(station_id)
        if type(takeover_ack) is not bool:raise ValueError('explicit takeover acknowledgment required')
        body={'expected_version':expected_version,'expected_epoch':expected_epoch,'expected_owner_session_id':expected_owner_session_id,
            'takeover_ack':takeover_ack,'reason':reason,'disposition':disposition,'name':name,'calibration_profile_id':calibration_profile_id}
        idem,digest,replay=self._replay(actor,'station-'+operation+':'+station_id,idempotency_key,body,role)
        if replay is not None:return replay
        station=self.repository.snapshot((key,))[key]
        if station is None:raise ResourceUnavailable('station unavailable')
        if station.revision!=expected_version:raise StoreConflict('station version changed')
        data=station.data;checks=();writes=();sid=actor.session.data['id']
        if operation!='profile':
            if type(expected_epoch) is not int or expected_epoch<0:raise ValueError('station epoch required')
            if expected_epoch!=data['epoch']:raise StoreConflict('station fence changed')
        if operation=='acquire':
            if expected_owner_session_id is not None:uuid(expected_owner_session_id)
            if expected_owner_session_id!=data['owner_session_id']:raise StoreConflict('station owner changed')
            if data['owner_session_id'] is not None and data['owner_session_id']!=sid:
                if not takeover_ack:raise Denied('explicit takeover acknowledgment required')
                self._reason(reason)
            deps,cal,deadline=self._calibration(data['calibration_profile_id']);runtime=self._runtime()
            checks=merge(deps.values(),(runtime,))
            writes,old_checks=self._close_work(station,disposition=disposition,reason='station_takeover')
            checks=merge(checks,old_checks)
            updated={**data,'epoch':integer(data['epoch'])+1,'owner_session_id':sid,'active_inspection_id':None,'heartbeat_at_ms':self.access.now()}
        elif operation=='profile':
            self._name(name);deps,cal,deadline=self._calibration(calibration_profile_id)
            writes,old_checks=self._close_work(station,disposition=disposition,reason='profile_changed')
            checks=merge(deps.values(),old_checks)
            updated={**data,'name':name,'calibration_profile_id':calibration_profile_id,'epoch':integer(data['epoch'])+1,
                'owner_session_id':None,'active_inspection_id':None,'heartbeat_at_ms':None}
        else:
            if data['owner_session_id']!=sid:raise Denied('owning operator session required')
            if operation=='release':
                writes,checks=self._close_work(station,disposition=disposition,reason='station_released')
                updated={**data,'epoch':integer(data['epoch'])+1,'owner_session_id':None,'active_inspection_id':None,'heartbeat_at_ms':None}
            else:updated={**data,'heartbeat_at_ms':self.access.now()}
        quota=self._quota(station_id)
        result={'station_id':station_id,'epoch':integer(updated['epoch']),'state_version':station.revision+1,'operation':operation}
        committed=self.access._record(actor,'station-'+operation+':'+station_id,idem,digest,result,
            (*writes,Write(key,station.revision,updated),quota),merge(actor.rows,checks),required_role=role,
            event_details={'station_id':station_id,'epoch':integer(updated['epoch']),'closed_inspection_id':data['active_inspection_id'] if operation!='heartbeat' else None,
                'reason':reason,'disposition':disposition})
        if operation!='heartbeat':self._invalidate_worker(station_id,integer(data['epoch']))
        return self._result(actor,committed,role)

    def start(self,actor,*,station_id,expected_version,expected_epoch,recipe_id,kit_id,idempotency_key):
        actor=self.access._fresh(actor,Role.OPERATOR);self._version(expected_version);key=station_key(station_id)
        if type(expected_epoch) is not int or expected_epoch<0:raise ValueError('station epoch required')
        if not isinstance(kit_id,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',kit_id):raise ValueError('opaque kit identifier required')
        uuid(recipe_id)
        body={'station_id':station_id,'expected_version':expected_version,'expected_epoch':expected_epoch,'recipe_id':recipe_id,'kit_id':kit_id}
        idem,digest,replay=self._replay(actor,'inspection-start',idempotency_key,body,Role.OPERATOR)
        if replay is not None:return replay
        rows=self.repository.snapshot((key,ALLOCATION,POLICY));station=rows[key];policy=rows[POLICY]
        if station is None:raise ResourceUnavailable('station unavailable')
        if station.revision!=expected_version or station.data['epoch']!=expected_epoch:raise StoreConflict('station changed')
        if station.data['owner_session_id']!=actor.session.data['id']:raise Denied('owning operator session required')
        if station.data['active_inspection_id'] is not None:raise StoreConflict('station already has active work')
        slots=self._allocation(rows[ALLOCATION])
        if len(slots)>=2:raise StoreConflict('two active inspection slots are already reserved')
        runtime_rows=self.runtime.enabled_snapshot();recipe_rows,recipe,recipe_deadline=self.recipes.active_snapshot(recipe_id)
        cal_rows,cal,cal_deadline=self._calibration(station.data['calibration_profile_id'])
        qualified=self._policy_snapshot()
        if qualified.policy!=policy:raise StoreConflict('active policy changed during admission')
        if recipe.calibration_profile_id!=station.data['calibration_profile_id']:raise Denied('recipe requires this qualified station calibration')
        if (policy is None or policy.data.get('status')!='approved' or policy.data.get('mode')!='deterministic_policy'
                or policy.data.get('environment')!=self.runtime.environment or policy.data.get('artifact_sha256')!=self.runtime.artifact_sha256
                or policy.data.get('data_epoch')!=runtime_rows[DATA].data['epoch']):raise StoreUnavailable('approved deterministic policy required')
        deadline=min(recipe_deadline,cal_deadline,qualified.expires_at_ms,integer(policy.data['expires_at_ms']),
            integer(runtime_rows[RUNTIME].data['enable_expires_at_ms']),integer(actor.session.data['expires_at_ms']))
        if self.access.now()>=deadline:raise Denied('inspection admission dependencies expired')
        ticks=self.tick_ns()
        if type(ticks) is not int or ticks<0:raise StoreUnavailable('trusted monotonic clock required')
        ident=str(uuid4());slots[ident]=station_id;runtime=runtime_rows[RUNTIME].data
        inspection={'id':ident,'station_id':station_id,'station_epoch':expected_epoch,'kit_id':kit_id,'recipe_id':recipe_id,
            'recipe_revision':recipe.revision,'recipe_active_version':recipe_rows[recipe_active_key(recipe_id)].revision,
            'calibration_profile_id':recipe.calibration_profile_id,'calibration_state_version':cal.revision,
            'policy_state_version':policy.revision,'policy_provenance':self._policy_provenance(policy),
            'runtime_epoch':integer(runtime['runtime_epoch']),'runtime_instance_id':runtime['instance_id'],
            'artifact_sha256':self.runtime.artifact_sha256,
            'control_version':integer(runtime['control_version']),'data_epoch':integer(runtime_rows[DATA].data['epoch']),
            'originating_session_id':actor.session.data['id'],'originating_user_id':actor.member.data['id'],
            'originating_access_version':integer(actor.member.data['access_version']),'state':'CREATED','latest_input_sequence':0,
            'verified_sequence':0,'corrections':0,'created_at_ms':self.access.now(),'created_tick_ns':ticks,
            'admission_expires_at_ms':deadline,'deadline_tick_ns':0,'pending_sequence':None,'disposition':None}
        quota=self._quota(station_id)
        result={'station_id':station_id,'inspection_id':ident,'epoch':expected_epoch,'state_version':1,'operation':'created'}
        checks=merge(actor.rows,rows.values(),runtime_rows.values(),recipe_rows.values(),cal_rows.values(),qualified.dependencies)
        def final():
            self.guard_policy(inspection,checks)
            if self.access.now()>=deadline:raise Denied('inspection admission expired before commit')
        committed=self.access._record(actor,'inspection-start',idem,digest,result,
            (Write(inspection_key(ident),None,inspection),Write(key,station.revision,{**station.data,'active_inspection_id':ident}),
             Write(ALLOCATION,None if rows[ALLOCATION] is None else rows[ALLOCATION].revision,{'slots':slots}),quota),checks,
            required_role=Role.OPERATOR,before_commit=final,event_details={'inspection_id':ident,'station_id':station_id,'epoch':expected_epoch,
                'recipe_id':recipe_id,'recipe_revision':recipe.revision,'runtime_epoch':integer(runtime['runtime_epoch'])})
        return self._result(actor,committed,Role.OPERATOR)

    def close(self,actor,*,inspection_id,expected_version,expected_epoch,reason,disposition,idempotency_key):
        actor=self.access._fresh(actor,Role.OPERATOR);self._version(expected_version);self._reason(reason)
        key=inspection_key(inspection_id)
        body={'expected_version':expected_version,'expected_epoch':expected_epoch,'reason':reason,'disposition':disposition}
        idem,digest,replay=self._replay(actor,'inspection-close:'+inspection_id,idempotency_key,body,Role.OPERATOR)
        if replay is not None:return replay
        work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection unavailable')
        if work.revision!=expected_version:raise StoreConflict('inspection changed')
        stationid=work.data['station_id'];skey=station_key(stationid);station=self.repository.snapshot((skey,))[skey]
        if station is None or station.data['active_inspection_id']!=inspection_id:raise StoreConflict('inspection is not station current work')
        if type(expected_epoch) is not int or expected_epoch!=station.data['epoch']:raise StoreConflict('station fence changed')
        if station.data['owner_session_id']!=actor.session.data['id']:raise Denied('owning operator session required')
        writes,checks=self._close_work(station,disposition=disposition,reason='operator_closed')
        if not any(row.key==key and row==work for row in checks):raise StoreConflict('inspection changed during close')
        epoch=integer(station.data['epoch'])+1
        result={'station_id':stationid,'inspection_id':inspection_id,'epoch':epoch,'state_version':work.revision+1,'operation':'closed'}
        committed=self.access._record(actor,'inspection-close:'+inspection_id,idem,digest,result,
            (*writes,Write(skey,station.revision,{**station.data,'epoch':epoch,'active_inspection_id':None}),self._quota(stationid)),
            merge(actor.rows,checks),required_role=Role.OPERATOR,
            event_details={'station_id':stationid,'inspection_id':inspection_id,'epoch':epoch,'reason':reason,'disposition':disposition})
        self._invalidate_worker(stationid,integer(station.data['epoch']))
        return self._result(actor,committed,Role.OPERATOR)

    def _disposition_record(self,ident,decision_id,station_id):
        key=Key('state','human-disposition#'+ident+'#'+uuid(decision_id));row=self.repository.snapshot((key,))[key]
        if row is None:raise StoreUnavailable('human decision record unavailable')
        record=row.data
        try:
            unsigned={k:v for k,v in record.items() if k!='sha256'}
            if (row.revision!=1 or record_digest(unsigned)!=record['sha256'] or record['id']!=decision_id
                    or record['inspection_id']!=ident or record['station_id']!=station_id or record['machine_approval'] is not False
                    or record['independent_truth_verified'] is not False):raise ValueError('matching immutable human record required')
        except (KeyError,ValueError,TypeError) as exc:raise StoreUnavailable('human decision integrity unavailable') from exc
        return row

    def record_disposition(self,actor,*,inspection_id,expected_version,expected_epoch,disposition,reason,human_check_confirmed,idempotency_key):
        actor=self.access._fresh(actor,Role.OPERATOR);self._version(expected_version);self._reason(reason)
        if not reason.strip() or disposition not in DISPOSITIONS or type(human_check_confirmed) is not bool:
            raise ValueError('explicit bounded human decision required')
        if disposition=='human_accepted' and not human_check_confirmed:raise ValueError('complete manual check must be explicitly confirmed')
        ident=uuid(inspection_id);key=inspection_key(ident)
        body={'expected_version':expected_version,'expected_epoch':expected_epoch,'disposition':disposition,'reason':reason,'human_check_confirmed':human_check_confirmed}
        operation='inspection-disposition:'+ident
        idem,body_hash,replay=self.access._idempotency(actor,operation,idempotency_key,body)
        if replay is not None:
            self.access._fresh(actor,Role.OPERATOR);return replay.data['result']
        work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection unavailable')
        skey=station_key(work.data['station_id']);station=self.repository.snapshot((skey,))[skey]
        if (work.revision!=expected_version or work.data['state']=='CLOSED' or station is None
                or station.data['active_inspection_id']!=ident or type(expected_epoch) is not int
                or station.data['epoch']!=expected_epoch or work.data['station_epoch']!=expected_epoch
                or work.data.get('pending_sequence') is not None):
            # A duplicate may have committed after our original replay miss.
            # Recover only that exact historical result; authorize no new write.
            _,_,committed=self.access._idempotency(actor,operation,idempotency_key,body)
            if committed is not None:
                self.access._fresh(actor,Role.OPERATOR)
                return committed.data['result']
            raise StoreConflict('current nonpending station work required')
        if (station.data['owner_session_id']!=actor.session.data['id'] or work.data['originating_session_id']!=actor.session.data['id']
                or work.data['originating_user_id']!=actor.member.data['id']):raise Denied('originating owning operator session required')
        prior=None if work.data.get('latest_disposition_id') is None else self._disposition_record(ident,work.data['latest_disposition_id'],station.data['id'])
        decision_id=str(uuid4());record={'id':decision_id,'inspection_id':ident,'station_id':station.data['id'],'station_epoch':expected_epoch,
            'source_inspection_revision':expected_version,'source_state':work.data['state'],'source_observation_id':work.data.get('latest_observation_id'),
            'previous_id':work.data.get('latest_disposition_id'),'disposition':disposition,'reason':reason,'human_check_confirmed':human_check_confirmed,
            'actor_user_id':actor.member.data['id'],'actor_session_id':actor.session.data['id'],'at_ms':self.access.now(),
            'machine_approval':False,'independent_truth_verified':False}
        record['sha256']=record_digest(record)
        result={'id':decision_id,'inspection_id':ident,'inspection_state_version':work.revision+1,'decision':record}
        return self.access._record(actor,operation,idem,body_hash,result,
            (Write(Key('state','human-disposition#'+ident+'#'+decision_id),None,record),
             Write(key,work.revision,{**work.data,'disposition':disposition,'latest_disposition_id':decision_id}),self._quota(station.data['id'])),
            merge(actor.rows,(work,station,prior)),required_role=Role.OPERATOR,
            event_details={'inspection_id':ident,'decision_id':decision_id,'disposition':disposition,'sha256':record['sha256']})

    def latest_disposition(self,actor,inspection_id):
        actor=self.access._fresh(actor);ident=uuid(inspection_id);key=inspection_key(ident);work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection unavailable')
        def permitted(current):
            if Role.REVIEWER in current.principal.roles:return self.access._fresh(current,Role.REVIEWER)
            if Role.OPERATOR in current.principal.roles and work.data['originating_user_id']==current.member.data['id']:return self.access._fresh(current,Role.OPERATOR)
            if Role.OWNER in current.principal.roles:return self.access._fresh(current,Role.OWNER)
            raise Denied('scoped human decision access required')
        actor=permitted(actor);expected={row.key:row for row in (*actor.rows,work)};record=None
        decision_id=work.data.get('latest_disposition_id')
        if decision_id is not None:
            row=self._disposition_record(ident,decision_id,work.data['station_id']);record=row.data;expected[row.key]=row
        actor=permitted(actor)
        for row in actor.rows:
            if row.key in expected and expected[row.key]!=row:raise StoreConflict('human decision authority changed')
            expected[row.key]=row
        final=self.repository.snapshot(tuple(expected))
        if any(final[k]!=v for k,v in expected.items()):raise StoreConflict('human decision changed during read')
        permitted(actor)
        return {'inspection_id':ident,'inspection_state_version':work.revision,'decision':record,'current_disposition':work.data.get('disposition'),'historical':True,'machine_approval':False}

    def inspection_authority(self,actor,ident):
        """Complete consistent authority; downstream commits must condition-check all rows."""
        actor=self.access._fresh(actor);key=inspection_key(ident);work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection unavailable')
        if work.data['state']=='CLOSED':raise Denied('closed inspection has no capture authority')
        data=work.data;skey=station_key(data['station_id']);session=Key('state','session#'+uuid(data['originating_session_id']))
        member=user_key(data['originating_user_id'])
        rows=self.repository.snapshot((key,skey,session,member,POLICY))
        if rows[key]!=work:raise StoreConflict('inspection changed during read')
        runtime=self.runtime.enabled_snapshot();recipe_rows,recipe,recipe_deadline=self.recipes.active_snapshot(data['recipe_id'])
        calibration,cal,cal_deadline=self._calibration(data['calibration_profile_id'])
        qualified=self._policy_snapshot()
        if qualified.policy!=rows[POLICY]:raise StoreConflict('inspection policy changed during read')
        authority=merge(actor.rows,rows.values(),runtime.values(),recipe_rows.values(),calibration.values(),qualified.dependencies)
        self.guard_policy(data,authority)
        consistent=self.repository.snapshot(tuple(row.key for row in authority))
        if any(consistent[row.key]!=row for row in authority):raise StoreConflict('authority changed during final status snapshot')
        station,origin,grant,policy=(rows[k] for k in (skey,session,member,POLICY))
        if any(row is None for row in (station,origin,grant,policy)):raise Denied('authority missing')
        if (station.data['active_inspection_id']!=ident or station.data['epoch']!=data['station_epoch']
                or station.data['owner_session_id']!=data['originating_session_id']
                or origin.data['active'] is not True or self.access.now()>=origin.data['expires_at_ms']
                or grant.data['enabled'] is not True or grant.data['invited'] is not True or Role.OPERATOR.value not in grant.data['roles']
                or origin.data['user_id']!=grant.data['id'] or origin.data['issuer']!=grant.data['issuer']
                or origin.data['subject']!=grant.data['subject'] or origin.data['access_version']!=grant.data['access_version']
                or origin.data['session_epoch']!=grant.data['session_epoch']
                or grant.data['access_version']!=data['originating_access_version']
                or runtime[RUNTIME].data['runtime_epoch']!=data['runtime_epoch']
                or runtime[RUNTIME].data['instance_id']!=data['runtime_instance_id']
                or runtime[RUNTIME].data['control_version']!=data['control_version']
                or runtime[DATA].data['epoch']!=data['data_epoch']
                or recipe_rows[recipe_active_key(data['recipe_id'])].revision!=data['recipe_active_version']
                or cal.revision!=data['calibration_state_version'] or policy.revision!=data['policy_state_version']
                or self._allocation(runtime[ALLOCATION]).get(ident)!=data['station_id']
                or self.access.now()>=min(recipe_deadline,cal_deadline,integer(policy.data['expires_at_ms']),integer(data['admission_expires_at_ms']))):
            raise Denied('inspection authority changed')
        deadline=min(recipe_deadline,cal_deadline,qualified.expires_at_ms,integer(policy.data['expires_at_ms']),
            integer(data['admission_expires_at_ms']),integer(origin.data['expires_at_ms']),
            integer(runtime[RUNTIME].data['enable_expires_at_ms']))
        if self.access.now()>=deadline:raise Denied('inspection dependencies expired')
        return actor,work,authority,recipe,cal,deadline

    def inspection(self,actor,ident):
        actor=self.access._fresh(actor);key=inspection_key(ident);work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection unavailable')
        state=work.data['state'];reasons=[]
        if state!='CLOSED':
            try:
                actor,work,authority,recipe,cal,deadline=self.inspection_authority(actor,ident)
                state=work.data['state']
                if state=='PASSED_CURRENT':raise Denied('verification publication is not connected')
            except (Denied,StoreUnavailable,StoreConflict,ResourceUnavailable,KeyError,TypeError,ValueError):
                state='INVALIDATED';reasons=['AUTHORITY_OR_VERIFICATION_UNAVAILABLE']
        self.access._fresh(actor)
        return {'id':ident,'station_id':work.data['station_id'],'state_version':work.revision,'effective_state':state,
            'last_observed_at':None,'expires_at':None,'remaining_lease_ms':0,'reason_codes':reasons,
            'disposition':work.data.get('disposition')}
