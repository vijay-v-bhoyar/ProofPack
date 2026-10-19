"""Bounded support acknowledgment; never transfers capture or clears findings.

Domain phase only. Explicit installed API/inbox/UI/export/privacy integration is
separate acceptance work. Synthetic tests are not people accepting duties.
"""
from dataclasses import asdict, dataclass
import json
import re
import time
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import RUNTIME, ResourceUnavailable, user_key
from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.repository import Key, StoreConflict, StoreUnavailable, Write
from proofpack.runtime.control import DATA, integer, sha, uuid
from proofpack.stations.service import StationService, inspection_key, station_key, merge


class HandoffLimited(RuntimeError):
    def __init__(self,message,*,retry_after_seconds=None):
        super().__init__(message);self.retry_after_seconds=retry_after_seconds


INSPECTION_METADATA_MAX_MS=30*86400000


class HandoffRequest(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    recipient_user_id:StrictStr
    expected_epoch:StrictInt=Field(ge=0,le=2**63-1)
    reason_code:Literal['unresolved_inspection','capture_interrupted','support_needed']
    stop_acknowledged:StrictBool

    @field_validator('recipient_user_id')
    @classmethod
    def identifier(cls,value):return uuid(value)

    @model_validator(mode='after')
    def stop(self):
        if self.stop_acknowledged is not True:raise ValueError('explicit stop acknowledgment required')
        return self


class HandoffResponse(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    decision:Literal['accepted','declined']
    request_sha256:StrictStr
    expected_inspection_version:StrictInt=Field(ge=1,le=2**63-1)
    acknowledge_no_capture_transfer:StrictBool

    @field_validator('request_sha256')
    @classmethod
    def signature(cls,value):return sha(value)

    @model_validator(mode='after')
    def acknowledgment(self):
        if self.acknowledge_no_capture_transfer is not True:raise ValueError('explicit responsibility-only acknowledgment required')
        return self


class HandoffCancel(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    request_sha256:StrictStr

    @field_validator('request_sha256')
    @classmethod
    def signature(cls,value):return sha(value)


@dataclass(frozen=True)
class HandoffLimits:
    max_requests:int
    lifetime_ms:int
    reads_per_minute:int
    read_window_ms:int
    page_size:int
    metadata_retention_ms:int

    def __post_init__(self):
        for value,low,high in ((self.max_requests,1,16),(self.lifetime_ms,1000,3600000),
                (self.reads_per_minute,1,120),(self.read_window_ms,1,5000),(self.page_size,1,20),
                (self.metadata_retention_ms,1000,30*86400000)):
            if type(value) is not int or not low<=value<=high:raise ValueError('explicit bounded handoff limits required')
        if self.metadata_retention_ms<self.lifetime_ms:raise ValueError('metadata retention must cover pending request lifetime')

    @classmethod
    def from_controls(cls,controls):
        value=controls['handoffs']
        if set(value)!={'max_requests_per_inspection','lifetime_ms','reads_per_minute','read_window_ms','page_size'}:
            raise ValueError('complete handoff configuration required')
        days=controls['privacy']['metadata_retention_days']
        if type(days) is not int:raise ValueError('integer metadata retention required')
        return cls(value['max_requests_per_inspection'],value['lifetime_ms'],value['reads_per_minute'],
            value['read_window_ms'],value['page_size'],days*86400000)


def handoff_key(inspection_id,ident):return Key('state','inspection-handoff#'+uuid(inspection_id)+'#'+uuid(ident))
def inbox_key(recipient,ident):return Key('state','handoff-inbox#'+uuid(recipient)+'#'+uuid(ident))


class InspectionHandoffs:
    def __init__(self,stations,*,limits,tick_ns=None):
        if not isinstance(stations,StationService) or not isinstance(limits,HandoffLimits):raise ValueError('exact shared station service and handoff limits required')
        self.stations=stations;self.access=stations.access;self.repository=stations.repository;self.runtime=stations.runtime
        self.limits=limits;self.tick_ns=tick_ns or time.monotonic_ns
        self.configuration=digest({'limits':asdict(limits),'environment':self.runtime.environment,
            'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256})

    @staticmethod
    def _version(value):
        if type(value) is not int or not 1<=value<2**63:raise ValueError('exact bounded positive revision required')

    def _base(self,actor,inspection_id):
        actor=self.access._fresh(actor);key=inspection_key(inspection_id)
        work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection unavailable')
        created=integer(work.data['created_at_ms'])
        if not created<=self.access.now()<created+INSPECTION_METADATA_MAX_MS:raise ResourceUnavailable('inspection metadata retention expired')
        skey=station_key(work.data['station_id']);rows=self.repository.snapshot((skey,RUNTIME,DATA))
        station=rows[skey];runtime=rows[RUNTIME];data=rows[DATA]
        if station is None or data is None or not self.runtime.matches(runtime):raise StoreUnavailable('current handoff service and source context required')
        integer(data.data['epoch'])
        return actor,work,station,runtime,data,merge(actor.rows,(work,*rows.values()))

    def _row(self,inspection_id,ident):
        key=handoff_key(inspection_id,ident);row=self.repository.snapshot((key,))[key]
        return self.retained(row,inspection_id,ident,now=self.access.now)

    @staticmethod
    def retained(row,inspection_id,ident,*,now,include_expired=False):
        if type(include_expired) is not bool:raise ValueError('explicit internal expired-record mode required')
        if row is None:raise ResourceUnavailable('handoff unavailable')
        if row.key!=handoff_key(inspection_id,ident):raise StoreUnavailable('bound handoff record key required')
        try:
            request=row.data['request'];decision=row.data['decision'];status=row.data['status'];checked_at=now()
            if (row.data['id']!=ident or row.data['inspection_id']!=inspection_id or request['id']!=ident or request['inspection_id']!=inspection_id
                    or integer(request['schema_version'])!=1 or integer(row.data['schema_version'])!=1
                    or sha(row.data['request_sha256'])!=digest(request)
                    or status not in {'pending','accepted','declined','cancelled','superseded'}
                    or row.revision!=(1 if status=='pending' else 2)
                    or (status=='pending' and (decision is not None or row.data['decision_sha256'] is not None))
                    or (status!='pending' and (not isinstance(decision,dict) or decision['kind']!=status or sha(row.data['decision_sha256'])!=digest(decision)))
                    or not integer(request['created_at_ms'])<=checked_at
                    or (not include_expired and checked_at>=integer(row.data['metadata_expires_at_ms']))
                    or not integer(request['created_at_ms'])<integer(request['expires_at_ms'])<=integer(row.data['metadata_expires_at_ms'])
                    or integer(row.data['metadata_expires_at_ms'])!=integer(request['metadata_expires_at_ms'])
                    or not 0<integer(request['metadata_expires_at_ms'])-integer(request['created_at_ms'])<=INSPECTION_METADATA_MAX_MS
                    or integer(request['metadata_expires_at_ms'])>integer(request['parent_metadata_expires_at_ms'])
                    or integer(request['expires_at_ms'])-integer(request['created_at_ms'])>3600000
                    or integer(row.data['ttl_epoch_seconds'])!=(integer(request['metadata_expires_at_ms'])+999)//1000):
                raise ValueError('intact retained request/decision required')
            for name in ('sender_user_id','recipient_user_id','sender_session_id','station_id'):uuid(request[name])
            if request['sender_user_id']==request['recipient_user_id'] or not re.fullmatch(r'cookie#[a-f0-9]{64}',request['sender_cookie_resource']):raise ValueError()
            if request['sender_role'] not in {Role.OPERATOR.value,Role.REVIEWER.value}:raise ValueError()
            HandoffRequest(recipient_user_id=request['recipient_user_id'],expected_epoch=integer(request['station_epoch']),
                reason_code=request['reason_code'],stop_acknowledged=request['stop_acknowledged'])
            StationService._name(request['station_name'])
            if not isinstance(request['kit_reference'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',request['kit_reference']):raise ValueError('opaque kit reference required')
            sha(request['configuration'])
            for name in ('source_observation_id','previous_accepted_handoff_id'):
                if request[name] is not None:uuid(request[name])
            for name in ('sender_access_version','recipient_access_version','source_inspection_revision','post_request_inspection_revision','runtime_epoch'):
                if integer(request[name])<1:raise ValueError('positive source revision required')
            if request['post_request_inspection_revision']!=request['source_inspection_revision']+1:raise ValueError('exact stopped inspection revision required')
            if decision is not None:
                common={'kind','inspection_id','handoff_id','request_sha256','source_request_revision','actor_user_id','actor_session_id','actor_role','at_ms'}
                extra={'acknowledge_no_capture_transfer'} if status in {'accepted','declined'} else {'successor_id'} if status=='superseded' else set()
                if (set(decision)!=common|extra or decision['inspection_id']!=inspection_id or decision['handoff_id']!=ident
                        or decision['request_sha256']!=row.data['request_sha256'] or integer(decision['source_request_revision'])!=1
                        or not request['created_at_ms']<=integer(decision['at_ms'])<=now()):raise ValueError('outcome must bind the exact request')
                uuid(decision['actor_user_id']);uuid(decision['actor_session_id'])
                if status in {'accepted','declined'}:
                    if (decision['actor_user_id']!=request['recipient_user_id'] or decision['actor_role']!=Role.REVIEWER.value
                            or decision['acknowledge_no_capture_transfer'] is not True or decision['at_ms']>=request['expires_at_ms']):raise ValueError('recipient responsibility acknowledgment required')
                elif status=='cancelled':
                    if (decision['actor_user_id']!=request['sender_user_id'] or decision['actor_role']!=request['sender_role']):raise ValueError('requester cancellation required')
                elif uuid(decision['successor_id'])==ident or decision['actor_role'] not in {Role.OPERATOR.value,Role.REVIEWER.value}:raise ValueError('distinct explicit successor required')
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('intact retained handoff required') from exc
        return row

    def _decision(self,row,actor,role,kind,**extra):
        return {'kind':kind,'inspection_id':row.data['inspection_id'],'handoff_id':row.data['id'],
            'request_sha256':row.data['request_sha256'],'source_request_revision':row.revision,
            'actor_user_id':actor.member.data['id'],'actor_session_id':actor.session.data['id'],'actor_role':role.value,
            'at_ms':self.access.now(),**extra}

    @staticmethod
    def _station_current(work,station):
        return (work.data['state']!='CLOSED' and station.data['active_inspection_id']==work.data['id']
            and station.data['epoch']==work.data['station_epoch'])

    def _member(self,ident):
        row=self.repository.snapshot((user_key(ident),))[user_key(ident)]
        if row is None or row.data.get('enabled') is not True or row.data.get('invited') is not True or Role.REVIEWER.value not in row.data.get('roles',[]):
            raise Denied('explicit enabled invited reviewer recipient required')
        try:
            if (row.data['id']!=ident or integer(row.data['access_version'])<1 or not isinstance(row.data['roles'],list)
                    or any(value not in {role.value for role in Role} for value in row.data['roles'])):raise ValueError('intact explicit grant required')
        except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('current reviewer grant unavailable') from exc
        return row

    def _assigned(self,row,work,station,data):
        request=row.data['request'];member=self._member(request['recipient_user_id'])
        current=(row.data['status']=='accepted' and work.data.get('accepted_handoff_id')==row.data['id']
            and work.data.get('accepted_recipient_user_id')==request['recipient_user_id'] and self._station_current(work,station)
            and work.data['state']=='REVIEW_REQUIRED' and data.data['epoch']==request['data_epoch']
            and integer(member.data['access_version'])==request['recipient_access_version'] and request['configuration']==self.configuration)
        return current,(member,)

    def _request_role(self,actor,work,station,data):
        if not self._station_current(work,station):raise StoreConflict('current open station inspection required')
        if (work.data['originating_user_id']==actor.member.data['id'] and work.data['originating_session_id']==actor.session.data['id']
                and station.data['owner_session_id']==actor.session.data['id'] and Role.OPERATOR in actor.principal.roles):
            return self.access._fresh(actor,Role.OPERATOR),Role.OPERATOR,()
        if Role.REVIEWER not in actor.principal.roles or work.data.get('accepted_handoff_id') is None:raise Denied('originating owning operator or accepted reviewer required')
        previous=self._row(work.data['id'],work.data['accepted_handoff_id']);current,checks=self._assigned(previous,work,station,data)
        if not current or previous.data['request']['recipient_user_id']!=actor.member.data['id']:raise Denied('current accepted reviewer assignment required')
        return self.access._fresh(actor,Role.REVIEWER),Role.REVIEWER,merge(checks,(previous,))

    def _pending(self,row,work,station,runtime,data):
        request=row.data['request']
        if row.data['status']!='pending':return False,()
        if not (request['configuration']==self.configuration and self._station_current(work,station)
                and work.data['state']=='REVIEW_REQUIRED' and work.data.get('latest_handoff_id')==row.data['id']
                and work.revision==request['post_request_inspection_revision']
                and work.data.get('accepted_handoff_id')==request['previous_accepted_handoff_id']
                and work.data['station_epoch']==request['station_epoch'] and data.data['epoch']==request['data_epoch']
                and runtime.data['runtime_epoch']==request['runtime_epoch'] and runtime.data['instance_id']==request['runtime_instance_id']
                and request['created_at_ms']<=self.access.now()<request['expires_at_ms']):return False,()
        try:
            sender=self.access._resolve_key(Key('state',request['sender_cookie_resource']))
            sender=self.access._fresh(sender,Role(request['sender_role']));recipient=self._member(request['recipient_user_id'])
            if (sender.member.data['id']!=request['sender_user_id'] or sender.session.data['id']!=request['sender_session_id']
                    or integer(sender.member.data['access_version'])!=request['sender_access_version']
                    or integer(recipient.data['access_version'])!=request['recipient_access_version']):return False,()
            actor,role,extra=self._request_role(sender,work,station,data)
            if role.value!=request['sender_role']:return False,()
            return True,merge(sender.rows,(recipient,),extra)
        except Denied:return False,()

    def _permission(self,actor,work,row):
        request=row.data['request'];own=actor.member.data['id']
        if own==request['recipient_user_id']:return self.access._fresh(actor,Role.REVIEWER),Role.REVIEWER
        if own==request['sender_user_id']:
            role=Role(request['sender_role']);return self.access._fresh(actor,role),role
        if own==work.data['originating_user_id']:return self.access._fresh(actor,Role.OPERATOR),Role.OPERATOR
        raise Denied('requesting operator or designated reviewer scope required')

    def _start(self):
        value=self.tick_ns()
        if type(value) is not int or value<0:raise StoreUnavailable('trusted monotonic clock required')
        return value

    def _elapsed(self,started):
        now=self.tick_ns()
        if type(now) is not int or not 0<=now-started<self.limits.read_window_ms*1000000:
            raise StoreUnavailable('handoff operation/read window expired')
        return now-started

    def _time(self,started,deadline):
        self._elapsed(started)
        if self.access.now()>=deadline:raise StoreUnavailable('handoff operation/read window expired')

    def _read_quota(self,actor):
        key=Key('state','handoff-read-quota#'+actor.member.data['id']);row=self.repository.snapshot((key,))[key];window=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>window:raise StoreUnavailable('handoff read clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=window else integer(row.data['count'])
        if count<0:raise StoreUnavailable('handoff quota unavailable')
        if count>=self.limits.reads_per_minute:raise HandoffLimited('handoff read limit reached',retry_after_seconds=max(1,((window+1)*60000-self.access.now()+999)//1000))
        return Write(key,None if row is None else row.revision,{'minute':window,'count':count+1})

    def _deliver(self,actor,role,rows,deadline,build,*,started,details):
        self._elapsed(started)
        deadline=min(deadline,integer(actor.session.data['expires_at_ms']),self.access.now()+self.limits.read_window_ms)
        def gate():self._time(started,deadline)
        idem,body_hash,_=self.access._idempotency(actor,'handoff-read',str(uuid4()),{'deadline':deadline})
        self.access._record(actor,'handoff-read',idem,body_hash,{'historical':True},(self._read_quota(actor),),rows,
            required_role=role,before_commit=gate,event_details={'historical':True,**details})
        self.access._fresh(actor,role);gate()
        current=self.repository.snapshot(tuple(row.key for row in rows))
        if any(current[row.key]!=row for row in rows):raise StoreConflict('handoff context changed before delivery')
        result=build();self.access._fresh(actor,role);gate()
        remaining=min(deadline-self.access.now(),self.limits.read_window_ms-self._elapsed(started)//1000000)
        if remaining<=0:raise StoreUnavailable('handoff read expired before delivery')
        return json.loads(canonical({**result,'remaining_validity_ms':remaining}))

    def read(self,actor,inspection_id,ident):
        return self._read(actor,uuid(inspection_id),uuid(ident),self._start())

    def _read(self,actor,inspection_id,ident,started,*,context=None):
        actor,work,station,runtime,data,rows=self._base(actor,inspection_id) if context is None else context
        self._elapsed(started);row=self._row(inspection_id,ident);self._elapsed(started)
        actor,role=self._permission(actor,work,row);pending,checks=self._pending(row,work,station,runtime,data)
        assigned=False;assignment_checks=()
        if row.data['status']=='accepted':
            try:assigned,assignment_checks=self._assigned(row,work,station,data)
            except Denied:pass
        refs=merge(rows,actor.rows,(row,),checks,assignment_checks)
        deadline=integer(row.data['metadata_expires_at_ms'])
        if pending:deadline=min(deadline,integer(row.data['request']['expires_at_ms']))
        def result():
            request=row.data['request'];status=row.data['status']
            effective='expired' if status=='pending' and self.access.now()>=request['expires_at_ms'] else 'held' if status=='pending' and not pending else status
            return {'id':row.data['id'],'inspection_id':inspection_id,'state_version':row.revision,'inspection_state_version':work.revision,
                'request_sha256':row.data['request_sha256'],'recorded_status':status,'effective_status':effective,'pending_eligible':pending,
                'acknowledged':status=='accepted','current_assignment':assigned,'historical':True,'machine_approval':False,'capture_transferred':False,
                'request':{name:request[name] for name in ('sender_user_id','recipient_user_id','reason_code','station_id','station_epoch',
                    'station_name','kit_reference','source_inspection_revision','post_request_inspection_revision','source_observation_id','previous_accepted_handoff_id','created_at_ms','expires_at_ms')},
                'decision':None if row.data['decision'] is None else {name:row.data['decision'][name] for name in ('kind','actor_user_id','at_ms')}}
        return self._deliver(actor,role,refs,deadline,result,started=started,details={'inspection_id':inspection_id,'handoff_id':ident})

    def latest(self,actor,inspection_id):
        started=self._start();context=self._base(actor,uuid(inspection_id));self._elapsed(started)
        actor,work,station,runtime,data,rows=context;ident=work.data.get('latest_handoff_id')
        if ident is not None:return self._read(actor,inspection_id,uuid(ident),started,context=context)
        if work.data['originating_user_id']!=actor.member.data['id']:raise Denied('originating operator required')
        actor=self.access._fresh(actor,Role.OPERATOR)
        return self._deliver(actor,Role.OPERATOR,merge(rows,actor.rows),integer(actor.session.data['expires_at_ms']),
            lambda:{'inspection_id':inspection_id,'handoff':None,'historical':True,'machine_approval':False,'capture_transferred':False},
            started=started,details={'inspection_id':inspection_id})

    def request(self,actor,inspection_id,*,expected_version,request,idempotency_key):
        if not isinstance(request,HandoffRequest):raise ValueError('typed handoff request required')
        self._version(expected_version);inspection_id=uuid(inspection_id);actor=self.access._fresh(actor)
        body={'inspection_id':inspection_id,'expected_version':expected_version,**request.model_dump(mode='json')}
        operation='handoff-request:'+inspection_id;idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is not None:return self.read(actor,inspection_id,prior.data['result']['id'])
        actor,work,station,runtime,data,rows=self._base(actor,inspection_id)
        actor,role,assigned_checks=self._request_role(actor,work,station,data)
        if work.revision!=expected_version or work.data['station_epoch']!=request.expected_epoch or work.data.get('pending_sequence') is not None:
            raise StoreConflict('current nonpending inspection revision/epoch required')
        recipient=self._member(request.recipient_user_id)
        if recipient.data['id']==actor.member.data['id']:raise Denied('another explicitly granted reviewer must acknowledge')
        count=integer(work.data.get('handoff_count',0))
        if not 0<=count<self.limits.max_requests:raise HandoffLimited('inspection handoff request budget exhausted')
        previous=None;extra=()
        if work.data.get('latest_handoff_id') is not None:
            previous=self._row(inspection_id,work.data['latest_handoff_id']);eligible,extra=self._pending(previous,work,station,runtime,data)
            if previous.data['status']=='pending' and eligible:raise StoreConflict('resolve the existing pending handoff first')
        now=self.access.now();parent_expires=integer(work.data['created_at_ms'])+INSPECTION_METADATA_MAX_MS
        expires=min(now+self.limits.lifetime_ms,integer(actor.session.data['expires_at_ms']),parent_expires)
        if expires<=now:raise Denied('current sender session required')
        ident=str(uuid4());metadata_expires=min(now+self.limits.metadata_retention_ms,parent_expires)
        frozen={'schema_version':1,'id':ident,'inspection_id':inspection_id,'station_id':station.data['id'],'station_epoch':request.expected_epoch,
            'station_name':station.data['name'],'kit_reference':work.data['kit_id'],
            'source_inspection_revision':expected_version,'post_request_inspection_revision':expected_version+1,
            'source_observation_id':work.data.get('latest_observation_id'),'reason_code':request.reason_code,'stop_acknowledged':True,
            'sender_user_id':actor.member.data['id'],'sender_session_id':actor.session.data['id'],'sender_cookie_resource':actor.cookie.key.resource,
            'sender_role':role.value,'sender_access_version':integer(actor.member.data['access_version']),'recipient_user_id':recipient.data['id'],
            'recipient_access_version':integer(recipient.data['access_version']),'previous_accepted_handoff_id':work.data.get('accepted_handoff_id'),
            'runtime_epoch':integer(runtime.data['runtime_epoch']),'runtime_instance_id':runtime.data['instance_id'],
            'data_epoch':integer(data.data['epoch']),'created_at_ms':now,'expires_at_ms':expires,'metadata_expires_at_ms':metadata_expires,
            'parent_metadata_expires_at_ms':parent_expires,'configuration':self.configuration}
        signature=digest(frozen);record={'schema_version':1,'id':ident,'inspection_id':inspection_id,'request':frozen,'request_sha256':signature,
            'status':'pending','decision':None,'decision_sha256':None,'metadata_expires_at_ms':metadata_expires,'ttl_epoch_seconds':(metadata_expires+999)//1000}
        updated={**work.data,'state':'REVIEW_REQUIRED','deadline_tick_ns':0,'stable_ticks_ns':[],'current_action_id':None,
            'latest_handoff_id':ident,'handoff_count':count+1}
        writes=[Write(handoff_key(inspection_id,ident),None,record),Write(work.key,work.revision,updated),
            Write(inbox_key(recipient.data['id'],ident),None,{'id':ident,'inspection_id':inspection_id,'recipient_user_id':recipient.data['id'],
                'request_sha256':signature,'metadata_expires_at_ms':metadata_expires,'ttl_epoch_seconds':(metadata_expires+999)//1000}),self.stations._quota(station.data['id'])]
        if previous is not None and previous.data['status']=='pending':
            decision=self._decision(previous,actor,role,'superseded',successor_id=ident)
            writes.append(Write(previous.key,previous.revision,{**previous.data,'status':'superseded','decision':decision,'decision_sha256':digest(decision)}))
        def gate():
            if not now<=self.access.now()<expires:raise StoreUnavailable('handoff request expired before commit')
        result=self.access._record(actor,operation,idem,body_hash,{'id':ident},tuple(writes),merge(rows,actor.rows,assigned_checks,extra,(recipient,previous)),
            required_role=role,before_commit=gate,event_details={'inspection_id':inspection_id,'handoff_id':ident,'machine_approval':False})
        return self.read(actor,inspection_id,result['id'])

    def respond(self,actor,inspection_id,ident,*,expected_version,response,idempotency_key):
        if not isinstance(response,HandoffResponse):raise ValueError('typed responsibility acknowledgment required')
        self._version(expected_version);inspection_id=uuid(inspection_id);ident=uuid(ident);actor=self.access._fresh(actor,Role.REVIEWER)
        operation='handoff-response:'+ident;body={'inspection_id':inspection_id,'expected_version':expected_version,**response.model_dump(mode='json')}
        idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is not None:return self.read(actor,inspection_id,ident)
        actor,work,station,runtime,data,rows=self._base(actor,inspection_id);row=self._row(inspection_id,ident)
        if row.data['request']['recipient_user_id']!=actor.member.data['id']:raise Denied('designated reviewer required')
        eligible,extra=self._pending(row,work,station,runtime,data)
        if not eligible or row.revision!=expected_version or work.revision!=response.expected_inspection_version or row.data['request_sha256']!=response.request_sha256:
            raise StoreConflict('current exact pending responsibility request required')
        now=self.access.now();decision=self._decision(row,actor,Role.REVIEWER,response.decision,acknowledge_no_capture_transfer=True)
        writes=[Write(row.key,row.revision,{**row.data,'status':response.decision,'decision':decision,'decision_sha256':digest(decision)}),self.stations._quota(station.data['id'])]
        if response.decision=='accepted':
            writes.append(Write(work.key,work.revision,{**work.data,'accepted_handoff_id':ident,'accepted_recipient_user_id':actor.member.data['id']}))
        expires=integer(row.data['request']['expires_at_ms'])
        def gate():
            if not now<=self.access.now()<expires:raise StoreUnavailable('pending handoff expired before response commit')
        self.access._record(actor,operation,idem,body_hash,{'id':ident},tuple(writes),merge(rows,actor.rows,extra,(row,)),required_role=Role.REVIEWER,
            before_commit=gate,event_details={'inspection_id':inspection_id,'handoff_id':ident,'decision':response.decision,'machine_approval':False})
        return self.read(actor,inspection_id,ident)

    def cancel(self,actor,inspection_id,ident,*,expected_version,request,idempotency_key):
        if not isinstance(request,HandoffCancel):raise ValueError('typed request digest required')
        self._version(expected_version);inspection_id=uuid(inspection_id);ident=uuid(ident)
        actor,work,station,runtime,data,rows=self._base(actor,inspection_id);row=self._row(inspection_id,ident);frozen=row.data['request']
        role=Role(frozen['sender_role']);actor=self.access._fresh(actor,role)
        if actor.member.data['id']!=frozen['sender_user_id']:raise Denied('original requester with current explicit role required for cancellation')
        operation='handoff-cancel:'+ident;body={'inspection_id':inspection_id,'expected_version':expected_version,**request.model_dump(mode='json')}
        idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is not None:return self.read(actor,inspection_id,ident)
        if row.revision!=expected_version or row.data['status']!='pending' or row.data['request_sha256']!=request.request_sha256:raise StoreConflict('exact pending request required for cancellation')
        decision=self._decision(row,actor,role,'cancelled')
        self.access._record(actor,operation,idem,body_hash,{'id':ident},
            (Write(row.key,row.revision,{**row.data,'status':'cancelled','decision':decision,'decision_sha256':digest(decision)}),self.stations._quota(station.data['id'])),
            merge(rows,actor.rows,(row,)),required_role=role,event_details={'inspection_id':inspection_id,'handoff_id':ident,'machine_approval':False})
        return self.read(actor,inspection_id,ident)

    def inbox(self,actor,*,cursor=None):
        started=self._start();actor=self.access._fresh(actor,Role.REVIEWER);prefix='handoff-inbox#'+actor.member.data['id']+'#'
        start=None if cursor is None else prefix+uuid(cursor)
        page,last=self.repository.query(prefix=prefix,limit=self.limits.page_size,start_resource=start);self._elapsed(started)
        runtime=self.stations._runtime();refs=merge(actor.rows,(runtime,),page);items=[];deadline=integer(actor.session.data['expires_at_ms'])
        for index in page:
            self._elapsed(started)
            if index.data.get('recipient_user_id')!=actor.member.data['id'] or index.key!=inbox_key(actor.member.data['id'],index.data['id']):raise StoreUnavailable('intact recipient inbox reference required')
            if self.access.now()>=integer(index.data['metadata_expires_at_ms']):continue
            row=self._row(uuid(index.data['inspection_id']),uuid(index.data['id']));request=row.data['request']
            if request['recipient_user_id']!=actor.member.data['id'] or index.data['request_sha256']!=row.data['request_sha256']:raise StoreUnavailable('bound recipient inbox source required')
            refs=merge(refs,(row,));deadline=min(deadline,integer(row.data['metadata_expires_at_ms']))
            items.append({'id':row.data['id'],'inspection_id':row.data['inspection_id'],'state_version':row.revision,
                'request_sha256':row.data['request_sha256'],'recorded_status':row.data['status'],'reason_code':request['reason_code'],
                'station_name':request['station_name'],'kit_reference':request['kit_reference'],
                'created_at_ms':request['created_at_ms'],'expires_at_ms':request['expires_at_ms'],'historical':True,'machine_approval':False})
        return self._deliver(actor,Role.REVIEWER,refs,deadline,lambda:{'requests':json.loads(canonical(items)),
            'next_cursor':None if last is None else last.rsplit('#',1)[-1],'historical':True,'machine_approval':False,
            'scope':'recorded recipient references only; read current request details before any response'},started=started,
            details={'inbox':True,'handoff_ids':[item['id'] for item in items]})
