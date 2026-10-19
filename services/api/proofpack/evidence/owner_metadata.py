"""Authenticated owner request/hold lifecycle; no HTTP bypass or cleanup grant."""
from contextlib import contextmanager
from dataclasses import dataclass,asdict
import re
from threading import Lock
from types import MethodType
from uuid import uuid4

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import AccessService,Actor,RUNTIME
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.inspection_scope import inspection_scope,scope_sha256
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionHeld,GATE,REGISTRY
from proofpack.evidence.repository import Key,Row,Write,StoreConflict,StoreUnavailable
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode,MissingResourceBindings,InvalidResourceBindings
from proofpack.runtime.control import DATA,integer,uuid,sha
from proofpack.runtime.ownership import ResourceOwner

from proofpack.evidence.metadata_request_contract import (
    BASE, CANCEL, MAXIMUM, request_key, _version, _operation, validate_request)


class OwnerMetadataBusy(RuntimeError):pass
class OwnerMetadataLimited(RuntimeError):pass


@dataclass(frozen=True)
class OwnerMetadataLimits:
    max_inspections:int
    writes_per_minute:int
    reads_per_minute:int
    operation_timeout_ms:int

    def __post_init__(self):
        if any(type(v) is not int or not 1<=v<=high for v,high in (
                (self.max_inspections,64),(self.writes_per_minute,100),(self.reads_per_minute,1000),(self.operation_timeout_ms,20000))):
            raise ValueError('explicit bounded owner request/read/write limits required')


class OwnerMetadataRequests:
    def __init__(self,access,admission,resource_owner,*,limits,tick_ns):
        if (type(access) is not AccessService or type(admission) is not PersistentAdmission
                or type(resource_owner) is not ResourceOwner or type(limits) is not OwnerMetadataLimits
                or admission.runtime.access is not access or admission.repository is not access.repository
                or not (admission.clock_ms is access.clock_ms or
                    (type(admission.clock_ms) is MethodType and admission.clock_ms.__self__ is access
                     and admission.clock_ms.__func__ is AccessService.now)) or not callable(tick_ns)):
            raise ValueError('exact shared owner/admission/clock/resource dependencies required')
        self.access=access;self.admission=admission;self.resource_owner=resource_owner;self.limits=limits
        self.repository=access.repository;self.runtime=admission.runtime
        self.tick_ns=tick_ns;self._deadline=None;self._last_tick=-1
        self._initial=(access,admission,resource_owner,limits,self.repository,self.runtime,access.config,access.clock_ms,tick_ns)
        self._admission_limits=admission.limits
        self._admission_clock=admission.clock_ms
        self._runtime_configuration=(self.runtime.artifact_sha256,self.runtime.controls_sha256,self.runtime.environment,admission._configuration)
        self._configuration=digest({'schema_version':1,'limits':asdict(limits),'admission':admission._configuration,
            'artifact':self.runtime.artifact_sha256,'controls':self.runtime.controls_sha256})
        self._lock=Lock();self.release_pending=False;self._pending_ticket=None
        self._read_minute=-1;self._read_count=0

    def _check(self):
        current=(self.access,self.admission,self.resource_owner,self.limits,self.repository,self.runtime,self.access.config,self.access.clock_ms,self.tick_ns)
        if (any(a is not b for a,b in zip(current,self._initial))
                or self.access.repository is not self.repository or self.admission.repository is not self.repository
                or self.runtime.access is not self.access or self.admission.clock_ms is not self._admission_clock
                or self.admission.limits is not self._admission_limits
                or (self.runtime.artifact_sha256,self.runtime.controls_sha256,self.runtime.environment,self.admission._configuration)!=self._runtime_configuration):
            raise AdmissionHeld('owner maintenance configuration changed')
        self.admission._check_target()
        now=self.tick_ns()
        if (self._deadline is None or type(now) is not int or not 0<=self._last_tick<=now<self._deadline):
            raise AdmissionHeld('original owner operation deadline or monotonic clock invalid')
        self._last_tick=now

    @contextmanager
    def _work(self):
        if self.release_pending:raise AdmissionHeld('owner maintenance completion remains unconfirmed')
        if not self._lock.acquire(blocking=False):raise OwnerMetadataBusy('owner maintenance request busy')
        owner=self._initial[2];ticket=None;uncertain=False
        try:
            if self.release_pending:raise AdmissionHeld('owner maintenance completion remains unconfirmed')
            ticket=owner.acquire();now=self.tick_ns()
            if type(now) is not int or not max(0,self._last_tick)<=now<2**63-1-self.limits.operation_timeout_ms*1_000_000:
                raise AdmissionHeld('bounded original owner operation clock required')
            self._last_tick=now;self._deadline=now+self.limits.operation_timeout_ms*1_000_000
            self._check();yield
        except BaseException as error:
            if not isinstance(error,Exception):
                uncertain=True;self.release_pending=True;self._pending_ticket=ticket
            raise
        finally:
            try:
                if ticket is not None and not uncertain:
                    try:owner.release(ticket)
                    except BaseException:
                        self.release_pending=True;self._pending_ticket=ticket;raise
            finally:self._deadline=None;self._lock.release()

    def _fresh(self,actor):
        self._check()
        if type(actor) is not Actor:raise Denied('current owner session required')
        actor=self.access._fresh(actor,Role.OWNER);self._check();return actor

    def _now(self):
        self._check();now=self.admission._now()
        if now>MAXIMUM:raise AdmissionHeld('safe owner timestamp required')
        return now

    def _read_allowance(self):
        minute=self._now()//60000
        if minute<self._read_minute:raise AdmissionHeld('owner read clock moved backwards')
        if minute!=self._read_minute:self._read_minute=minute;self._read_count=0
        if self._read_count>=self.limits.reads_per_minute:raise OwnerMetadataLimited('owner read allowance exhausted')
        self._read_count+=1

    def _quota(self,actor):
        self._check()
        key=Key('state','metadata-owner-quota#'+actor.scope);row=self.repository.snapshot((key,))[key];minute=self._now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise AdmissionHeld('owner write clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        if count>=self.limits.writes_per_minute:raise OwnerMetadataLimited('owner write allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def _heads(self):
        self._check()
        gate,registry,runtime,value,active=self.admission._read()
        active=self.admission._business_active(active,runtime,value)
        data=self.repository.snapshot((DATA,))[DATA]
        if (type(data) is not Row or integer(data.data['epoch'])<1
                or integer(data.data.get('changed_at_ms',0))>self._now()):
            raise AdmissionHeld('current data authority required')
        self.runtime._runtime(runtime)
        try:
            for number in (gate.revision,registry.revision,runtime.revision,data.revision,value['epoch'],
                    integer(runtime.data['runtime_epoch']),integer(runtime.data['control_version']),integer(data.data['epoch'])):
                _version(number)
        except ValueError:raise AdmissionHeld('safe owner control versions required') from None
        return gate,registry,runtime,value,active,data

    def _checked_delivery(self,actor,rows):
        self._fresh(actor);expected={r.key:r for r in (*actor.rows,*rows)}
        current=self.repository.snapshot(tuple(expected))
        if any(current[k]!=r for k,r in expected.items()):raise StoreConflict('owner maintenance view changed')
        self._now()
        if self._fresh(actor).rows!=actor.rows:raise StoreConflict('owner maintenance authority changed before delivery')
        self.admission._checkpoint_control_context()
        self._check()

    def context(self,actor):
        with self._work():
            actor=self._fresh(actor);self._read_allowance();gate,registry,runtime,value,active,data=self._heads()
            self._checked_delivery(actor,(gate,registry,runtime,data))
            return {'gate_version':gate.revision,'gate_phase':value['phase'],'gate_epoch':value['epoch'],
                'control_version':integer(runtime.data['control_version']),'inspection_enabled':runtime.data['inspection_enabled'],
                'active_count':len(active),'foreign_active':self.admission._foreign(active,runtime),
                'max_inspections':self.limits.max_inspections,'can_create':value['phase']=='OPEN' and runtime.data['inspection_enabled'] is False,
                'can_confirm_cleanup':False,'erasure_complete':False}

    def _request(self,row):
        self._check()
        return validate_request(row,deployment=self.repository.deployment,
            configuration_sha256=self._configuration,max_inspections=self.limits.max_inspections,
            now=self._now,snapshot=self.repository.snapshot)

    def _view(self,actor,ident):
        key=request_key(ident);row=self.repository.snapshot((key,))[key];value,history=self._request(row)
        gate,registry,runtime,current,active,data=self._heads()
        matching=current['phase']=='HELD' and current.get('request_id')==ident and current.get('scope_sha256')==value['scope_sha256'] and current['epoch']==integer(value['gate_epoch'])
        disabled=runtime.data['inspection_enabled'] is False
        self._checked_delivery(actor,(row,*history,gate,registry,runtime,data))
        return {'id':ident,'state_version':row.revision,'status':value['status'],'scope_sha256':value['scope_sha256'],
            'inspection_ids':list(value['scope']['inspection_ids']),'selector_policy':value['scope']['selector_policy'],
            'created_at_ms':integer(value['created_at_ms']),'original_owner_session':value['owner_user_id']==actor.member.data['id'] and value['owner_session_id']==actor.session.data['id'],
            'current_hold':bool(matching),'gate_version':gate.revision,'gate_epoch':current['epoch'],'gate_phase':current['phase'],
            'control_version':integer(runtime.data['control_version']),'inspection_enabled':runtime.data['inspection_enabled'],
            'active_count':len(active),'foreign_active':self.admission._foreign(active,runtime),
            'drain_status':'not_current' if not matching else ('blocked_runtime' if not disabled else ('waiting' if active else 'empty')),
            'can_cancel':value['status']=='held' and matching and disabled and not active,
            'can_confirm_cleanup':False,'erasure_complete':False,'request_fulfilled':False}

    def get(self,actor,ident):
        uuid(ident)
        with self._work():
            actor=self._fresh(actor);self._read_allowance();return self._view(actor,ident)

    def recover_current(self,actor):
        """Read only the durable current hold; never reconcile an unknown write."""
        with self._work():
            actor=self._fresh(actor);self._read_allowance()
            gate,registry,runtime,value,active,data=self._heads()
            result=None
            if value['phase']=='OPEN':
                self._checked_delivery(actor,(gate,registry,runtime,data))
                status='open'
            else:
                ident=uuid(value['request_id'])
                result=self._view(actor,ident)
                if (result['id']!=ident or result['status']!='held' or result['current_hold'] is not True
                        or result['scope_sha256']!=value['scope_sha256'] or result['gate_version']!=gate.revision
                        or result['gate_epoch']!=value['epoch']):
                    raise StoreConflict('current held metadata request changed')
                status='held'
            self._check()
            return {'status':status,'request':result,'unknown_writes_reconciled':False,
                'inspection_resumption_authorized':False,'can_confirm_cleanup':False,
                'erasure_complete':False,'request_fulfilled':False}

    def _result(self,actor,operation,body_hash,*,replayed,kind):
        self._check()
        if replayed:self._read_allowance()
        row=self.repository.snapshot((operation,))[operation]
        if row is None or row.data.get('body_hash')!=body_hash:raise StoreUnavailable('original owner operation confirmation unavailable')
        try:
            result=row.data['result']
            if type(result) is not dict or set(result)!={'id','scope_sha256','request_sha256'}:raise ValueError()
            record=self.repository.snapshot((request_key(result['id']),))[request_key(result['id'])]
            value,_=self._request(record)
            field='creation_operation_resource' if kind=='held' else 'cancellation_operation_resource'
            if value.get(field)!=operation.resource or result['request_sha256']!=value['original_request_sha256']:raise ValueError()
        except (KeyError,TypeError,ValueError,AttributeError):raise AdmissionHeld('original owner operation provenance changed') from None
        view=self._view(actor,uuid(result['id']))
        if view['scope_sha256']!=result['scope_sha256']:raise AdmissionHeld('original owner operation scope changed')
        return {**view,'replayed':replayed,'original_operation':kind}

    def _prior_result(self,actor,operation,body_hash,kind):
        self._check();row=self.repository.snapshot((operation,))[operation]
        if row is None:return None
        if row.data.get('body_hash')!=body_hash:raise StoreConflict('original owner operation input changed')
        return self._result(actor,operation,body_hash,replayed=True,kind=kind)

    def _commit(self,actor,kind,operation,body_hash,result,writes,checks):
        self._check()
        def final():
            self._check();self._fresh(actor);self._now();self.admission._checkpoint_control_context()
        try:return self.access._record(actor,kind,operation,body_hash,result,writes,checks,before_commit=final)
        except StoreUnavailable:
            row=self.repository.snapshot((operation,))[operation]
            if row is None or row.data.get('body_hash')!=body_hash:raise
            return row.data['result']

    def create(self,actor,*,inspection_ids,expected_gate_version,expected_control_version,interruption_acknowledged,idempotency_key):
        _version(expected_gate_version);_version(expected_control_version)
        if interruption_acknowledged is not True:raise Denied('explicit maintenance interruption acknowledgment required')
        scope=inspection_scope(self.repository.deployment,inspection_ids,max_inspections=self.limits.max_inspections)
        body={'inspection_ids':list(inspection_ids),'expected_gate_version':expected_gate_version,
            'expected_control_version':expected_control_version,'interruption_acknowledged':True}
        with self._work():
            actor=self._fresh(actor);operation,body_hash,replay=self.access._idempotency(actor,'owner-metadata-create',idempotency_key,body)
            if replay is not None:return self._result(actor,operation,body_hash,replayed=True,kind='held')
            gate,registry,runtime,current,active,data=self._heads();now=self._now()
            if (current['phase']!='OPEN' or gate.revision!=expected_gate_version
                    or integer(runtime.data['control_version'])!=expected_control_version or runtime.data['inspection_enabled'] is not False):
                prior=self._prior_result(actor,operation,body_hash,'held')
                if prior is not None:return prior
                raise StoreConflict('current open gate and disabled runtime review required')
            if now<current['created_at_ms'] or any(a['issued_at_ms']>now for a in active.values()):raise AdmissionHeld('original maintenance clock required')
            for number in (gate.revision+1,current['epoch']+1,expected_control_version+1,integer(data.data['epoch'])+1):_version(number)
            keys=tuple(Key('state','inspection#'+ident) for ident in inspection_ids);selected=self.repository.snapshot(keys)
            if any(type(selected[k]) is not Row or selected[k].data.get('id')!=ident or selected[k].data.get('state')!='CLOSED' for k,ident in zip(keys,inspection_ids)):
                raise AdmissionHeld('existing closed inspection selection required')
            ident=str(uuid4());scope_hash=scope_sha256(scope)
            value={'schema_version':1,'id':ident,'kind':'inspection_metadata_request','status':'held',
                'scope':{**asdict(scope),'inspection_ids':list(inspection_ids)},'scope_sha256':scope_hash,
                'creator_scope':actor.scope,'owner_user_id':actor.member.data['id'],'owner_session_id':actor.session.data['id'],
                'owner_access_version':integer(actor.member.data['access_version']),'initial_control_version':expected_control_version,
                'initial_runtime_epoch':integer(runtime.data['runtime_epoch']),'initial_runtime_id':runtime.data['instance_id'],
                'initial_gate_revision':gate.revision,'gate_epoch':current['epoch'],'created_at_ms':now,
                'configuration_sha256':self._configuration,'creation_operation_resource':operation.resource}
            value['original_request_sha256']=_payload_sha256(value)
            held={**current,'phase':'HELD','request_id':ident,'scope_sha256':scope_hash,'held_at_ms':now}
            result={'id':ident,'scope_sha256':scope_hash,'request_sha256':value['original_request_sha256']}
            committed=self._commit(actor,'owner-metadata-create',operation,body_hash,result,
                (Write(request_key(ident),None,value),Write(GATE,gate.revision,held),self._quota(actor)),
                (registry,runtime,data,*selected.values()))
            return self._result(actor,operation,body_hash,replayed=committed['id']!=ident,kind='held')

    def cancel(self,actor,*,ident,confirmed_scope_sha256,expected_request_version,expected_gate_version,expected_control_version,no_erasure_acknowledged,idempotency_key):
        uuid(ident);sha(confirmed_scope_sha256)
        for version in (expected_request_version,expected_gate_version,expected_control_version):_version(version)
        if no_erasure_acknowledged is not True:raise Denied('explicit no-erasure cancellation acknowledgment required')
        body={'id':ident,'confirmed_scope_sha256':confirmed_scope_sha256,'expected_request_version':expected_request_version,
            'expected_gate_version':expected_gate_version,'expected_control_version':expected_control_version,'no_erasure_acknowledged':True}
        with self._work():
            actor=self._fresh(actor);operation,body_hash,replay=self.access._idempotency(actor,'owner-metadata-cancel',idempotency_key,body)
            if replay is not None:return self._result(actor,operation,body_hash,replayed=True,kind='cancelled')
            key=request_key(ident);row=self.repository.snapshot((key,))[key];value,history=self._request(row)
            gate,registry,runtime,current,active,data=self._heads();now=self._now()
            if (value['status']!='held' or row.revision!=expected_request_version or value['scope_sha256']!=confirmed_scope_sha256
                    or gate.revision!=expected_gate_version or current['phase']!='HELD' or current.get('request_id')!=ident
                    or current.get('scope_sha256')!=confirmed_scope_sha256 or current['epoch']!=integer(value['gate_epoch'])
                    or integer(runtime.data['control_version'])!=expected_control_version or runtime.data['inspection_enabled'] is not False):
                prior=self._prior_result(actor,operation,body_hash,'cancelled')
                if prior is not None:return prior
                raise StoreConflict('exact current held request review required')
            proof=self.admission.drained(request_id=ident,scope_sha256=confirmed_scope_sha256)
            original=self.admission.assert_drained(proof)
            if original!=(gate,registry,runtime):raise StoreConflict('original maintenance drain changed')
            epoch=current['epoch']+1;control=expected_control_version+1
            _version(epoch);_version(control);_version(integer(data.data['epoch'])+1)
            cancelled={**value,'status':'cancelled','cancelled_at_ms':now,'cancelled_by_user_id':actor.member.data['id'],
                'cancelled_gate_epoch':epoch,'cancelled_control_version':control,'cancellation_operation_resource':operation.resource}
            reopened={k:v for k,v in current.items() if k not in {'request_id','scope_sha256','held_at_ms'}}
            reopened.update(phase='OPEN',epoch=epoch,created_at_ms=now)
            stopped={**runtime.data,'control_version':control,'inspection_enabled':False,'enable_receipt_id':None,
                'enable_expires_at_ms':None,'enable_receipt_sha256':None,'enable_owner_id':None,'reason':'metadata_request_cancelled'}
            result={'id':ident,'scope_sha256':confirmed_scope_sha256,'request_sha256':value['original_request_sha256']}
            self._commit(actor,'owner-metadata-cancel',operation,body_hash,result,
                (Write(key,row.revision,cancelled),Write(GATE,gate.revision,reopened),
                 Write(REGISTRY,registry.revision,{'schema_version':1,'gate_epoch':epoch,'active':registry.data['active']}),Write(RUNTIME,runtime.revision,stopped),
                 Write(DATA,data.revision,{**data.data,'epoch':integer(data.data['epoch'])+1,'changed_at_ms':now}),self._quota(actor)),
                (*history,))
            return self._result(actor,operation,body_hash,replayed=False,kind='cancelled')
