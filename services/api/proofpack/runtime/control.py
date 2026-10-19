"""Durable runtime fencing and owner control. No public readiness attestation.

Receipt/review rows are trusted assurance-writer inputs, not request booleans.
Their production writers and deployment verification remain separate work.
"""
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import re
from uuid import UUID, uuid4

from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import RUNTIME,user_key
from proofpack.evidence.repository import DynamoRepository, Key, StoreConflict, StoreUnavailable, Write
from proofpack.runtime.startup_schema import restore_startup, bounded_integer

DATA = Key('state', 'data-authority')
ALLOCATION = Key('state', 'allocation')
CHECKS = frozenset({'opencv5', 'storage', 'dependencies', 'authorization', 'worker', 'recovery', 'release_gates'})


def uuid(value):
    try:
        if str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError('canonical UUID required') from exc
    return value


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value):
        raise ValueError('SHA-256 digest required')
    return value


def readiness_digest(data):
    # The schema contains strings, booleans and integer counts/times only;
    # DynamoDB Decimal is normalized explicitly, never via lossy float encoding.
    normalized = {**data, **{name: integer(data[name]) for name in
        ('runtime_epoch','control_version','data_epoch','issued_at_ms','expires_at_ms')}}
    return hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def integer(value):
    if (type(value) not in (int,Decimal)
            or (isinstance(value,Decimal) and (not value.is_finite() or value != value.to_integral_value()))
            or value < 0):
        raise ValueError('nonnegative integer required')
    return int(value)


def allocation_slots(row):
    try:
        if row is None:raise ValueError('allocation head missing')
        slots=row.data['slots']
        if not isinstance(slots,dict) or len(slots)>2 or len(set(slots.values()))!=len(slots):raise ValueError()
        for inspection,station in slots.items():uuid(inspection);uuid(station)
        return dict(slots)
    except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('inspection allocation inconsistent') from exc


@dataclass(frozen=True)
class RuntimeHandle:
    instance_id: str
    epoch: int
    artifact_sha256: str
    controls_sha256: str
    environment: str


@dataclass(frozen=True)
class StartupObservation:
    instance_id: str
    runtime_epoch: int
    control_version: int
    data_epoch: int
    startup_data_epoch: int
    runtime_state_version: int
    data_state_version: int
    marker_state_version: int
    observed_at_ms: int
    restore_generation_sha256: str
    read_only: bool = True
    authority: str = 'none'


class RuntimeControl:
    def __init__(self, access, *, instance_id: str, artifact_sha256: str, controls_sha256: str,environment: str):
        self.access = access
        self.repository = access.repository
        self.instance_id = uuid(instance_id)
        self.artifact_sha256 = sha(artifact_sha256)
        self.controls_sha256 = sha(controls_sha256)
        if environment not in {'test','synthetic_demo','beta'}:raise ValueError('explicit runtime environment required')
        self.environment=environment
        self.handle = None

    def _runtime(self, row):
        if row is None:
            raise StoreUnavailable('runtime startup required')
        try:
            if (integer(row.data['runtime_epoch']) < 0 or integer(row.data['control_version']) < 1
                    or type(row.data['inspection_enabled']) is not bool):
                raise ValueError()
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreUnavailable('runtime control is inconsistent') from exc
        return row

    def _restore_generation(self):
        if not isinstance(self.repository,DynamoRepository):
            return None
        fence=self.repository._check_data_fence()
        if fence is None:
            return None
        if fence.config.artifact_sha256!=self.artifact_sha256:
            raise StoreUnavailable('runtime artifact does not match protected release')
        return fence.generation_sha256()

    def _same_generation(self, captured):
        if self._restore_generation()!=captured:
            raise StoreUnavailable('original startup restore generation changed')

    def _startup_rows(self, generation):
        marker = Key('state', 'runtime-start#' + self.instance_id)
        rows = self.repository.snapshot((RUNTIME, marker, ALLOCATION, DATA))
        current = rows[RUNTIME]
        if current is not None:self._runtime(current)
        data=rows[DATA]
        if data is None and (rows[marker] is not None or (current is not None and integer(current.data['runtime_epoch'])>0)):
            raise StoreUnavailable('missing data authority requires reviewed recovery')
        try:
            if data is not None and (integer(data.data['epoch'])<1 or integer(data.data.get('changed_at_ms',0))>self.access.now()):
                raise ValueError('invalid data authority')
            if generation is not None and data is not None:
                if set(data.data)!={'epoch','changed_at_ms'}:
                    raise ValueError('closed DATA authority required')
                bounded_integer(data.data['epoch'],1)
        except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('invalid data authority') from exc
        allocation=rows[ALLOCATION]
        if generation is not None:
            if allocation is None and current is not None and integer(current.data['runtime_epoch'])>0:
                raise StoreUnavailable('missing allocation requires reviewed recovery')
            if allocation is not None:
                allocation_slots(allocation)
                if set(allocation.data)!={'slots'}:
                    raise StoreUnavailable('closed allocation authority required')
        return rows

    def _existing_startup(self, rows, generation):
        marker=Key('state','runtime-start#'+self.instance_id)
        current,data=rows[RUNTIME],rows[DATA]
        if rows[marker] is None:
            raise StoreUnavailable('original startup marker unavailable; no startup fallback')
        previous = rows[marker].data
        try:
            if rows[marker].revision!=1:
                raise ValueError('immutable original startup marker required')
            startup=restore_startup(previous)
            marker_epoch=bounded_integer(previous['runtime_epoch'],1)
        except (KeyError,TypeError,ValueError,ArithmeticError) as exc:
            raise StoreUnavailable('invalid original startup marker') from exc
        if (previous['artifact_sha256'] != self.artifact_sha256
                or previous['controls_sha256'] != self.controls_sha256 or previous['environment'] != self.environment):
            raise StoreConflict('runtime identity reused for another build')
        if (generation is None)!=(startup is None) or startup is not None and startup[0]!=generation:
            raise StoreConflict('startup marker belongs to another protection generation')
        if generation is not None:
            if (current is None or current.data.get('instance_id')!=self.instance_id
                    or integer(current.data['runtime_epoch'])!=marker_epoch
                    or any(current.data.get(name)!=previous[name] for name in ('artifact_sha256','controls_sha256','environment'))):
                raise StoreConflict('original startup is no longer the current incarnation')
            if integer(data.data['epoch'])<startup[2]:
                raise StoreUnavailable('DATA authority predates original startup')
        self._same_generation(generation)
        if generation is not None:
            try:
                started=integer(current.data['started_at_ms'])
                changed=integer(data.data['changed_at_ms'])
                if changed<started or self.access.now()<changed:
                    raise ValueError('DATA time does not cover original startup')
            except (KeyError,TypeError,ValueError,ArithmeticError) as exc:
                raise StoreUnavailable('original startup time unavailable') from exc
        return RuntimeHandle(self.instance_id, marker_epoch,
            self.artifact_sha256, self.controls_sha256,self.environment)

    def observe_startup(self):
        """Read only; never start, repair, enable or acquire a process handle."""
        generation=self._restore_generation()
        if generation is None:
            raise StoreUnavailable('protected startup observation required')
        rows=self._startup_rows(generation)
        self._existing_startup(rows,generation)
        current=self._startup_rows(generation)
        if current!=rows:
            raise StoreUnavailable('startup heads changed during observation')
        handle=self._existing_startup(current,generation)
        marker=current[Key('state','runtime-start#'+self.instance_id)]
        startup=restore_startup(marker.data)
        observed=self.access.now()
        if observed<integer(current[DATA].data['changed_at_ms']):
            raise StoreUnavailable('startup observation clock moved backwards')
        return StartupObservation(self.instance_id,handle.epoch,
            bounded_integer(current[RUNTIME].data['control_version'],1),
            bounded_integer(current[DATA].data['epoch'],1),startup[2],
            current[RUNTIME].revision,current[DATA].revision,marker.revision,
            observed,generation)

    def start(self) -> RuntimeHandle:
        """One process incarnation, no owner bootstrap or automatic enablement."""
        generation=self._restore_generation()
        rows=self._startup_rows(generation)
        marker=Key('state','runtime-start#'+self.instance_id)
        current,data,allocation=rows[RUNTIME],rows[DATA],rows[ALLOCATION]
        if rows[marker] is not None:
            self.handle=self._existing_startup(rows,generation)
            return self.handle
        if allocation is None and current is not None and integer(current.data['runtime_epoch'])>0:
            raise StoreUnavailable('missing allocation requires reviewed recovery')
        if allocation is not None:allocation_slots(allocation)
        epoch = 1 if current is None else int(current.data['runtime_epoch']) + 1
        control = 1 if current is None else int(current.data['control_version']) + 1
        previous_data=0 if data is None else integer(data.data['epoch'])
        next_data=previous_data+1
        if generation is not None:
            try:
                bounded_integer(epoch,1);bounded_integer(control,1);bounded_integer(next_data,1)
                if current is not None:bounded_integer(current.revision,1)
                if data is not None:bounded_integer(data.revision,1)
            except ValueError as exc:
                raise StoreUnavailable('startup authority counter exhausted') from exc
        state = {'runtime_epoch': epoch, 'control_version': control, 'inspection_enabled': False,
            'instance_id': self.instance_id, 'artifact_sha256': self.artifact_sha256,
            'controls_sha256': self.controls_sha256, 'started_at_ms': self.access.now(),
            'environment': self.environment,
            'enable_receipt_id': None, 'enable_expires_at_ms': None, 'reason': 'runtime_started'}
        event = Write(Key('events', 'runtime#' + str(uuid4())), None, {
            'kind': 'runtime_started', 'instance_id': self.instance_id, 'runtime_epoch': epoch,
            'control_version': control, 'at_ms': self.access.now()})
        allocation_writes=() if allocation is not None else (Write(ALLOCATION,None,{'slots':{}}),)
        data_writes=() if data is not None else (Write(DATA,None,{'epoch':1,'changed_at_ms':self.access.now()}),)
        marker_data={'runtime_epoch':epoch,'artifact_sha256':self.artifact_sha256,
            'controls_sha256':self.controls_sha256,'environment':self.environment}
        if generation is not None:
            marker_data.update(startup_schema_version=2,restore_generation_sha256=generation,
                previous_data_epoch=previous_data,data_epoch=next_data)
            data_writes=(Write(DATA,None if data is None else data.revision,
                {'epoch':next_data,'changed_at_ms':self.access.now()}),)
        writes,checks=self.access._prepare_linked('runtime_started',(Write(RUNTIME, None if current is None else current.revision, state),
            Write(marker, None, marker_data), event,*allocation_writes,*data_writes),
            tuple(row for row in (allocation,data if generation is None else None) if row is not None))
        if data is not None and integer(data.data.get('changed_at_ms',0))>self.access.now():
            raise StoreUnavailable('data authority changed relative to startup clock')
        finished=None
        if generation is not None:
            finished=self.access.now()
            if not state['started_at_ms']<=event.data['at_ms']<=data_writes[0].data['changed_at_ms']<=finished:
                raise StoreUnavailable('startup clock moved backwards before commit')
        self.repository.transact(writes,checks)
        self._same_generation(generation)
        if finished is not None and self.access.now()<finished:
            raise StoreUnavailable('startup clock moved backwards after commit')
        self.handle = RuntimeHandle(self.instance_id, epoch, self.artifact_sha256, self.controls_sha256,self.environment)
        return self.handle

    def matches(self, row):
        return (self.handle is not None and row is not None
            and row.data.get('instance_id') == self.handle.instance_id
            and row.data.get('runtime_epoch') == self.handle.epoch
            and row.data.get('artifact_sha256') == self.handle.artifact_sha256
            and row.data.get('controls_sha256') == self.handle.controls_sha256
            and row.data.get('environment') == self.handle.environment)

    def public(self, row, *, ready=False):
        self._runtime(row)
        data = row.data
        current = self.matches(row)
        enabled = (ready and current and data['inspection_enabled'] is True
            and data.get('enable_expires_at_ms') is not None
            and self.access.now() < data['enable_expires_at_ms'])
        return {'runtime_epoch': int(data['runtime_epoch']), 'control_version': int(data['control_version']),
            'state_version': row.revision, 'inspection_enabled': bool(enabled),
            'local_instance_current': current, 'artifact_sha256': data.get('artifact_sha256'),
            'controls_sha256': data.get('controls_sha256'), 'environment': data.get('environment'),
            'reason': data.get('reason', 'startup_required')}

    def read(self, actor):
        actor = self.access._fresh(actor, Role.OWNER)
        rows = self.repository.snapshot((RUNTIME, *[row.key for row in actor.rows]))
        if any(rows[row.key] != row for row in actor.rows):
            raise StoreConflict('access changed during control read')
        self.access._fresh(actor, Role.OWNER)
        runtime = self._runtime(rows[RUNTIME])
        ready = False
        if runtime.data['inspection_enabled'] is True and self.matches(runtime):
            try:
                self.enabled_snapshot(runtime)
                ready = True
            except (StoreUnavailable, StoreConflict, Denied):
                ready = False
        return self.public(runtime, ready=ready)

    def readiness(self,actor,receipt_id):
        actor=self.access._fresh(actor,Role.OWNER)
        row=self._runtime(self.repository.snapshot((RUNTIME,))[RUNTIME])
        if not self.matches(row):raise Denied('current runtime required')
        rows,receipt,review=self._receipt_rows(row,uuid(receipt_id),actor)
        expected={**rows,**{item.key:item for item in actor.rows}}
        final=self.repository.snapshot(tuple(expected))
        if any(final[key]!=item for key,item in expected.items()):raise StoreConflict('readiness authority changed')
        self.access._fresh(actor,Role.OWNER);remaining=integer(receipt.data['expires_at_ms'])-self.access.now()
        if remaining<=0:raise StoreUnavailable('readiness expired')
        return {'id':receipt_id,'eligible_for_enable':True,'control_version':integer(row.data['control_version']),
            'runtime_epoch':integer(row.data['runtime_epoch']),'environment':self.environment,
            'artifact_sha256':self.artifact_sha256,'controls_sha256':self.controls_sha256,
            'receipt_sha256':readiness_digest(receipt.data),'checks':dict(receipt.data['checks']),
            'remaining_validity_ms':remaining}

    def enabled_snapshot(self, runtime=None):
        """Current conservative admission gate. Caller must fence these rows at commit."""
        row = runtime or self._runtime(self.repository.snapshot((RUNTIME,))[RUNTIME])
        if not self.matches(row) or row.data.get('inspection_enabled') is not True:
            raise Denied('inspection admission is disabled')
        try:
            ident = uuid(row.data['enable_receipt_id'])
            receipt_key = Key('state', 'readiness#' + ident)
            review_key = Key('state', 'readiness-review#' + ident)
            owner_key = user_key(row.data['enable_owner_id'])
            rows = self.repository.snapshot((RUNTIME, DATA, receipt_key, review_key, owner_key,ALLOCATION))
            allocation_slots(rows[ALLOCATION])
            if rows[RUNTIME] != row:
                raise StoreConflict('runtime changed during admission')
            receipt, review, data, owner = (rows[key] for key in (receipt_key, review_key, DATA, owner_key))
            if any(item is None for item in (receipt, review, data, owner)):
                raise ValueError('missing readiness dependency')
            if (receipt.revision != 1 or review.revision != 1
                    or readiness_digest(receipt.data) != row.data['enable_receipt_sha256']
                    or review.data['receipt_sha256'] != row.data['enable_receipt_sha256']
                    or review.data['owner_user_id'] != owner.data['id']
                    or integer(review.data['owner_access_version']) != integer(owner.data['access_version'])
                    or review.data['approved'] is not True or owner.data['enabled'] is not True
                    or owner.data['invited'] is not True or Role.OWNER.value not in owner.data['roles']
                    or receipt.data['data_epoch'] != data.data['epoch']
                    or not integer(receipt.data['issued_at_ms']) <= self.access.now() < integer(receipt.data['expires_at_ms'])):
                raise ValueError('readiness dependency changed or expired')
            return rows
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreUnavailable('current readiness dependencies unavailable') from exc

    @staticmethod
    def _version(value):
        if type(value) is not int or value < 1:
            raise ValueError('positive control version required')

    def _replay(self, actor, operation, key, body):
        idem, body_hash, prior = self.access._idempotency(actor, operation, key, body)
        if prior is not None:
            return idem, body_hash, {**prior.data['result'], 'current': self.read(actor)}
        return idem, body_hash, None

    def disable(self, actor, *, expected_version: int, reason: str, idempotency_key: str):
        actor = self.access._fresh(actor, Role.OWNER)
        self._version(expected_version)
        if not isinstance(reason, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _.-]{0,119}', reason):
            raise ValueError('bounded non-sensitive control reason required')
        idem, body_hash, replay = self._replay(actor, 'runtime-disable', idempotency_key,
            {'expected_version': expected_version, 'reason': reason})
        if replay is not None:
            return replay
        row = self._runtime(self.repository.snapshot((RUNTIME,))[RUNTIME])
        if row.data['control_version'] != expected_version:
            raise StoreConflict('control version changed')
        data = {**row.data, 'control_version': expected_version + 1, 'inspection_enabled': False,
            'enable_receipt_id': None, 'enable_expires_at_ms': None,'enable_receipt_sha256':None,
            'enable_owner_id':None,'reason': reason}
        result = {'runtime_epoch': int(data['runtime_epoch']), 'control_version': expected_version + 1, 'operation': 'disabled'}
        committed = self.access._record(actor, 'runtime-disable', idem, body_hash, result,
            (Write(RUNTIME, row.revision, data),))
        return {**committed, 'current': self.read(actor)}

    def _receipt_rows(self, row, receipt_id, actor):
        receipt_key = Key('state', 'readiness#' + uuid(receipt_id))
        review_key = Key('state', 'readiness-review#' + receipt_id)
        rows = self.repository.snapshot((RUNTIME, DATA, receipt_key, review_key,ALLOCATION))
        allocation_slots(rows[ALLOCATION])
        if rows[RUNTIME] != row:
            raise StoreConflict('runtime changed during readiness review')
        receipt, review, data_head = rows[receipt_key], rows[review_key], rows[DATA]
        if receipt is None or review is None or data_head is None:
            raise StoreUnavailable('current reviewed readiness evidence required')
        try:
            data = receipt.data
            expected = {'deployment': self.repository.deployment, 'runtime_epoch': int(row.data['runtime_epoch']),
                'instance_id': row.data['instance_id'], 'artifact_sha256': self.artifact_sha256,
                'controls_sha256': self.controls_sha256, 'control_version': int(row.data['control_version']),
                'data_epoch': integer(data_head.data['epoch']),'environment':self.environment}
            if (any(data[name] != value for name, value in expected.items())
                    or receipt.revision != 1 or review.revision != 1
                    or not isinstance(data['checks'],dict) or set(data['checks']) != CHECKS
                    or any(value is not True for value in data['checks'].values())
                    or not integer(data['issued_at_ms']) <= self.access.now() < integer(data['expires_at_ms'])
                    or not 0 < integer(data['expires_at_ms'])-integer(data['issued_at_ms']) <= 60000
                    or review.data['receipt_sha256'] != readiness_digest(data)
                    or review.data['owner_user_id'] != actor.member.data['id']
                    or integer(review.data['owner_access_version']) != integer(actor.member.data['access_version'])
                    or review.data['approved'] is not True):
                raise ValueError('readiness or owner review mismatch')
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreUnavailable('current reviewed readiness evidence required') from exc
        return rows, receipt, review

    def enable(self, actor, *, expected_version: int, receipt_id: str, idempotency_key: str):
        actor = self.access._fresh(actor, Role.OWNER)
        self._version(expected_version)
        uuid(receipt_id)
        idem, body_hash, replay = self._replay(actor, 'runtime-enable', idempotency_key,
            {'expected_version': expected_version, 'receipt_id': receipt_id})
        if replay is not None:
            return replay
        row = self._runtime(self.repository.snapshot((RUNTIME,))[RUNTIME])
        if not self.matches(row):
            raise Denied('current runtime incarnation required')
        if row.data['control_version'] != expected_version:
            raise StoreConflict('control version changed')
        rows, receipt, review = self._receipt_rows(row, receipt_id, actor)
        data = {**row.data, 'control_version': expected_version + 1, 'inspection_enabled': True,
            'enable_receipt_id': receipt_id, 'enable_expires_at_ms': int(receipt.data['expires_at_ms']),
            'enable_receipt_sha256': readiness_digest(receipt.data), 'enable_owner_id': actor.member.data['id'],
            'reason': 'reviewed_enablement'}
        result = {'runtime_epoch': int(data['runtime_epoch']), 'control_version': expected_version + 1, 'operation': 'enabled'}
        # _record rechecks Owner/MFA immediately before the transaction and merges
        # duplicate runtime/actor conditions with their corresponding writes.
        committed = self.access._record(actor, 'runtime-enable', idem, body_hash, result,
            (Write(RUNTIME, row.revision, data),), tuple(rows.values()))
        return {**committed, 'current': self.read(actor)}
