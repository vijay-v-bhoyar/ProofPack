"""Private durable admission bookkeeping; not owner authority or an integrated barrier."""
from dataclasses import asdict, dataclass
from contextlib import contextmanager
from contextvars import ContextVar
from decimal import Decimal
import hashlib
import json
from threading import Lock
from uuid import UUID

from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key, Row, Write, StoreConflict, StoreUnavailable
from proofpack.evidence.resource_bindings import _payload_sha256


GATE = Key('state', 'metadata-maintenance-gate')
REGISTRY = Key('state', 'metadata-admission-registry')
MAXIMUM = 2**63-1
_CURRENT = ContextVar('proofpack_metadata_admission', default=None)
_CONTROL = ContextVar('proofpack_metadata_control', default=None)


class AdmissionHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class AdmissionLimits:
    max_active: int
    max_lease_ms: int

    def __post_init__(self):
        if (type(self.max_active) is not int or not 1 <= self.max_active <= 64
                or type(self.max_lease_ms) is not int or not 1 <= self.max_lease_ms <= 300000):
            raise ValueError('explicit supported admission limits required')


@dataclass(frozen=True)
class AdmissionConfiguration:
    max_active: int
    max_lease_ms: int
    http_lease_ms: int
    worker_lease_ms: int
    attempts: int
    enrollment_sha256: str

    def __post_init__(self):
        AdmissionLimits(self.max_active, self.max_lease_ms)
        if (any(type(value) is not int or not 1 <= value <= self.max_lease_ms
                for value in (self.http_lease_ms, self.worker_lease_ms))
                or type(self.attempts) is not int or not 1 <= self.attempts <= 3):
            raise ValueError('explicit admission execution bounds required')
        _sha(self.enrollment_sha256)


@dataclass(frozen=True)
class EnrollmentState:
    phase: str
    active_count: int
    foreign_active: bool


@dataclass(frozen=True, repr=False)
class AdmissionIntent:
    work_id: str
    kind: str
    instance_id: str
    runtime_epoch: int
    gate_epoch: int
    issued_at_ms: int
    expires_at_ms: int


@dataclass(frozen=True)
class AdmissionReference:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class DrainProof:
    request_id: str
    scope_sha256: str
    epoch: int
    gate: AdmissionReference
    registry: AdmissionReference
    runtime: AdmissionReference


def _n(value, *, positive=False):
    if (type(value) not in (int, Decimal) or (type(value) is Decimal and
            (not value.is_finite() or value != value.to_integral_value()))
            or not (1 if positive else 0) <= value <= MAXIMUM):
        raise ValueError()
    return int(value)


def _uuid(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError()
    return value


def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError()
    return value


def _target(repository):
    if (type(repository.deployment) is not str or not 1 <= len(repository.deployment) <= 256
            or type(repository.tables) is not dict or set(repository.tables) != {'state', 'events'}
            or any(type(v) is not str or not v for v in repository.tables.values())):
        raise AdmissionHeld('supported admission target required')
    return repository.deployment, repository.tables['state'], repository.tables['events']


def _ref(row):
    if not isinstance(row, Row) or not isinstance(row.key, Key) or type(row.data) is not dict:
        raise ValueError()
    return AdmissionReference(row.key, _n(row.revision, positive=True), _payload_sha256(row.data))


class PersistentAdmission:
    def __init__(self, runtime, *, limits, clock_ms):
        if type(limits) is not AdmissionLimits or not callable(clock_ms):
            raise ValueError('explicit admission bounds and trusted clock required')
        self.runtime = runtime; self.repository = runtime.repository
        self.limits = limits; self.clock_ms = clock_ms
        self._instance = _uuid(runtime.instance_id)
        self._client = self.repository.client; self._target = _target(self.repository)
        self._clock_lock = Lock(); self._last_ms = -1
        self._configuration = hashlib.sha256(json.dumps({'schema_version': 1,
            'target': self._target, 'limits': asdict(limits)}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def _check_target(self):
        if (self.runtime.repository is not self.repository or self.repository.client is not self._client
                or _target(self.repository) != self._target or self.runtime.instance_id != self._instance):
            raise AdmissionHeld('admission target changed')

    def _now(self):
        self._check_target()
        with self._clock_lock:
            value = self.clock_ms()
            self._check_target()
            if type(value) is not int or not 0 <= value <= MAXIMUM or value < self._last_ms:
                raise AdmissionHeld('admission clock invalid')
            self._last_ms = value
            return value

    def _snapshot(self):
        self._check_target()
        try:
            rows = self.repository.snapshot((GATE, REGISTRY, RUNTIME))
        except StoreUnavailable:
            raise AdmissionHeld('admission state unavailable') from None
        self._check_target()
        if type(rows) is not dict or set(rows) != {GATE, REGISTRY, RUNTIME}:
            raise AdmissionHeld('complete admission state required')
        return rows

    def _body(self, value):
        fields = set(AdmissionIntent.__dataclass_fields__)
        if (type(value) is not dict or set(value) != fields or type(value['kind']) is not str
                or value['kind'] not in {'http', 'worker', 'control', 'public_asset'}):
            raise ValueError()
        result = AdmissionIntent(_uuid(value['work_id']), value['kind'], _uuid(value['instance_id']),
            _n(value['runtime_epoch'], positive=True), _n(value['gate_epoch'], positive=True),
            _n(value['issued_at_ms']), _n(value['expires_at_ms']))
        if not 1 <= result.expires_at_ms-result.issued_at_ms <= self.limits.max_lease_ms:
            raise ValueError()
        return asdict(result)

    def _owned(self, intent, *, control=False):
        try:
            if (type(intent) is not AdmissionIntent or intent.instance_id != self._instance
                    or intent.kind not in ({'control'} if control else {'http','worker'})):
                raise ValueError()
            return self._body(asdict(intent))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise AdmissionHeld('exact original admission intent required') from None

    def _read(self, *, current=True):
        rows = self._snapshot()
        try:
            gate, registry, runtime = (rows[k] for k in (GATE, REGISTRY, RUNTIME))
            for key, row in rows.items():
                if row is None or row.key != key: raise ValueError()
                _ref(row)
            raw = gate.data
            required = {'schema_version', 'epoch', 'phase', 'configuration_sha256', 'enrollment_sha256', 'created_at_ms'}
            if raw.get('phase') == 'HELD': required |= {'request_id', 'scope_sha256', 'held_at_ms'}
            if (set(raw) != required or _n(raw['schema_version'], positive=True) != 1
                    or raw['phase'] not in {'OPEN', 'HELD'} or raw['configuration_sha256'] != self._configuration):
                raise ValueError()
            value = {**raw, 'epoch': _n(raw['epoch'], positive=True), 'created_at_ms': _n(raw['created_at_ms'])}
            _sha(value['configuration_sha256']); _sha(value['enrollment_sha256'])
            if value['phase'] == 'HELD':
                _uuid(value['request_id']); _sha(value['scope_sha256'])
                value['held_at_ms'] = _n(value['held_at_ms'])
                if value['held_at_ms'] < value['created_at_ms']: raise ValueError()
            reg = registry.data
            if (set(reg) != {'schema_version', 'gate_epoch', 'active'}
                    or _n(reg['schema_version'], positive=True) != 1 or _n(reg['gate_epoch'], positive=True) != value['epoch']
                    or type(reg['active']) is not dict or len(reg['active']) > self.limits.max_active):
                raise ValueError()
            active = {}
            for key, item in reg['active'].items():
                body = self._body(item)
                older_control = body['kind'] == 'control' and body['gate_epoch'] < value['epoch']
                if (_uuid(key) != body['work_id'] or body['gate_epoch'] > value['epoch']
                        or (not older_control and (body['gate_epoch'] != value['epoch']
                            or body['issued_at_ms'] < value['created_at_ms']))):
                    raise ValueError()
                active[key] = body
            if sum(body['kind'] == 'control' for body in active.values()) > 1: raise ValueError()
            _uuid(runtime.data['instance_id']); _n(runtime.data['runtime_epoch'], positive=True)
            if type(runtime.data['inspection_enabled']) is not bool:
                raise ValueError()
            if current and (runtime.data['instance_id'] != self._instance or not self.runtime.matches(runtime)):
                raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError, ArithmeticError):
            raise AdmissionHeld('intact supported admission state required') from None
        return gate, registry, runtime, value, active

    def initialize(self, enrollment_sha256):
        _sha(enrollment_sha256)
        rows = self._snapshot()
        if rows[GATE] is not None or rows[REGISTRY] is not None:
            gate, _, _, value, _ = self._read()
            if value['enrollment_sha256'] != enrollment_sha256:
                raise AdmissionHeld('original admission enrollment required')
            return _ref(gate)  # In particular, HELD stays HELD on restart.
        runtime = rows[RUNTIME]
        if (runtime is None or not self.runtime.matches(runtime) or runtime.data.get('inspection_enabled') is not False):
            raise AdmissionHeld('current disabled runtime required for enrollment')
        now = self._now()
        gate = {'schema_version': 1, 'epoch': 1, 'phase': 'OPEN', 'configuration_sha256': self._configuration,
                'enrollment_sha256': enrollment_sha256, 'created_at_ms': now}
        try:
            self.repository.transact((Write(GATE, None, gate), Write(REGISTRY, None,
                {'schema_version': 1, 'gate_epoch': 1, 'active': {}})), (runtime,))
        except (StoreConflict, StoreUnavailable):
            pass  # Reconcile both original records; never replace an uncertain enrollment.
        existing, _, _, value, _ = self._read()
        if value['enrollment_sha256'] != enrollment_sha256:
            raise AdmissionHeld('original admission enrollment required')
        return _ref(existing)

    def _foreign(self, active, runtime):
        epoch = _n(runtime.data['runtime_epoch'], positive=True)
        return any(body['instance_id'] != self._instance or body['runtime_epoch'] != epoch
                   for body in active.values())

    def require_enrollment(self, enrollment_sha256):
        """Read-only startup admission; missing state is never a fresh-install signal."""
        _sha(enrollment_sha256)
        _, _, runtime, gate, active = self._read()
        if gate['enrollment_sha256'] != enrollment_sha256:
            raise AdmissionHeld('original admission enrollment required')
        return EnrollmentState(gate['phase'], len(active), self._foreign(active, runtime))

    def prepare(self, *, work_id, kind, lease_ms):
        _uuid(work_id)
        if type(kind) is not str or kind not in {'http', 'worker'} or type(lease_ms) is not int or not 1 <= lease_ms <= self.limits.max_lease_ms:
            raise ValueError('bounded admission intent required')
        _, _, runtime, gate, active = self._read()
        if self._foreign(active, runtime):
            raise AdmissionHeld('previous runtime completion remains unconfirmed')
        now = self._now()
        if gate['phase'] != 'OPEN' or now < gate['created_at_ms'] or now+lease_ms > MAXIMUM:
            raise AdmissionHeld('new metadata work held')
        return AdmissionIntent(work_id, kind, self._instance, _n(runtime.data['runtime_epoch'], positive=True),
                               gate['epoch'], now, now+lease_ms)

    def _eligible(self, intent, gate, runtime):
        now = self._now()
        if (gate['phase'] != 'OPEN' or intent.gate_epoch != gate['epoch']
                or intent.runtime_epoch != _n(runtime.data['runtime_epoch'], positive=True)
                or not intent.issued_at_ms <= now < intent.expires_at_ms):
            raise AdmissionHeld('original admission held or expired')

    def _eligible_control(self, intent, gate, runtime):
        now = self._now()
        if (intent.gate_epoch > gate['epoch']
                or intent.runtime_epoch != _n(runtime.data['runtime_epoch'], positive=True)
                or not intent.issued_at_ms <= now < intent.expires_at_ms):
            raise AdmissionHeld('original control admission held or expired')

    def _owned_public_asset(self, intent):
        try:
            if type(intent) is not AdmissionIntent or intent.instance_id != self._instance or intent.kind != 'public_asset':
                raise ValueError()
            return self._body(asdict(intent))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise AdmissionHeld('exact original public asset intent required') from None

    def _eligible_public_asset(self, intent, gate, runtime):
        now = self._now()
        if (intent.gate_epoch != gate['epoch'] or intent.runtime_epoch != _n(runtime.data['runtime_epoch'], positive=True)
                or not intent.issued_at_ms <= now < intent.expires_at_ms):
            raise AdmissionHeld('original public asset admission held or expired')

    def _prepare_public_asset(self, *, work_id, lease_ms):
        """Trusted frozen-byte transport only; grants no metadata/business authority."""
        _uuid(work_id)
        if type(lease_ms) is not int or not 1 <= lease_ms <= self.limits.max_lease_ms:
            raise ValueError('bounded public asset admission required')
        _, _, runtime, gate, _ = self._read()
        now = self._now()
        if now < gate['created_at_ms'] or now+lease_ms > MAXIMUM:
            raise AdmissionHeld('public asset admission clock invalid')
        return AdmissionIntent(work_id, 'public_asset', self._instance,
            _n(runtime.data['runtime_epoch'], positive=True), gate['epoch'], now, now+lease_ms)

    def _admit_public_asset(self, intent):
        body = self._owned_public_asset(intent)
        gate_row, registry, runtime, gate, active = self._read()
        self._eligible_public_asset(intent, gate, runtime)
        if intent.work_id in active:
            if active[intent.work_id] != body: raise AdmissionHeld('public asset admission intent changed')
            return intent
        if len(active) >= self.limits.max_active: raise AdmissionHeld('public asset admission capacity exhausted')
        active[intent.work_id] = body
        try:
            self.repository.transact((Write(REGISTRY, registry.revision,
                {'schema_version': 1, 'gate_epoch': gate['epoch'], 'active': active}),), (gate_row, runtime))
        except (StoreConflict, StoreUnavailable) as error:
            _, _, current, value, found = self._read()
            self._eligible_public_asset(intent, value, current)
            if found.get(intent.work_id) == body: return intent
            if isinstance(error, StoreConflict): raise StoreConflict('public asset admission changed; reconcile original intent') from None
            raise AdmissionHeld('public asset admission confirmation unavailable') from None
        return intent

    def _checkpoint_public_asset(self, intent):
        body = self._owned_public_asset(intent)
        _, _, runtime, gate, active = self._read()
        self._eligible_public_asset(intent, gate, runtime)
        if active.get(intent.work_id) != body:
            raise AdmissionHeld('active original public asset admission required')

    def _release_public_asset(self, intent):
        return self._release(intent, control=False, public_asset=True)

    def _prepare_control(self, *, work_id, lease_ms):
        """Trusted transport entry; control registration conveys no business authority."""
        _uuid(work_id)
        if type(lease_ms) is not int or not 1 <= lease_ms <= self.limits.max_lease_ms:
            raise ValueError('bounded control admission required')
        _, _, runtime, gate, active = self._read()
        if any(body['kind'] == 'control' for body in active.values()):
            raise AdmissionHeld('previous control completion remains unconfirmed')
        now = self._now()
        if now < gate['created_at_ms'] or now+lease_ms > MAXIMUM:
            raise AdmissionHeld('control admission clock invalid')
        return AdmissionIntent(work_id, 'control', self._instance,
            _n(runtime.data['runtime_epoch'], positive=True), gate['epoch'], now, now+lease_ms)

    def _admit_control(self, intent):
        body = self._owned(intent, control=True)
        gate_row, registry, runtime, gate, active = self._read()
        self._eligible_control(intent, gate, runtime)
        if intent.work_id in active:
            if active[intent.work_id] != body: raise AdmissionHeld('control admission intent changed')
            return intent
        if (intent.gate_epoch != gate['epoch'] or len(active) >= self.limits.max_active
                or any(item['kind'] == 'control' for item in active.values())):
            raise AdmissionHeld('control admission held or capacity exhausted')
        active[intent.work_id] = body
        try:
            self.repository.transact((Write(REGISTRY, registry.revision,
                {'schema_version': 1, 'gate_epoch': gate['epoch'], 'active': active}),), (gate_row, runtime))
        except (StoreConflict, StoreUnavailable) as error:
            _, _, current, value, found = self._read()
            self._eligible_control(intent, value, current)
            if found.get(intent.work_id) == body: return intent
            if isinstance(error, StoreConflict): raise StoreConflict('control admission changed; reconcile original intent') from None
            raise AdmissionHeld('control admission confirmation unavailable') from None
        return intent

    def _checkpoint_control(self, intent):
        body = self._owned(intent, control=True)
        _, _, runtime, gate, active = self._read()
        self._eligible_control(intent, gate, runtime)
        if active.get(intent.work_id) != body:
            raise AdmissionHeld('active original control admission required')

    def _business_active(self, active, runtime, gate):
        """Only the exact durably admitted server context can exclude its own work."""
        current = _CONTROL.get()
        if current is None: return active
        service, intent = current
        if service is not self: raise AdmissionHeld('original control service required')
        body = self._owned(intent, control=True)
        self._eligible_control(intent, gate, runtime)
        if active.get(intent.work_id) != body:
            raise AdmissionHeld('original registered control context required')
        return {key: item for key, item in active.items() if key != intent.work_id}

    def _checkpoint_control_context(self):
        current = _CONTROL.get()
        if current is None: return
        if current[0] is not self: raise AdmissionHeld('original control service required')
        self._checkpoint_control(current[1])

    def admit(self, intent):
        body = self._owned(intent)
        gate_row, registry, runtime, gate, active = self._read()
        self._eligible(intent, gate, runtime)
        if self._foreign(active, runtime):
            raise AdmissionHeld('previous runtime completion remains unconfirmed')
        if intent.work_id in active:
            if active[intent.work_id] != body: raise AdmissionHeld('admission intent changed')
            return intent
        if len(active) >= self.limits.max_active: raise AdmissionHeld('admission capacity exhausted')
        active[intent.work_id] = body
        try:
            self.repository.transact((Write(REGISTRY, registry.revision,
                {'schema_version': 1, 'gate_epoch': gate['epoch'], 'active': active}),), (gate_row, runtime))
        except (StoreConflict, StoreUnavailable) as error:
            _, _, current, value, found = self._read()
            self._eligible(intent, value, current)
            if self._foreign(found, current):
                raise AdmissionHeld('previous runtime completion remains unconfirmed')
            if found.get(intent.work_id) == body: return intent
            if isinstance(error, StoreConflict): raise StoreConflict('admission changed; reconcile original intent') from None
            raise AdmissionHeld('admission confirmation unavailable') from None
        return intent

    def checkpoint(self, intent):
        body = self._owned(intent)
        _, _, runtime, gate, active = self._read()
        self._eligible(intent, gate, runtime)
        if active.get(intent.work_id) != body:
            raise AdmissionHeld('active original admission required')

    def release(self, intent):
        return self._release(intent, control=False)

    def _release_control(self, intent):
        return self._release(intent, control=True)

    def _release(self, intent, *, control, public_asset=False):
        body = self._owned_public_asset(intent) if public_asset else self._owned(intent, control=control)
        gate_row, registry, _, gate, active = self._read(current=False)
        if intent.work_id not in active: return False  # Absence is not a business-task completion claim.
        if active[intent.work_id] != body: raise AdmissionHeld('exact original admission release required')
        del active[intent.work_id]
        try:
            self.repository.transact((Write(REGISTRY, registry.revision,
                {'schema_version': 1, 'gate_epoch': gate['epoch'], 'active': active}),), (gate_row,))
        except (StoreConflict, StoreUnavailable) as error:
            _, _, _, _, found = self._read(current=False)
            if intent.work_id not in found: return False
            if isinstance(error, StoreConflict): raise StoreConflict('admission release changed; retain original intent') from None
            raise AdmissionHeld('admission release confirmation unavailable') from None
        return True

    def hold(self, *, request_id, scope_sha256):
        _uuid(request_id); _sha(scope_sha256)
        gate_row, _, runtime, gate, active = self._read()
        if runtime.data['inspection_enabled'] is not False:
            raise AdmissionHeld('inspections must be disabled before metadata hold')
        if gate['phase'] == 'HELD':
            if (gate['request_id'], gate['scope_sha256']) != (request_id, scope_sha256):
                raise AdmissionHeld('original metadata hold intent required')
            return _ref(gate_row)
        now = self._now()
        if now < gate['created_at_ms'] or any(body['issued_at_ms'] > now for body in active.values()):
            raise AdmissionHeld('metadata hold clock invalid')
        value = {**gate, 'phase': 'HELD', 'request_id': request_id, 'scope_sha256': scope_sha256, 'held_at_ms': now}
        try:
            self.repository.transact((Write(GATE, gate_row.revision, value),), (runtime,))
        except (StoreConflict, StoreUnavailable):
            pass
        row, _, _, held, _ = self._read()
        if (held['phase'], held.get('request_id'), held.get('scope_sha256')) != ('HELD', request_id, scope_sha256):
            raise AdmissionHeld('metadata hold confirmation unavailable')
        return _ref(row)

    def drained(self, *, request_id, scope_sha256):
        _uuid(request_id); _sha(scope_sha256)
        gate_row, registry, runtime, gate, active = self._read()
        active = self._business_active(active, runtime, gate)
        now = self._now()
        if (gate['phase'] != 'HELD' or (gate['request_id'], gate['scope_sha256']) != (request_id, scope_sha256)
                or runtime.data['inspection_enabled'] is not False or active or now < gate['held_at_ms']):
            raise AdmissionHeld('exact held request and confirmed empty registry required')
        return DrainProof(request_id, scope_sha256, gate['epoch'], _ref(gate_row), _ref(registry), _ref(runtime))

    def assert_drained(self, proof):
        if type(proof) is not DrainProof: raise AdmissionHeld('exact original drain proof required')
        try:
            _uuid(proof.request_id); _sha(proof.scope_sha256)
            if type(proof.epoch) is not int: raise ValueError()
            _n(proof.epoch, positive=True)
            for reference, key in ((proof.gate, GATE), (proof.registry, REGISTRY), (proof.runtime, RUNTIME)):
                if (type(reference) is not AdmissionReference or type(reference.key) is not Key
                        or reference.key != key or type(reference.revision) is not int):
                    raise ValueError()
                _n(reference.revision, positive=True); _sha(reference.sha256)
        except (ValueError, TypeError, AttributeError):
            raise AdmissionHeld('exact typed drain references required') from None
        current = self.drained(request_id=proof.request_id, scope_sha256=proof.scope_sha256)
        if current != proof: raise AdmissionHeld('metadata drain source changed')
        gate, registry, runtime, _, _ = self._read()
        if (_ref(gate), _ref(registry), _ref(runtime)) != (proof.gate, proof.registry, proof.runtime):
            raise AdmissionHeld('metadata drain source changed')
        return gate, registry, runtime  # Private rows for the actual caller's conditional commit.


@contextmanager
def bind_admission(service, intent):
    """Carry an intent, without granting it; checkpoint_current checks durable state."""
    if type(service) is not PersistentAdmission or type(intent) is not AdmissionIntent:
        raise AdmissionHeld('typed metadata admission context required')
    token = _CURRENT.set((service, intent))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def checkpoint_current(expected_service=None):
    current = _CURRENT.get()
    if current is None or (expected_service is not None and current[0] is not expected_service):
        raise AdmissionHeld('registered metadata work context required')
    current[0].checkpoint(current[1])


@contextmanager
def _bind_control(service, intent):
    """Transport-only context; never accepts an unregistered or ordinary intent."""
    if (type(service) is not PersistentAdmission or type(intent) is not AdmissionIntent
            or _CONTROL.get() is not None or _CURRENT.get() is not None):
        raise AdmissionHeld('exclusive typed control context required')
    service._checkpoint_control(intent)
    token = _CONTROL.set((service, intent))
    try:
        yield
    finally:
        _CONTROL.reset(token)
