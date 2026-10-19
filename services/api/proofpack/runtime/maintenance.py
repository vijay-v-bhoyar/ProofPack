"""One bounded same-host maintenance thread using the application's existing services."""
from threading import Event, Lock, Thread

from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import RUNTIME, ResourceUnavailable
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.job_authority import resolve
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable
from proofpack.evidence.privacy_admission import AdmissionHeld
from proofpack.evidence.privacy_workers import AdmittedWorker
from proofpack.evidence.exports import ExportLimited
from proofpack.evidence.erasure import ErasureLimited
from proofpack.review.manifests import DatasetLimited
from proofpack.review.evaluation_models import EvaluationLimited
from proofpack.runtime.control import integer, uuid


QUOTA = Key('state', 'maintenance-step-quota')


class MaintenanceStopped(RuntimeError): pass
class MaintenanceSuperseded(MaintenanceStopped): pass
class MaintenanceLimited(RuntimeError): pass


def validate_limits(enabled, poll_ms, page_size, steps_per_minute, drain_ms):
    if type(enabled) is not bool or any(type(value) is not int or not low <= value <= high
            for value, low, high in ((poll_ms, 250, 60000), (page_size, 1, 25),
                (steps_per_minute, 1, 120), (drain_ms, 1000, 60000))):
        raise ValueError('explicit bounded maintenance configuration required')


class MaintenanceDriver:
    def __init__(self, access, runtime, exports, erasure, *, enabled, poll_ms, page_size, steps_per_minute, drain_ms, datasets=None, evaluations=None, preparations=None, qualifications=None, admission_runner=None):
        validate_limits(enabled, poll_ms, page_size, steps_per_minute, drain_ms)
        if runtime.access is not access or any(service.access is not access or service.runtime is not runtime
                or service.repository is not access.repository for service in (exports, erasure, *((datasets,) if datasets is not None else ()), *((evaluations,) if evaluations is not None else ()))):
            raise ValueError('maintenance must share application authority and services')
        if preparations is not None and (evaluations is None or preparations.evaluations is not evaluations or preparations.access is not access or preparations.runtime is not runtime or preparations.repository is not access.repository):raise ValueError('preparation dispatch must share evaluation authority')
        if qualifications is not None and (qualifications.access is not access or qualifications.runtime is not runtime or qualifications.repository is not access.repository
                or evaluations is None or qualifications.policies is not evaluations.policies or qualifications.preparations is not preparations):raise ValueError('qualification dispatch must share genuine policy and preparation authority')
        self.access = access; self.repository = access.repository; self.runtime = runtime
        if (admission_runner is not None and (type(admission_runner) is not AdmittedWorker
                or admission_runner.admission.repository is not self.repository
                or admission_runner.admission.runtime is not runtime)):
            raise ValueError('maintenance admission must share exact application runtime and target')
        self._admission_runner = admission_runner
        self.services = {'inspection_export': exports, 'asset_erasure': erasure}
        if datasets is not None:self.services['dataset_manifest']=datasets
        if evaluations is not None:self.services['policy_evaluation']=evaluations
        if preparations is not None:self.services['policy_qualification_preparation']=preparations
        if qualifications is not None:self.services['policy_qualification']=qualifications
        self.enabled = enabled; self.poll_ms = poll_ms; self.page_size = page_size
        self.steps_per_minute = steps_per_minute; self.drain_ms = drain_ms
        self._stop = Event(); self._lock = Lock(); self._poll_lock = Lock()
        self._thread = None; self._started = False; self._finished = False; self._callbacks = []
        self._exit_observer = None; self._thread_exit_callbacks = []
        self._drain_failed = False; self._cursor = None; self._state = 'constructed'; self._active = False
        self._counts = {'polls': 0, 'attempts': 0, 'succeeded': 0, 'held': 0, 'errors': 0}
        self._reason = None

    def _runtime_row(self):
        row = self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(row): raise MaintenanceSuperseded('maintenance runtime superseded')
        return row

    def checkpoint(self):
        if self._stop.is_set(): raise MaintenanceStopped('maintenance stopping')
        if self._admission_runner is not None: self._admission_runner.checkpoint()
        self._runtime_row()
        if self._stop.is_set(): raise MaintenanceStopped('maintenance stopping')

    def _record(self, reason, count=None):
        with self._lock:
            if reason is not None: self._reason = reason
            if count is not None: self._counts[count] += 1

    def _reserve(self, job):
        self.checkpoint()
        rows = self.repository.snapshot((RUNTIME, QUOTA)); runtime = rows[RUNTIME]; row = rows[QUOTA]
        if not self.runtime.matches(runtime): raise MaintenanceSuperseded('maintenance runtime superseded')
        minute = self.access.now() // 60000
        if row is not None and integer(row.data['minute']) > minute:
            raise StoreUnavailable('maintenance quota clock moved backwards')
        count = 0 if row is None or integer(row.data['minute']) != minute else integer(row.data['count'])
        if count >= self.steps_per_minute: raise MaintenanceLimited('maintenance allowance exhausted')
        self.checkpoint()
        self.repository.transact((Write(QUOTA, None if row is None else row.revision,
            {'minute': minute, 'count': count + 1}),), (runtime, job))

    def _eligible(self, row):
        data = row.data
        try:
            return (data['kind'] in self.services and row.key == Key('state', 'maintenance-job#' + uuid(data['id']))
                and (data['status'] == 'queued' or (data['status'] == 'processing'
                    and self.access.now() >= integer(data['lease_until_ms']))))
        except (KeyError, TypeError, ValueError): return False

    def poll_once(self):
        if self._admission_runner is None: return self._poll_once()
        if not self.enabled: return False
        try:
            result = self._admission_runner.run(self._poll_once)
            if self._admission_runner.release_pending: self._record('METADATA_RELEASE_PENDING', 'held')
            return result
        except (AdmissionHeld, StoreConflict, StoreUnavailable):
            self._record('METADATA_ADMISSION_HELD', 'held')
            return False

    def _poll_once(self):
        """Trusted deterministic test/driver entry; not an HTTP operation."""
        if not self.enabled: return False
        if not self._poll_lock.acquire(blocking=False): return False
        try:
            self.checkpoint(); self._record(None, 'polls')
            page, cursor = self.repository.query(prefix='maintenance-job#', table='state',
                limit=self.page_size, start_resource=self._cursor)
            self.checkpoint()
            if len(page) > self.page_size or (cursor is not None and cursor == self._cursor):
                raise StoreUnavailable('bounded progressing maintenance page required')
            candidate = next((row for row in page if self._eligible(row)), None)
            self._cursor = cursor if candidate is None else candidate.key.resource
            if candidate is None: return False
            self._reserve(candidate); self._record(None, 'attempts')
            actor = resolve(self.access, candidate.data)
            self.checkpoint()
            with self._lock: self._active = True
            intent = digest({'operation': 'maintenance-v1', 'job_id': candidate.data['id'], 'revision': candidate.revision})
            self.services[candidate.data['kind']].advance(actor, candidate.data['id'],
                expected_version=candidate.revision, idempotency_key=intent, execution_gate=self.checkpoint)
            self._record('STEP_FINISHED', 'succeeded')
            return True
        except MaintenanceSuperseded:
            self._stop.set()
            with self._lock: self._state = 'superseded'
            self._record('RUNTIME_SUPERSEDED', 'held')
        except MaintenanceStopped: self._record('STOPPED', 'held')
        except AdmissionHeld: self._record('METADATA_ADMISSION_HELD', 'held')
        except MaintenanceLimited: self._record('STEP_ALLOWANCE', 'held')
        except (ExportLimited, ErasureLimited, DatasetLimited, EvaluationLimited): self._record('EXECUTOR_ALLOWANCE', 'held')
        except (Denied, ResourceUnavailable): self._record('AUTHORITY_HELD', 'held')
        except StoreConflict: self._record('STATE_CHANGED', 'held')
        except StoreUnavailable: self._record('DEPENDENCY_UNAVAILABLE', 'held')
        except Exception: self._record('INTERNAL_ERROR', 'errors')
        finally:
            with self._lock: self._active = False
            self._poll_lock.release()
        return False

    def start(self):
        with self._lock:
            if self._started or self._stop.is_set(): raise RuntimeError('maintenance incarnation cannot restart')
            self._started = True
            if not self.enabled:
                self._state = 'disabled'; self._finished = True
                return
            self._state = 'running'
            self._thread = Thread(target=self._run, name='proofpack-maintenance', daemon=False)
            try: self._thread.start()
            except BaseException:
                self._thread = None; self._finished = True; self._state = 'failed'
                raise

    def _run(self):
        try:
            while not self._stop.is_set():
                self.poll_once()
                self._stop.wait(self.poll_ms / 1000)
        finally:
            with self._lock:
                self._finished = True
                if not self._drain_failed and self._state != 'superseded': self._state = 'stopped'
                callbacks = self._callbacks; self._callbacks = []
            for callback in callbacks: callback()

    def request_stop(self):
        """Synchronous stop/terminal notification, safe before any drain await."""
        self._stop.set()
        with self._lock:
            thread = self._thread
            if self._state == 'running': self._state = 'stopping'
            callbacks = []
            if thread is None:
                self._finished = True
                callbacks, self._callbacks = self._callbacks, []
        for callback in callbacks: callback()

    def stop_and_drain(self):
        self.request_stop()
        with self._lock: thread = self._thread
        if thread is not None: thread.join(self.drain_ms / 1000)
        drained = thread is None or not thread.is_alive()
        with self._lock:
            if not drained: self._drain_failed = True; self._state = 'drain_failed'
        return drained

    def after_thread_exit(self, callback):
        """Observe physical thread termination; processing-finally is not exit."""
        if not callable(callback): raise ValueError('thread exit callback required')
        with self._lock:
            thread = self._thread
            ready = thread is None or not thread.is_alive()
            if not ready:
                self._thread_exit_callbacks.append(callback)
                if self._exit_observer is None:
                    observer = Thread(target=self._observe_thread_exit, args=(thread,),
                        name='proofpack-maintenance-exit', daemon=False)
                    self._exit_observer = observer
                    try: observer.start()
                    except BaseException:
                        self._exit_observer = None
                        raise
        if ready: callback()

    def _observe_thread_exit(self, thread):
        thread.join()  # Owned deferred notification; never a server drain wait.
        with self._lock:
            callbacks, self._thread_exit_callbacks = self._thread_exit_callbacks, []
        for callback in callbacks: callback()

    def after_exit(self, callback):
        """Race-safe resource-owner notification; not permission to close mid-step."""
        with self._lock:
            now = self._finished
            if not now: self._callbacks.append(callback)
        if now: callback()

    def read(self, actor):
        self.access._fresh(actor, Role.OWNER)
        current = self.runtime.matches(self.repository.snapshot((RUNTIME,))[RUNTIME])
        with self._lock:
            result = {'enabled': self.enabled, 'state': self._state,
                'local_instance_current': current,
                'thread_alive': self._thread is not None and self._thread.is_alive(),
                'active_step': self._active, 'drain_failed': self._drain_failed,
                'counts': dict(self._counts), 'last_reason': self._reason,
                'poll_ms': self.poll_ms, 'page_size': self.page_size,
                'steps_per_minute': self.steps_per_minute, 'drain_ms': self.drain_ms}
        self.access._fresh(actor, Role.OWNER)
        return result
