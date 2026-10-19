"""Exact synchronous ordinary-work admission; no cleanup/control-plane bypass."""
from uuid import uuid4
from concurrent.futures import Future
import inspect

from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionHeld, bind_admission, checkpoint_current
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.ownership import ResourceOwner


class AdmittedWorker:
    def __init__(self, admission, *, lease_ms, attempts, resource_owner=None):
        if (type(admission) is not PersistentAdmission or type(lease_ms) is not int
                or not 1 <= lease_ms <= admission.limits.max_lease_ms
                or type(attempts) is not int or not 1 <= attempts <= 3
                or (resource_owner is not None and type(resource_owner) is not ResourceOwner)):
            raise ValueError('explicit shared worker admission/lifetime/retry bounds required')
        self.admission = admission; self.lease_ms = lease_ms; self.attempts = attempts
        self.release_pending = False; self.resource_owner = resource_owner
        self._initial = (admission, lease_ms, attempts, resource_owner)

    def _check(self):
        admission, lease_ms, attempts, owner = self._initial
        if (self.admission is not admission or self.resource_owner is not owner
                or type(self.lease_ms) is not int or self.lease_ms != lease_ms
                or type(self.attempts) is not int or self.attempts != attempts):
            raise AdmissionHeld('original worker configuration changed')

    def _attempt(self, operation):
        attempts = self._initial[2]
        for index in range(attempts):
            self._check()
            try:
                result = operation()
                self._check()
                return result
            except StoreConflict:
                self._check()
                if index+1 == attempts: raise

    def checkpoint(self):
        self._check()
        checkpoint_current(self._initial[0])
        self._check()

    def run(self, operation):
        if not callable(operation) or inspect.iscoroutinefunction(operation):
            raise ValueError('trusted synchronous worker operation required')
        self._check()
        if self.release_pending: raise AdmissionHeld('prior worker release remains pending')
        admission, lease_ms, _, owner = self._initial
        ticket = owner.acquire() if owner is not None else None
        intent = None; uncertain = False; failed = False
        try:
            self._check()
            intent = admission.prepare(work_id=str(uuid4()), kind='worker', lease_ms=lease_ms)
            self._check()
            self._attempt(lambda: admission.admit(intent))
            admission.checkpoint(intent)
            self._check()
            with bind_admission(admission, intent):
                result = operation()  # Never replay business work on a bookkeeping conflict.
                if inspect.isawaitable(result) or isinstance(result, Future):
                    uncertain = True
                    self.release_pending = True
                    if inspect.iscoroutine(result): result.close()
                    raise AdmissionHeld('deferred worker completion remains unconfirmed')
                self._check()
                return result
        except BaseException as error:
            failed = True
            if not isinstance(error, Exception):
                uncertain = True
                self.release_pending = True
            raise
        finally:
            try:
                try:
                    self._check()
                except AdmissionHeld:
                    self.release_pending = True
                    if not failed: raise
                if intent is not None and not uncertain and not self.release_pending:
                    try:
                        self._attempt(lambda: admission.release(intent))
                    except (AdmissionHeld, StoreConflict, StoreUnavailable):
                        self.release_pending = True
                        try:
                            self._check()
                        except AdmissionHeld:
                            if not failed: raise
                    except Exception:
                        self.release_pending = True
                        try:
                            self._check()
                        except AdmissionHeld:
                            if not failed: raise
                        if not failed: raise
            except BaseException as error:
                if not isinstance(error, Exception):
                    uncertain = True
                    self.release_pending = True
                raise
            finally:
                if ticket is not None and not uncertain:
                    owner.release(ticket)
