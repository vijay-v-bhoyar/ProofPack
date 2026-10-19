"""Actual local executor ownership; never a durable privacy-drain attestation."""
from threading import Condition
from time import monotonic

from proofpack.evidence.privacy_admission import AdmissionHeld


class ResourceOwner:
    def __init__(self):
        self._condition = Condition()
        self._active = set()
        self._closing = False
        self._callbacks = []

    def acquire(self):
        with self._condition:
            if self._closing:
                raise AdmissionHeld('application resources are stopping')
            ticket = object()
            self._active.add(ticket)
            return ticket

    def release(self, ticket):
        callbacks = []
        with self._condition:
            if ticket not in self._active:
                raise ValueError('exact active resource ownership required')
            self._active.remove(ticket)
            if not self._active:
                self._condition.notify_all()
                if self._closing:
                    callbacks, self._callbacks = self._callbacks, []
        for callback in callbacks:
            callback()

    def stop_accepting(self):
        with self._condition:
            self._closing = True

    def wait_for_drain(self, timeout_ms):
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 300000:
            raise ValueError('explicit bounded local drain duration required')
        deadline = monotonic() + timeout_ms/1000
        with self._condition:
            while self._active:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def after_drain(self, callback):
        if not callable(callback):
            raise ValueError('resource cleanup callback required')
        with self._condition:
            if not self._closing:
                raise ValueError('stop local admission before scheduling cleanup')
            ready = not self._active
            if not ready:
                self._callbacks.append(callback)
        if ready:
            callback()
