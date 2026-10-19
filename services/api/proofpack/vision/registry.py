"""Owned warm CV workers, fenced to station/runtime/profile. No automatic restart."""
from contextlib import contextmanager
from dataclasses import dataclass,field
from threading import Lock
from uuid import uuid4

from proofpack.runtime.control import sha,uuid
from proofpack.vision.worker import VisionPool,WorkerBusy,WorkerUnavailable
from proofpack.vision.worker_limits import WorkerLimits


@dataclass
class Binding:
    station_id: str
    epoch: int
    runtime_id: str
    calibration_sha256: str
    worker_id: str
    worker: object = field(repr=False)
    lease: object = field(repr=False)
    busy: bool = False
    retire_requested: bool = False


class WorkerRegistry:
    def __init__(self,limits:WorkerLimits,*,max_processes=2):
        self.pool=VisionPool(limits,max_processes=max_processes)
        self._bindings={};self._lock=Lock();self._closed=False
        self._fences={};self._runtime_id=None
        self._diagnostics={}

    @staticmethod
    def _identity(station_id,epoch,runtime_id):
        uuid(station_id);uuid(runtime_id)
        if type(epoch) is not int or epoch<1:raise ValueError('acquired station epoch required')

    def prepare(self,*,station_id,epoch,runtime_id,calibration_sha256):
        self._identity(station_id,epoch,runtime_id);sha(calibration_sha256)
        with self._lock:
            if self._closed:raise WorkerUnavailable('registry_closed')
            if self._runtime_id is None:self._runtime_id=runtime_id
            if self._runtime_id!=runtime_id:raise WorkerUnavailable('new_runtime_requires_new_registry')
            old=self._bindings.get(station_id)
            if old is not None:
                same=(old.epoch==epoch and old.runtime_id==runtime_id and old.calibration_sha256==calibration_sha256)
                if same:
                    if not old.worker.available:raise WorkerUnavailable('failed_worker_requires_new_station_fence')
                    return old.worker_id
                if old.busy:raise WorkerBusy('cannot_replace_inflight_worker')
                if old.runtime_id==runtime_id and epoch<=old.epoch:raise WorkerUnavailable('new_station_fence_required')
                old.lease.__exit__(None,None,None);self._bindings.pop(station_id)
            if old is None and station_id in self._fences and epoch<=self._fences[station_id]:
                raise WorkerUnavailable('new_station_fence_required')
            if station_id not in self._fences and len(self._fences)>=256:
                raise WorkerUnavailable('worker_history_limit_requires_runtime_restart')
            lease=self.pool.lease()
            try:worker=lease.__enter__()
            except WorkerBusy:raise
            except WorkerUnavailable:
                self._fences[station_id]=epoch
                raise
            binding=Binding(station_id,epoch,runtime_id,calibration_sha256,str(uuid4()),worker,lease)
            self._fences[station_id]=epoch
            self._bindings[station_id]=binding
            return binding.worker_id

    def guard(self,station_id,epoch,runtime_id):
        self._identity(station_id,epoch,runtime_id)
        with self._lock:
            binding=self._bindings.get(station_id)
            if (self._closed or binding is None or binding.epoch!=epoch or binding.runtime_id!=runtime_id
                    or not binding.worker.available):raise WorkerUnavailable('warm_worker_binding_unavailable')

    @contextmanager
    def diagnostic(self,*,runtime_id):
        uuid(runtime_id);ident=str(uuid4())
        with self._lock:
            if self._closed:raise WorkerUnavailable('registry_closed')
            if self._runtime_id is None:self._runtime_id=runtime_id
            if self._runtime_id!=runtime_id:raise WorkerUnavailable('new_runtime_requires_new_registry')
            lease=self.pool.lease();worker=lease.__enter__();self._diagnostics[ident]=worker
        try:yield worker
        finally:
            with self._lock:
                lease.__exit__(None,None,None);self._diagnostics.pop(ident,None)

    @contextmanager
    def analyze(self,*,station_id,epoch,runtime_id,calibration_sha256):
        self._identity(station_id,epoch,runtime_id);sha(calibration_sha256)
        with self._lock:
            binding=self._bindings.get(station_id)
            if (self._closed or binding is None or binding.epoch!=epoch or binding.runtime_id!=runtime_id
                    or binding.calibration_sha256!=calibration_sha256 or not binding.worker.available):
                raise WorkerUnavailable('warm_worker_binding_unavailable')
            if binding.busy:raise WorkerBusy('one_station_analysis_only')
            binding.busy=True
        try:yield binding
        finally:
            with self._lock:
                binding.busy=False
                if self._closed or binding.retire_requested:
                    for ident,item in tuple(self._bindings.items()):
                        if not item.busy and (self._closed or item.retire_requested):
                            item.lease.__exit__(None,None,None);self._bindings.pop(ident)

    def invalidate(self,station_id,epoch,runtime_id):
        """Withdrawal-only lifecycle hook; late calls cannot retire a newer fence."""
        uuid(station_id);uuid(runtime_id)
        with self._lock:
            binding=self._bindings.get(station_id)
            if binding is None or binding.epoch!=epoch or binding.runtime_id!=runtime_id:return
            binding.retire_requested=True
            binding.worker.close()
            if not binding.busy:binding.lease.__exit__(None,None,None);self._bindings.pop(station_id)

    def retire(self,station_id,*,worker_id=None,epoch=None,runtime_id=None):
        uuid(station_id)
        with self._lock:
            binding=self._bindings.get(station_id)
            if binding is None:return
            if worker_id is not None and binding.worker_id!=worker_id:return
            if epoch is not None and binding.epoch!=epoch:return
            if runtime_id is not None and binding.runtime_id!=runtime_id:return
            if binding.busy:raise WorkerBusy('cannot_retire_inflight_worker')
            binding.lease.__exit__(None,None,None);self._bindings.pop(station_id)

    def close(self):
        with self._lock:
            self._closed=True
            for worker in self._diagnostics.values():worker.close()
            if any(binding.busy for binding in self._bindings.values()):
                for binding in self._bindings.values():binding.worker.close()
                for ident,item in tuple(self._bindings.items()):
                    if not item.busy:item.lease.__exit__(None,None,None);self._bindings.pop(ident)
                return
            for binding in self._bindings.values():binding.lease.__exit__(None,None,None)
            self._bindings.clear()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
