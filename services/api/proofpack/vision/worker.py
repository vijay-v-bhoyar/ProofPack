"""Single-flight resource-limited CV worker. JSON bytes, never child-origin pickle.

Warmup precedes capture admission. A failed/timed-out worker is permanently closed;
the service must fence its station before explicitly creating a new incarnation.
"""
from dataclasses import asdict
from contextlib import contextmanager
import hashlib
import base64
import json
import multiprocessing
from threading import BoundedSemaphore,Lock,Timer
import time

from proofpack.vision.worker_limits import WorkerLimits


class WorkerUnavailable(RuntimeError):
    pass


class WorkerBusy(WorkerUnavailable):
    pass


def _entry(connection,limits: WorkerLimits):
    try:
        from proofpack.vision.worker_limits import apply_resource_limits
        resource_receipt=apply_resource_limits(limits)
        from proofpack.recipes.models import Recipe
        from proofpack.vision.calibration import CalibrationProfile,CalibrationError,rectify
        from proofpack.vision.pipeline import InvalidImage,decode_image,measure
        from proofpack.vision.tracking import SceneTracker
        from proofpack.verifier.core import Finding
        import cv2
        cv2.setNumThreads(1)
        if cv2.__version__.split('.')[0]!='5':raise RuntimeError("wrong_cv_version")
        tracker=SceneTracker(pixel_delta=limits.pixel_delta,max_changed_pixels=limits.max_changed_pixels)
        connection.send_bytes(json.dumps({"status":"ready","limits":resource_receipt}).encode())
        while True:
            raw=connection.recv_bytes(limits.max_metadata_bytes)
            request=json.loads(raw)
            if isinstance(request,dict) and set(request)=={'op','parameters'} and request['op']=='calibration':
                from proofpack.vision.calibration_diagnostics import diagnose_calibration
                payload=connection.recv_bytes(limits.max_input_bytes)
                result=diagnose_calibration(payload,request['parameters'],max_bytes=limits.max_input_bytes)
                encoded=json.dumps({'ok':True,'result':result.model_dump(mode='json')},allow_nan=False).encode()
                if len(encoded)>limits.max_reply_bytes:raise ValueError('diagnostic reply bound')
                connection.send_bytes(encoded)
                continue
            if isinstance(request,dict) and set(request)=={'op','content_type'} and request['op']=='reference':
                from proofpack.vision.reference import normalize_reference
                payload=connection.recv_bytes(limits.max_input_bytes)
                metadata,canonical=normalize_reference(payload,request['content_type'],max_bytes=limits.max_input_bytes)
                connection.send_bytes(json.dumps({'ok':True,'result':metadata.model_dump()},allow_nan=False).encode())
                connection.send_bytes(canonical)
                continue
            if set(request)!={"op","recipe","profile","sequence","inspection_id"} or request["op"]!="analyze":
                raise ValueError("invalid operation")
            payload=connection.recv_bytes(limits.max_input_bytes)
            try:
                recipe=Recipe.model_validate_json(json.dumps(request['recipe']))
                profile=CalibrationProfile.model_validate_json(json.dumps(request['profile']))
                frame=decode_image(payload,max_bytes=limits.max_input_bytes)
                rectified,envelope=rectify(frame,profile)
                result=measure(rectified,recipe,envelope,max_contours=limits.max_contours,max_candidates=limits.max_candidates)
                context=hashlib.sha256((recipe.model_dump_json()+profile.content_hash+request['inspection_id']).encode()).hexdigest()
                decision=tracker.update(rectified,sequence=request['sequence'],context=context)
                ok,evidence=cv2.imencode('.jpg',rectified,[cv2.IMWRITE_JPEG_QUALITY,85])
                evidence_bytes=evidence.tobytes() if ok else b''
                if len(evidence_bytes)>163840:evidence_bytes=b''
                body={**asdict(result),"scene_generation":decision.generation,"scene_changed":decision.changed,
                    "source_sha256":hashlib.sha256(payload).hexdigest(),"calibration_hash":profile.content_hash,
                    "evidence_jpeg_base64":base64.b64encode(evidence_bytes).decode() if evidence_bytes else None,
                    "evidence_sha256":hashlib.sha256(evidence_bytes).hexdigest() if evidence_bytes else None}
                if any(c.correction_reason is not None for c in result.candidates):
                    body['rectified_size']=[profile.output_width,profile.output_height]
                response={"ok":True,"result":body}
            except (InvalidImage,CalibrationError) as exc:
                decision=tracker.invalidate()
                response={"ok":True,"result":{"candidates":[],
                    "findings":[Finding.UNOBSERVABLE]*len(recipe.constraints),
                    "reason_codes":[str(exc) if isinstance(exc,CalibrationError) else "invalid_image"],
                    "quality_ok":False,"unknown_regions":0,"scene_generation":decision.generation,
                    "scene_changed":True,"source_sha256":hashlib.sha256(payload).hexdigest(),
                    "calibration_hash":profile.content_hash}}
            except ValueError:
                tracker.invalidate()
                response={"ok":False,"code":"unsupported_or_invalid_frame"}
            encoded=json.dumps(response,separators=(',',':'),allow_nan=False).encode()
            if len(encoded)>limits.max_reply_bytes:raise ValueError("reply too large")
            connection.send_bytes(encoded)
    except (Exception,KeyboardInterrupt):
        # No stack/input/image/provider configuration crosses the decoder boundary.
        try:connection.send_bytes(b'{"ok":false,"code":"worker_unavailable"}')
        except (OSError,EOFError):pass
    finally:
        connection.close()


class VisionWorker:
    def __init__(self,limits: WorkerLimits):
        self.limits=limits
        self._busy=Lock()
        self._closing=Lock()
        self._closed=False
        context=multiprocessing.get_context('spawn')
        self._connection,child=context.Pipe(duplex=True)
        self._process=context.Process(target=_entry,args=(child,limits),daemon=True)
        try:
            self._process.start()
            child.close()
            if not self._connection.poll(limits.startup_ms/1000):raise WorkerUnavailable("worker_startup_timeout")
            ready=json.loads(self._connection.recv_bytes(limits.max_reply_bytes))
            if (not isinstance(ready,dict) or set(ready)!={'status','limits'}
                    or ready.get('status')!='ready' or not isinstance(ready['limits'],dict)):
                raise WorkerUnavailable("worker_limits_or_runtime_unavailable")
            self.resource_receipt=ready['limits']
        except (OSError,EOFError,ValueError,WorkerUnavailable) as exc:
            child.close()
            self.close()
            raise WorkerUnavailable("worker_startup_failed") from exc

    @property
    def process_id(self) -> int:
        return self._process.pid

    @property
    def available(self) -> bool:
        return not self._closed and self._process.is_alive()

    def close(self) -> None:
        with self._closing:
            if self._closed:return
            self._closed=True
            if self._process.is_alive():self._process.terminate()
            if self._process.pid is not None:self._process.join(timeout=1)
            self._connection.close()

    def analyze(self,payload: bytes,recipe,profile,*,sequence: int,inspection_id: str):
        from proofpack.vision.worker_result import WorkerResult
        if (not isinstance(payload,bytes) or not 0<len(payload)<=self.limits.max_input_bytes
                or type(sequence) is not int or sequence<1 or not isinstance(inspection_id,str)
                or not 1<=len(inspection_id)<=64):
            raise ValueError("bounded frame identity required")
        if recipe.calibration_profile_id!=profile.profile_id or recipe.data_origin!=profile.data_origin:
            raise ValueError('recipe and calibration bindings do not match')
        metadata=json.dumps({"op":"analyze","recipe":recipe.model_dump(mode='json'),
            "profile":profile.model_dump(mode='json'),"sequence":sequence,"inspection_id":inspection_id},allow_nan=False).encode()
        if len(metadata)>self.limits.max_metadata_bytes:raise ValueError("metadata bound exceeded")
        if not self._busy.acquire(blocking=False):raise WorkerBusy("one_pending_frame_only")
        started=time.monotonic()
        watchdog=Timer(self.limits.wall_ms/1000,self.close)
        watchdog.daemon=True
        try:
            if self._closed or not self._process.is_alive():raise WorkerUnavailable("worker_closed")
            watchdog.start()
            self._connection.send_bytes(metadata)
            self._connection.send_bytes(payload)
            if not self._connection.poll(self.limits.wall_ms/1000):raise WorkerUnavailable("worker_timeout")
            raw=self._connection.recv_bytes(self.limits.max_reply_bytes)
            if (time.monotonic()-started)*1000>=self.limits.wall_ms:raise WorkerUnavailable("worker_timeout")
            reply=json.loads(raw)
            if not isinstance(reply,dict) or reply.get('ok') is not True or set(reply)!={'ok','result'}:
                raise WorkerUnavailable("frame_requires_review")
            result=WorkerResult.model_validate_json(json.dumps(reply['result']))
            if (result.source_sha256!=hashlib.sha256(payload).hexdigest() or result.calibration_hash!=profile.content_hash
                    or len(result.findings)!=len(recipe.constraints)):
                raise WorkerUnavailable("worker_provenance_mismatch")
            if self._closed or (time.monotonic()-started)*1000>=self.limits.wall_ms:
                raise WorkerUnavailable("worker_timeout")
            return result
        except (OSError,EOFError,ValueError,WorkerUnavailable) as exc:
            self.close()
            raise WorkerUnavailable("measurement_unavailable_station_recheck_required") from exc
        finally:
            watchdog.cancel()
            self._busy.release()

    def reference(self,payload:bytes,*,content_type:str):
        from proofpack.vision.reference import ReferenceMetadata
        if not isinstance(payload,bytes) or not 0<len(payload)<=self.limits.max_input_bytes or content_type not in {'image/jpeg','image/png'}:
            raise ValueError('bounded reference bytes required')
        if not self._busy.acquire(blocking=False):raise WorkerBusy('one_pending_frame_only')
        started=time.monotonic();watchdog=Timer(self.limits.wall_ms/1000,self.close);watchdog.daemon=True
        try:
            if not self.available:raise WorkerUnavailable('worker_closed')
            watchdog.start()
            self._connection.send_bytes(json.dumps({'op':'reference','content_type':content_type}).encode())
            self._connection.send_bytes(payload)
            if not self._connection.poll(self.limits.wall_ms/1000):raise WorkerUnavailable('worker_timeout')
            reply=json.loads(self._connection.recv_bytes(self.limits.max_reply_bytes))
            if not isinstance(reply,dict) or set(reply)!={'ok','result'} or reply['ok'] is not True:raise WorkerUnavailable('reference_unavailable')
            metadata=ReferenceMetadata.model_validate_json(json.dumps(reply['result']))
            if not self._connection.poll(self.limits.wall_ms/1000):raise WorkerUnavailable('worker_timeout')
            canonical=self._connection.recv_bytes(self.limits.max_input_bytes)
            if (self._closed or (time.monotonic()-started)*1000>=self.limits.wall_ms
                    or metadata.source_sha256!=hashlib.sha256(payload).hexdigest()
                    or metadata.stored_sha256!=hashlib.sha256(canonical).hexdigest()
                    or metadata.byte_length!=len(canonical) or not canonical.startswith(b'\xff\xd8\xff')):
                raise WorkerUnavailable('reference_provenance_or_deadline')
            return metadata,canonical
        except (OSError,EOFError,ValueError,WorkerUnavailable) as exc:
            self.close();raise WorkerUnavailable('reference_verification_unavailable') from exc
        finally:watchdog.cancel();self._busy.release()

    def calibration(self,payload:bytes,*,parameters):
        from proofpack.vision.calibration_diagnostics import CalibrationDiagnostic,EnrollmentParameters,CheckParameters
        if not isinstance(payload,bytes) or not 0<len(payload)<=self.limits.max_input_bytes:raise ValueError('bounded calibration bytes required')
        mode=parameters.get('mode') if isinstance(parameters,dict) else None
        spec=EnrollmentParameters.model_validate_json(json.dumps(parameters)) if mode=='enroll' else CheckParameters.model_validate_json(json.dumps(parameters))
        request=json.dumps({'op':'calibration','parameters':spec.model_dump(mode='json')},allow_nan=False).encode()
        if len(request)>self.limits.max_metadata_bytes:raise ValueError('diagnostic metadata bound')
        if not self._busy.acquire(blocking=False):raise WorkerBusy('one_pending_frame_only')
        started=time.monotonic();watchdog=Timer(self.limits.wall_ms/1000,self.close);watchdog.daemon=True
        try:
            if not self.available:raise WorkerUnavailable('worker_closed')
            watchdog.start();self._connection.send_bytes(request);self._connection.send_bytes(payload)
            if not self._connection.poll(self.limits.wall_ms/1000):raise WorkerUnavailable('worker_timeout')
            reply=json.loads(self._connection.recv_bytes(self.limits.max_reply_bytes))
            if not isinstance(reply,dict) or set(reply)!={'ok','result'} or reply['ok'] is not True:raise WorkerUnavailable('calibration_diagnostic_unavailable')
            result=CalibrationDiagnostic.model_validate_json(json.dumps(reply['result']))
            if (self._closed or (time.monotonic()-started)*1000>=self.limits.wall_ms
                    or result.source_sha256!=hashlib.sha256(payload).hexdigest()
                    or (mode=='check' and result.profile_sha256!=spec.profile.content_hash)
                    or (mode=='enroll' and result.profile is not None and
                        (result.profile.profile_id!=spec.profile_id or result.profile.revision!=spec.revision
                         or result.profile.camera_id!=spec.camera_id or result.profile.data_origin!=spec.data_origin))):
                raise WorkerUnavailable('calibration_diagnostic_provenance_or_deadline')
            return result
        except (OSError,EOFError,ValueError,WorkerUnavailable) as exc:
            self.close();raise WorkerUnavailable('calibration_diagnostic_unavailable') from exc
        finally:watchdog.cancel();self._busy.release()

    def __enter__(self):return self

    def __exit__(self,*args):self.close()


class VisionPool:
    """Per-runtime resource cap, in addition to the required durable station allocation."""
    def __init__(self,limits: WorkerLimits,*,max_processes: int):
        if type(max_processes) is not int or not 1<=max_processes<=2:
            raise ValueError('one or two worker processes only')
        self.limits=limits
        self._slots=BoundedSemaphore(max_processes)

    @contextmanager
    def lease(self):
        if not self._slots.acquire(blocking=False):raise WorkerBusy('worker_capacity_exhausted')
        worker=None
        try:
            worker=VisionWorker(self.limits)
            yield worker
        finally:
            if worker is not None:worker.close()
            self._slots.release()
