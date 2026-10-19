"""Resource limits only; filesystem/network isolation still needs target verification."""
from dataclasses import dataclass
import os
import sys


@dataclass(frozen=True)
class WorkerLimits:
    memory_mb: int
    cpu_seconds: int
    wall_ms: int
    startup_ms: int
    max_input_bytes: int
    max_metadata_bytes: int
    max_reply_bytes: int
    max_contours: int
    max_candidates: int
    pixel_delta: int
    max_changed_pixels: int

    @classmethod
    def from_controls(cls,controls: dict):
        section=controls.get('vision_worker',{})
        expected=set(cls.__dataclass_fields__)|{'max_processes'}
        if set(section)!=expected or type(section['max_processes']) is not int or not 1<=section['max_processes']<=2:
            raise ValueError('complete worker controls required')
        return cls(**{key:value for key,value in section.items() if key!='max_processes'})

    def __post_init__(self):
        for name,value in vars(self).items():
            if type(value) is not int:
                raise ValueError(f"integer worker limit required: {name}")
        if (not 128<=self.memory_mb<=1024 or not 1<=self.cpu_seconds<=60
                or not 1<=self.wall_ms<=1000 or not 1<=self.startup_ms<=10000
                or not 1<=self.max_input_bytes<=2097152 or not 1<=self.max_metadata_bytes<=65536
                or not 1024<=self.max_reply_bytes<=262144 or not 1<=self.max_contours<=4096
                or not 1<=self.max_candidates<=30 or not 0<=self.pixel_delta<=254
                or not 0<=self.max_changed_pixels<=2000000):
            raise ValueError("worker limits outside admitted bounds")


_job_handle=None


def apply_resource_limits(limits: WorkerLimits) -> dict:
    """Called in the child before OpenCV/numpy imports. No silently unbounded OS."""
    global _job_handle
    # SDK configuration is disabled as defense in depth, not an OS egress sandbox.
    for name in tuple(os.environ):
        if name.startswith(("AWS_","OPENAI_","ANTHROPIC_","GOOGLE_API_","GEMINI_API_")):
            os.environ.pop(name,None)
    os.environ.update({"OPENBLAS_NUM_THREADS":"1","OMP_NUM_THREADS":"1","MKL_NUM_THREADS":"1",
        "AWS_EC2_METADATA_DISABLED":"true","AWS_SHARED_CREDENTIALS_FILE":os.devnull,"AWS_CONFIG_FILE":os.devnull})
    if sys.platform=="win32":
        import ctypes
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_=[("process_time",ctypes.c_int64),("job_time",ctypes.c_int64),
                ("flags",wintypes.DWORD),("min_working_set",ctypes.c_size_t),("max_working_set",ctypes.c_size_t),
                ("active_processes",wintypes.DWORD),("affinity",ctypes.c_size_t),
                ("priority",wintypes.DWORD),("scheduling",wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_=[(name,ctypes.c_uint64) for name in ("read_ops","write_ops","other_ops","read_bytes","write_bytes","other_bytes")]
        class Extended(ctypes.Structure):
            _fields_=[("basic",Basic),("io",IO),("process_memory",ctypes.c_size_t),
                ("job_memory",ctypes.c_size_t),("peak_process",ctypes.c_size_t),("peak_job",ctypes.c_size_t)]
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype=wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        kernel.SetInformationJobObject.restype=wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype=wintypes.BOOL
        kernel.GetCurrentProcess.restype=wintypes.HANDLE
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        job=kernel.CreateJobObjectW(None,None)
        if not job:raise RuntimeError("worker_job_creation_failed")
        info=Extended()
        info.basic.flags=0x00000002|0x00000008|0x00000100|0x00002000
        info.basic.process_time=limits.cpu_seconds*10000000
        info.basic.active_processes=1
        info.process_memory=limits.memory_mb*1024*1024
        if (not kernel.SetInformationJobObject(job,9,ctypes.byref(info),ctypes.sizeof(info))
                or not kernel.AssignProcessToJobObject(job,kernel.GetCurrentProcess())):
            kernel.CloseHandle(job)
            raise RuntimeError("worker_job_assignment_failed")
        _job_handle=job
        return {"platform":"windows_job","memory_mb":limits.memory_mb,"cpu_seconds":limits.cpu_seconds,"active_process_limit":1}
    if sys.platform.startswith("linux"):
        import ctypes
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(limits.memory_mb*1024*1024,)*2)
        resource.setrlimit(resource.RLIMIT_CPU,(limits.cpu_seconds,)*2)
        resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(38,1,0,0,0)!=0:
            raise RuntimeError("worker_no_new_privileges_failed")
        return {"platform":"linux_rlimit","memory_mb":limits.memory_mb,"cpu_seconds":limits.cpu_seconds,"open_file_limit":64}
    raise RuntimeError("worker_resource_platform_unsupported")
