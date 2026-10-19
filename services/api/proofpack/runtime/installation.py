"""Bounded local bytes-to-approved-wheel check; no host or loaded-code attestation."""
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import os
from pathlib import Path
import re
import stat
from time import monotonic_ns
import zipfile

from proofpack import __version__
from proofpack.runtime.public_web import FrozenWeb

MAX_ARCHIVE_BYTES=32*1024*1024
MAX_EXPANDED_BYTES=32*1024*1024
MAX_FILE_BYTES=4*1024*1024
MAX_MEMBERS=1024
MAX_VISITS=2048
MAX_DIRECTORIES=128
MAX_VALIDATION_NS=5_000_000_000
METADATA_FILES=frozenset({'METADATA','WHEEL','entry_points.txt','top_level.txt','RECORD'})


class InstallationUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallationConfig:
    wheel_path:str

    def __post_init__(self):
        value=self.wheel_path
        if (type(value) is not str or not 1<=len(value)<=1024 or '\x00' in value
                or value.startswith(('//','\\\\')) or not Path(value).is_absolute()
                or '..' in Path(value).parts or Path(value).suffix!='.whl'):
            raise ValueError('absolute local approved wheel path required')


@dataclass(frozen=True)
class InstallationObservation:
    artifact_sha256:str
    backend_files:int
    web_files:int
    authority:str='none'


def _identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def _ordinary(path,*,directory=False):
    # Keep the lexical path: resolve() would conceal links before inspection.
    current=path
    for _ in range(128):
        value=current.lstat()
        if (stat.S_ISLNK(value.st_mode) or getattr(value,'st_file_attributes',0)&0x400
                or getattr(current,'is_junction',lambda:False)()):
            raise ValueError('linked installation path')
        if current==path:
            if not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
                raise ValueError('ordinary installation path required')
            original=_identity(value)
        elif not stat.S_ISDIR(value.st_mode):raise ValueError('ordinary parent directory required')
        if current.parent==current:return original
        current=current.parent
    raise ValueError('installation path depth exceeded')


def _read(path,limit,checkpoint):
    checkpoint();identity=_ordinary(path)
    if not 0<identity[3]<=limit:raise ValueError('bounded complete installation file required')
    with path.open('rb') as stream:
        opened=_identity(os.fstat(stream.fileno()))
        # Windows lstat and CRT fstat report different ctime meanings. Pin each
        # independently; compare common device/inode/mode/size/mtime across APIs.
        if opened[:5]!=identity[:5]:raise ValueError('changed open file')
        content=stream.read(limit+1);checkpoint()
        if len(content)!=identity[3] or _identity(os.fstat(stream.fileno()))!=opened:
            raise ValueError('changed file contents')
    if _ordinary(path)!=identity:raise ValueError('changed file path')
    return content,identity


def _inventory(root,checkpoint,*,backend=False):
    files={};directories={};pending=[(root,0)];visits=0;total=0;aliases=set()
    while pending:
        directory,depth=pending.pop();checkpoint()
        if depth>8 or len(directories)>=MAX_DIRECTORIES:raise ValueError('directory bound exceeded')
        directories[directory]=_ordinary(directory,directory=True)
        with os.scandir(directory) as entries:
            for entry in entries:
                visits+=1;checkpoint()
                if visits>MAX_VISITS:raise ValueError('directory entry bound exceeded')
                path=Path(entry.path);relative=path.relative_to(root).as_posix()
                if len(relative)>160 or re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',path.name) is None:
                    raise ValueError('unsupported installation name')
                alias=relative.casefold()
                if alias in aliases:raise ValueError('ambiguous installation name')
                aliases.add(alias)
                value=path.lstat()
                if stat.S_ISDIR(value.st_mode):
                    _ordinary(path,directory=True)
                    if path.name=='__pycache__':continue
                    if backend and path==root/'web':continue
                    pending.append((path,depth+1))
                else:
                    identity=_ordinary(path)
                    if backend and path.suffix!='.py':raise ValueError('unexpected backend payload')
                    if not 0<identity[3]<=MAX_FILE_BYTES:raise ValueError('installation file bound exceeded')
                    total+=identity[3]
                    if len(files)>=MAX_MEMBERS or total>MAX_EXPANDED_BYTES:raise ValueError('installation inventory bound exceeded')
                    files[relative]=(path,identity)
    return files,directories


def verify_installation(config,artifact_sha256,*,frozen_web=None,tick_ns=None):
    """No I/O until invoked; expected identity comes only from configured release SHA."""
    try:
        if type(config) is not InstallationConfig or type(artifact_sha256) is not str or re.fullmatch('[a-f0-9]{64}',artifact_sha256) is None:
            raise ValueError('typed installation and exact artifact identity required')
        tick=monotonic_ns if tick_ns is None else tick_ns
        started=tick();last=started
        if type(started) is not int or not 0<=started<2**63-MAX_VALIDATION_NS:raise ValueError('bounded validation clock required')
        def checkpoint():
            nonlocal last
            now=tick()
            if type(now) is not int or not last<=now<started+MAX_VALIDATION_NS:raise ValueError('original installation deadline held')
            last=now
        wheel=Path(config.wheel_path);checkpoint();wheel_identity=_ordinary(wheel)
        if not 0<wheel_identity[3]<=MAX_ARCHIVE_BYTES:raise ValueError('bounded wheel required')
        package=Path(__file__).absolute().parents[1]
        packaged=package/'web'
        web=packaged if packaged.exists() else package.parents[2]/'apps/web/dist'
        backend,backend_dirs=_inventory(package,checkpoint,backend=True)
        assets,web_dirs=_inventory(web,checkpoint)
        if any(n!='index.html' and re.fullmatch(r'assets/[A-Za-z0-9_-]{1,100}\.(js|css)',n) is None for n in assets):
            raise ValueError('flat supported web inventory required')
        local={'proofpack/'+n:v for n,v in backend.items()}|{'proofpack/web/'+n:v for n,v in assets.items()}
        if not {'proofpack/__init__.py','proofpack/runtime/installation.py','proofpack/web/index.html'}<=local.keys():
            raise ValueError('complete application installation required')
        metadata_prefix='proofpack-'+__version__+'.dist-info/'
        with wheel.open('rb') as stream:
            opened_wheel=_identity(os.fstat(stream.fileno()))
            if opened_wheel[:5]!=wheel_identity[:5]:raise ValueError('changed wheel handle')
            digest=hashlib.sha256();remaining=wheel_identity[3]
            while remaining:
                checkpoint();block=stream.read(min(65536,remaining))
                if not block:raise ValueError('incomplete wheel')
                digest.update(block);remaining-=len(block)
            checkpoint()
            if stream.read(1) or digest.hexdigest()!=artifact_sha256:raise ValueError('wheel identity mismatch')
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                infos=archive.infolist()
                if not 1<=len(infos)<=MAX_MEMBERS:raise ValueError('wheel member bound exceeded')
                names=set();aliases=set();expanded=0
                for info in infos:
                    checkpoint();name=info.filename;mode=info.external_attr>>16
                    if (info.orig_filename!=name or '\x00' in name or '\\' in name or ':' in name
                            or len(name)>200 or name.startswith('/') or any(p in {'','..','.'} for p in name.split('/'))
                            or name in names or name.casefold() in aliases or info.is_dir() or info.flag_bits&1
                            or stat.S_IFMT(mode) not in {0,stat.S_IFREG}
                            or info.compress_type not in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED}
                            or not 0<info.file_size<=MAX_FILE_BYTES):
                        raise ValueError('unsupported wheel member')
                    names.add(name);aliases.add(name.casefold());expanded+=info.file_size
                    if expanded>MAX_EXPANDED_BYTES:raise ValueError('expanded wheel bound exceeded')
                expected=set(local)|{metadata_prefix+n for n in METADATA_FILES}
                if names!=expected:raise ValueError('wheel inventory mismatch')
                observed_web={}
                for name,(path,identity) in local.items():
                    checkpoint();content,current=_read(path,MAX_FILE_BYTES,checkpoint)
                    if current!=identity or archive.read(name)!=content:raise ValueError('application member differs from approved wheel')
                    if name.startswith('proofpack/web/'):
                        relative=name.removeprefix('proofpack/web/')
                        observed_web['/' if relative=='index.html' else '/'+relative]=hashlib.sha256(content).hexdigest()
                for name in ('METADATA','WHEEL'):
                    if archive.getinfo(metadata_prefix+name).file_size>65536:raise ValueError('bounded package metadata required')
                metadata=BytesParser().parsebytes(archive.read(metadata_prefix+'METADATA'))
                if metadata.get_all('Name')!=['proofpack'] or metadata.get_all('Version')!=[__version__]:
                    raise ValueError('package metadata differs')
                wheel_metadata=BytesParser().parsebytes(archive.read(metadata_prefix+'WHEEL'))
                if (wheel_metadata.get_all('Wheel-Version')!=['1.0'] or wheel_metadata.get_all('Root-Is-Purelib')!=['true']
                        or wheel_metadata.get_all('Tag')!=['py3-none-any']):raise ValueError('unsupported wheel layout')
            checkpoint()
            if _identity(os.fstat(stream.fileno()))!=opened_wheel:raise ValueError('changed wheel')
        if _ordinary(wheel)!=wheel_identity:raise ValueError('changed wheel path')
        if _inventory(package,checkpoint,backend=True)!=(backend,backend_dirs) or _inventory(web,checkpoint)!=(assets,web_dirs):
            raise ValueError('installation changed during validation')
        if frozen_web is not None:
            if type(frozen_web) is not FrozenWeb or {a.path:a.sha256 for a in frozen_web.assets}!=observed_web:
                raise ValueError('served snapshot differs from approved installation')
        checkpoint()
        return InstallationObservation(artifact_sha256,len(backend),len(assets))
    except Exception:
        raise InstallationUnavailable('Local installation verification failed; no startup authority was granted.') from None
