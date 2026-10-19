"""Explicit fresh Linux ARM installation only; never installs/starts a service."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys

INSTALL_ROOT = Path('/opt/proofpack')
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
BASE_FILES = {'install.py', 'plan.json', 'report.json', 'requirements.lock', 'host.service',
              'operator-handoff.md', 'review-manifest.json'}


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('duplicate field')
        result[key] = value
    return result


def _decode(data):
    return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def _ordinary(path, *, directory=False, trusted=False):
    current = path
    for _ in range(128):
        s = current.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
            raise ValueError('linked input')
        if current == path:
            if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
                raise ValueError('ordinary input required')
            original = (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        elif not stat.S_ISDIR(s.st_mode): raise ValueError('ordinary parent required')
        if trusted and (s.st_uid != 0 or s.st_mode & 0o022):
            raise ValueError('root-owned nonwritable trust path required')
        if current.parent == current: return original
        current = current.parent
    raise ValueError('path bound exceeded')


def _read(path, limit=MAX_FILE, *, trusted=False):
    before = _ordinary(path, trusted=trusted)
    if not 0 < before[3] <= limit: raise ValueError('bounded input required')
    with path.open('rb') as stream:
        s = os.fstat(stream.fileno())
        identity = (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity[:5] != before[:5]: raise ValueError('input changed at open')
        data = stream.read(limit + 1)
        s = os.fstat(stream.fileno())
        if len(data) != before[3] or (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns) != identity:
            raise ValueError('input changed during read')
    if _ordinary(path, trusted=trusted) != before: raise ValueError('input path changed')
    return data


def _write_new(path, data):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def _python_target(plan):
    if 'python_full_version' not in plan: return None
    value = plan['python_full_version']
    if type(value) is not str or re.fullmatch(r'3\.12\.(0|[1-9][0-9]{0,3})', value) is None:
        raise ValueError('canonical final CPython3.12 patch required')
    return value


def _verify_python_target(plan):
    expected = _python_target(plan)
    if expected is not None and (tuple(map(int, expected.split('.'))) != sys.version_info[:3]
            or getattr(sys.version_info, 'releaselevel', None) != 'final'):
        raise ValueError('host CPython final patch differs from reviewed plan')
    return expected


def verify_bundle(directory, expected_sha256, *, trusted=False):
    if type(expected_sha256) is not str or re.fullmatch('[a-f0-9]{64}', expected_sha256) is None:
        raise ValueError('exact reviewed manifest SHA required')
    directory = Path(directory).absolute()
    _ordinary(directory, directory=True, trusted=trusted)
    raw = _read(directory / 'manifest.json', 65536, trusted=trusted)
    if hashlib.sha256(raw).hexdigest() != expected_sha256: raise ValueError('bundle identity mismatch')
    manifest = _decode(raw)
    if (type(manifest) is not dict or set(manifest) != {'schema_version', 'status', 'files', 'plan_sha256', 'install_authorized', 'beta_decision'}
            or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1
            or manifest['status'] != 'PREPARED_INSTALL_REVIEW' or manifest['install_authorized'] is not False
            or manifest['beta_decision'] != 'NO_GO' or type(manifest['files']) is not dict
            or not 8 <= len(manifest['files']) <= 71):
        raise ValueError('closed review bundle required')
    names = set(manifest['files'])
    if not BASE_FILES <= names: raise ValueError('complete bundle required')
    wheels = names - BASE_FILES
    if not 1 <= len(wheels) <= 64 or any(re.fullmatch(r'wheelhouse/[A-Za-z0-9_.+-]{1,180}\.whl', n) is None for n in wheels):
        raise ValueError('closed wheel inventory required')
    _ordinary(directory / 'wheelhouse', directory=True, trusted=trusted)
    if {p.name for p in directory.iterdir()} != BASE_FILES | {'manifest.json', 'wheelhouse'}:
        raise ValueError('unexpected bundle root')
    if {'wheelhouse/' + p.name for p in (directory / 'wheelhouse').iterdir()} != wheels:
        raise ValueError('unexpected wheelhouse contents')
    payloads = {}; total = 0
    for name in sorted(names):
        expected = manifest['files'][name]
        if type(expected) is not str or re.fullmatch('[a-f0-9]{64}', expected) is None:
            raise ValueError('exact file SHA required')
        data = _read(directory / name, MAX_FILE if name in wheels else 1024 * 1024, trusted=trusted)
        total += len(data)
        if total > MAX_TOTAL or hashlib.sha256(data).hexdigest() != expected: raise ValueError('bundle file mismatch')
        payloads[name] = data
    if hashlib.sha256(payloads['plan.json']).hexdigest() != manifest['plan_sha256']:
        raise ValueError('plan identity mismatch')
    return manifest, payloads


def _host_preflight():
    if (sys.platform != 'linux' or platform.machine() != 'aarch64'
            or sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 12)
            or not hasattr(os, 'geteuid') or os.geteuid() != 0):
        raise ValueError('root Linux ARM CPython3.12 host required')
    libc, version = platform.libc_ver()
    if libc != 'glibc' or re.fullmatch(r'[0-9]+\.[0-9]+', version) is None or tuple(map(int, version.split('.'))) < (2, 28):
        raise ValueError('glibc2.28 or newer required')
    import pwd
    account = pwd.getpwnam('proofpack')
    if account.pw_uid <= 0 or account.pw_gid <= 0: raise ValueError('existing unprivileged service account required')
    import grp
    group = grp.getgrnam('proofpack')
    if group.gr_gid <= 0 or group.gr_gid != account.pw_gid:
        raise ValueError('named service group must match unprivileged account')
    _ordinary(INSTALL_ROOT.parent, directory=True, trusted=True)
    if INSTALL_ROOT.exists() or INSTALL_ROOT.is_symlink(): raise FileExistsError('fresh install only')


def _run(command, timeout):
    # No inherited credentials, proxies, PYTHONPATH, HOME, pip index or startup options.
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
           'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_CONFIG_FILE': '/dev/null',
           'AWS_SHARED_CREDENTIALS_FILE': '/dev/null'}
    return subprocess.run(command, cwd=INSTALL_ROOT, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)


VERIFY = '''import json,sys
from pathlib import Path
import cv2
from importlib.metadata import distribution
from proofpack.runtime.installation import InstallationConfig,verify_installation
wheel,expected=sys.argv[1:]
observed=verify_installation(InstallationConfig(wheel),expected)
assert cv2.__version__.split('.')[0]=='5'
entry=[e for e in distribution('proofpack').entry_points if e.group=='console_scripts' and e.name=='proofpack']
assert len(entry)==1 and entry[0].value=='proofpack.runtime.host:main'
print(json.dumps(dict(artifact_sha256=observed.artifact_sha256,backend_files=observed.backend_files,web_files=observed.web_files,opencv=cv2.__version__,python_full_version='.'.join(map(str,sys.version_info[:3])))))
'''


def install(directory, expected_sha256):
    _host_preflight()
    manifest, payloads = verify_bundle(directory, expected_sha256, trusted=True)
    # Bind the actually running installer, not just a second file with its name.
    if _read(Path(__file__).absolute(), 1024 * 1024, trusted=True) != payloads['install.py']:
        raise ValueError('running installer differs from reviewed bundle')
    plan = _decode(payloads['plan.json']); report = _decode(payloads['report.json'])
    if type(plan) is not dict or type(report) is not dict:
        raise ValueError('plan and report must be JSON objects')
    expected_python = _verify_python_target(plan)
    if report.get('python_full_version') != expected_python:
        raise ValueError('report and plan Python target differ')
    app = report['application_wheel']
    if app not in plan['wheels'] or plan['wheels'][app] != plan['artifact_sha256']:
        raise ValueError('application artifact mismatch')
    # All effects follow complete validation. Never remove or reuse an incomplete directory.
    old_mask = os.umask(0o022)
    try:
        INSTALL_ROOT.mkdir(mode=0o755, exist_ok=False)
        (INSTALL_ROOT / 'wheelhouse').mkdir(mode=0o755)
        for name in sorted(payloads):
            if name.startswith('wheelhouse/') or name in {'requirements.lock', 'host.service'}:
                _write_new(INSTALL_ROOT / name, payloads[name])
        copied = {n: data for n, data in payloads.items()
                  if n.startswith('wheelhouse/') or n in {'requirements.lock', 'host.service'}}
        def verify_copies():
            if any(_read(INSTALL_ROOT / name, MAX_FILE, trusted=True) != data for name, data in copied.items()):
                raise ValueError('installed input copy changed')
        verify_copies()
        _run([sys.executable, '-I', '-m', 'venv', '--copies', str(INSTALL_ROOT / 'venv')], 60)
        verify_copies()
        python = str(INSTALL_ROOT / 'venv/bin/python')
        _run([python, '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install',
              '--no-index', '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-cache-dir',
              '--no-compile', '--find-links', str(INSTALL_ROOT / 'wheelhouse'), '-r', str(INSTALL_ROOT / 'requirements.lock')], 120)
        verify_copies()
        observed = _decode(_run([python, '-I', '-B', '-c', VERIFY,
                                str(INSTALL_ROOT / 'wheelhouse' / app), plan['artifact_sha256']], 30).stdout)
        if observed['artifact_sha256'] != plan['artifact_sha256'] or observed['backend_files'] + observed['web_files'] != report['runtime_members']:
            raise ValueError('installed runtime mismatch')
        if expected_python is not None and observed.get('python_full_version') != expected_python:
            raise ValueError('native child Python patch differs from reviewed plan')
        receipt = dict(schema_version=1, status='INSTALLED_LOCAL_NATIVE_IMPORT_ONLY',
            bundle_sha256=expected_sha256, observation=observed, application_started=False,
            service_installed=False, deploy_authorized=False, beta_decision='NO_GO',
            expected_python_full_version=expected_python)
        verify_copies()
        marker = INSTALL_ROOT / 'installation.json'; encoded = _json(receipt)
        try:
            _write_new(marker, encoded)
            if _read(marker, 65536, trusted=True) != encoded: raise ValueError('installation receipt changed')
            verify_copies()
        except BaseException:
            marker.unlink(missing_ok=True)
            raise
        return receipt
    finally:
        os.umask(old_mask)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Fresh fixed-path Linux ARM install; no service/config/enrollment/start')
    parser.add_argument('--bundle-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        result = install(Path(__file__).absolute().parent, args.bundle_sha256)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('INSTALL_HELD: inspect retained partial installation; no retry, cleanup, service or readiness implied', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
