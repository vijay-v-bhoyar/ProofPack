"""Synthetic host/process models; no privileged or Linux installation is executed."""
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_host_install_bundle import inputs as bundle_inputs


def module(): return importlib.import_module('install_host_bundle')


@pytest.fixture(scope='module')
def bundle(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('synthetic-host-bundle')
    builder, plan, review, house, _ = bundle_inputs.__wrapped__(tmp)
    original = builder.ROOT
    try:
        builder.ROOT = tmp
        out = tmp / 'bundle'; builder.write_bundle(plan, review, house, out)
    finally: builder.ROOT = original
    return out, hashlib.sha256((out / 'manifest.json').read_bytes()).hexdigest()


def test_real_windows_install_is_denied_before_bundle_read_or_effect(monkeypatch, tmp_path):
    m = module()
    assert sys.platform == 'win32', 'This oracle is explicitly the current Windows no-install boundary'
    monkeypatch.setattr(m, 'verify_bundle', lambda *a, **k: pytest.fail('must hold before reading bundle'))
    monkeypatch.setattr(m, 'INSTALL_ROOT', tmp_path / 'must-not-exist')
    with pytest.raises(ValueError): m.install(tmp_path / 'missing', 'a' * 64)
    assert not (tmp_path / 'must-not-exist').exists()


@pytest.mark.parametrize('reason', ['platform', 'architecture', 'python', 'implementation', 'uid', 'libc', 'old-libc', 'service-uid', 'service-gid'])
def test_host_prerequisites_are_explicit_and_fail_closed(monkeypatch, tmp_path, reason):
    m = module()
    monkeypatch.setattr(m.sys, 'platform', 'darwin' if reason == 'platform' else 'linux')
    monkeypatch.setattr(m.platform, 'machine', lambda: 'x86_64' if reason == 'architecture' else 'aarch64')
    monkeypatch.setattr(m.sys, 'version_info', (3, 13) if reason == 'python' else (3, 12))
    monkeypatch.setattr(m.sys, 'implementation', SimpleNamespace(name='pypy' if reason == 'implementation' else 'cpython'))
    monkeypatch.setattr(m.os, 'geteuid', lambda: 1000 if reason == 'uid' else 0, raising=False)
    monkeypatch.setattr(m.platform, 'libc_ver', lambda: ('musl', '1.2') if reason == 'libc' else ('glibc', '2.27' if reason == 'old-libc' else '2.28'))
    monkeypatch.setitem(sys.modules, 'pwd', SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=0 if reason == 'service-uid' else 1001, pw_gid=0 if reason == 'service-gid' else 1001)))
    monkeypatch.setattr(m, 'INSTALL_ROOT', tmp_path / 'fresh')
    monkeypatch.setattr(m, '_ordinary', lambda *a, **k: None)  # Host trust is synthetic in this model.
    with pytest.raises(ValueError): m._host_preflight()
    assert not (tmp_path / 'fresh').exists()


def test_verified_bundle_has_exact_payload_inventory(bundle):
    m = module(); directory, digest = bundle
    manifest, payloads = m.verify_bundle(directory, digest)
    assert set(payloads) == set(manifest['files'])
    assert payloads['install.py'] == Path(m.__file__).read_bytes()
    assert manifest['install_authorized'] is False


@pytest.mark.parametrize('change', ['hash', 'file', 'extra', 'wheel-extra', 'traversal'])
def test_changed_bundle_is_rejected(bundle, tmp_path, change):
    import shutil
    m = module(); directory, digest = bundle
    out = tmp_path / 'copy'; shutil.copytree(directory, out)
    if change == 'hash': digest = '0' * 64
    elif change == 'file': (out / 'requirements.lock').write_text('changed')
    elif change == 'extra': (out / 'credentials.json').write_text('never-echo-fixture')
    elif change == 'wheel-extra': (out / 'wheelhouse/extra.whl').write_bytes(b'extra')
    else:
        d = json.loads((out / 'manifest.json').read_text()); d['files']['../outside'] = 'a' * 64
        (out / 'manifest.json').write_text(json.dumps(d)); digest = hashlib.sha256((out / 'manifest.json').read_bytes()).hexdigest()
    with pytest.raises(ValueError): m.verify_bundle(out, digest)


@pytest.fixture
def host_model(bundle, tmp_path, monkeypatch):
    m = module(); directory, digest = bundle
    root = tmp_path / 'installed'; calls = []
    monkeypatch.setattr(m, 'INSTALL_ROOT', root)
    monkeypatch.setattr(m, '_host_preflight', lambda: None)  # NOT actual Linux/root/account acceptance.
    original_ordinary = m._ordinary
    monkeypatch.setattr(m, '_ordinary', lambda p, directory=False, **k: original_ordinary(p, directory=directory))
    original_read = m._read
    monkeypatch.setattr(m, '_read', lambda p, limit=m.MAX_FILE, **k: original_read(p, limit))  # Real bytes, synthetic host trust.
    report = json.loads((directory / 'report.json').read_text())
    plan = json.loads((directory / 'plan.json').read_text())
    observed = dict(artifact_sha256=plan['artifact_sha256'], backend_files=158, web_files=3, opencv='5.0.0.synthetic')
    def run(command, timeout):
        calls.append((command, timeout))
        return SimpleNamespace(stdout=json.dumps(observed).encode())
    monkeypatch.setattr(m, '_run', run)
    return m, directory, digest, root, calls, observed


def test_install_model_pins_offline_commands_and_does_not_install_or_start_service(host_model):
    m, directory, digest, root, calls, _ = host_model
    receipt = m.install(directory, digest)
    assert len(calls) == 3
    assert [c[1] for c in calls] == [60, 120, 30]
    assert calls[0][0] == [sys.executable, '-I', '-m', 'venv', '--copies', str(root / 'venv')]
    pip = calls[1][0]
    for flag in ['--isolated', '--no-index', '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-cache-dir', '--no-compile']:
        assert flag in pip
    assert calls[2][0][-1] == receipt['observation']['artifact_sha256']
    assert receipt['application_started'] is False and receipt['service_installed'] is False
    assert receipt['beta_decision'] == 'NO_GO'
    assert json.loads((root / 'installation.json').read_text()) == receipt
    assert {p.name for p in root.iterdir()} == {'host.service', 'requirements.lock', 'wheelhouse', 'installation.json'}
    assert not any('systemctl' in ' '.join(c[0]) for c in calls)


@pytest.mark.parametrize('phase', [0, 1, 2])
def test_phase_failure_preserves_partial_install_without_receipt_or_retry(host_model, monkeypatch, phase):
    m, directory, digest, root, calls, _ = host_model
    def failed(command, timeout):
        calls.append((command, timeout))
        if len(calls) == phase + 1: raise subprocess.TimeoutExpired(command, timeout)
        return SimpleNamespace(stdout=b'{}')
    monkeypatch.setattr(m, '_run', failed)
    with pytest.raises(subprocess.TimeoutExpired): m.install(directory, digest)
    assert len(calls) == phase + 1
    assert (root / 'requirements.lock').exists() and not (root / 'installation.json').exists()
    with pytest.raises(FileExistsError): m.install(directory, digest)
    assert len(calls) == phase + 1


def test_bad_native_observation_cannot_write_installation_receipt(host_model):
    m, directory, digest, root, calls, observed = host_model
    observed['artifact_sha256'] = 'f' * 64
    with pytest.raises(ValueError): m.install(directory, digest)
    assert len(calls) == 3 and not (root / 'installation.json').exists()


def test_copied_wheel_mutation_holds_before_any_subprocess(host_model, monkeypatch):
    m, directory, digest, root, calls, _ = host_model
    original = m._write_new
    def changed(path, data):
        original(path, data)
        if path.parent.name == 'wheelhouse': path.write_bytes(b'changed-copy')
    monkeypatch.setattr(m, '_write_new', changed)
    with pytest.raises(ValueError): m.install(directory, digest)
    assert calls == [] and not (root / 'installation.json').exists()


def test_subprocess_environment_does_not_inherit_credentials_or_python_overrides(monkeypatch, tmp_path):
    m = module(); calls = []
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'never-echo-fixture')
    monkeypatch.setenv('PYTHONPATH', 'untrusted-fixture'); monkeypatch.setenv('PIP_INDEX_URL', 'https://example.invalid')
    monkeypatch.setattr(m, 'INSTALL_ROOT', tmp_path)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: calls.append((a, k)))
    m._run(['/fixed/python', '-I'], 30)
    env = calls[0][1]['env']
    assert not {'AWS_SECRET_ACCESS_KEY', 'PYTHONPATH', 'PIP_INDEX_URL', 'HTTP_PROXY'} & env.keys()
    assert env['AWS_EC2_METADATA_DISABLED'] == 'true'
    assert calls[0][1]['timeout'] == 30 and calls[0][1]['check'] is True


def test_installer_cli_denial_is_sanitized(monkeypatch, capsys):
    m = module()
    def denied(*a): raise ValueError('never-echo-fixture')
    monkeypatch.setattr(m, 'install', denied)
    assert m.main(['--bundle-sha256', 'a' * 64]) == 2
    output = capsys.readouterr()
    assert not output.out and 'INSTALL_HELD' in output.err and 'never-echo-fixture' not in output.err
