"""Declared patch closure and before-effect host binding; process/host truth stays synthetic."""
from collections import namedtuple
import hashlib
import json
import shutil

import pytest

from test_host_install_bundle import inputs, replace_dependency
from test_host_install_execution import bundle, host_model


def test_explicit_python_patch_handles_observed_cryptography_marker_without_inventing_host_facts(inputs):
    m, plan, review, house, _ = inputs
    plan['python_full_version'] = '3.12.15'
    replace_dependency(plan, house, 'cryptography', requires=[
        "cffi>=2.0.0; platform_python_implementation != 'PyPy'",
        "typing-extensions>=4.13.2; python_full_version < '3.11'",
    ])
    result = m.prepare(plan, review, house)
    assert result['report.json']['python_full_version'] == '3.12.15'
    assert json.loads(result['plan.json'])['python_full_version'] == '3.12.15'
    assert result['report.json']['native_arm_installation'] == 'NOT_RUN'
    assert result['report.json']['install_authorized'] is False


def test_implementation_patch_uses_same_explicit_target(inputs):
    m, plan, review, house, _ = inputs
    plan['python_full_version'] = '3.12.15'
    replace_dependency(plan, house, 'numpy', requires=["never-supplied; implementation_version < '3.12.0'"])
    assert m.prepare(plan, review, house)['report.json']['python_full_version'] == '3.12.15'


def test_active_patch_dependency_must_exist_in_exact_closure(inputs):
    m, plan, review, house, _ = inputs
    plan['python_full_version'] = '3.12.15'
    replace_dependency(plan, house, 'numpy', requires=["never-supplied; python_full_version > '3.12.0'"])
    with pytest.raises(ValueError, match='complete compatible dependency closure'):
        m.prepare(plan, review, house)


@pytest.mark.parametrize('target,allowed', [('3.12.15', True), ('3.12.9', False)])
def test_requires_python_is_checked_at_declared_patch(inputs, target, allowed):
    m, plan, review, house, _ = inputs
    plan['python_full_version'] = target
    replace_dependency(plan, house, 'numpy', python='>=3.12.10,<3.13')
    if allowed:
        assert m.prepare(plan, review, house)['report.json']['python_full_version'] == target
    else:
        with pytest.raises(ValueError, match='Python3.12'):
            m.prepare(plan, review, house)


@pytest.mark.parametrize('target', [None, True, 3.12, '3.12', '3.13.0', '3.12.015', '3.12.15rc1', '3.12.-1', '3.12.10000'])
def test_invalid_or_noncanonical_patch_never_becomes_a_host_default(inputs, target):
    m, plan, review, house, _ = inputs
    plan['python_full_version'] = target
    with pytest.raises(ValueError): m.prepare(plan, review, house)


@pytest.mark.parametrize('marker', ["platform_release == '6.1'", "platform_version == 'release'"])
def test_python_patch_does_not_supply_unknown_kernel_facts(inputs, marker):
    m, plan, review, house, _ = inputs
    plan['python_full_version'] = '3.12.15'
    replace_dependency(plan, house, 'numpy', requires=['never-supplied; ' + marker])
    with pytest.raises(ValueError, match='kernel marker'):
        m.prepare(plan, review, house)


def explicit_host(host_model, tmp_path, monkeypatch, *, host='3.12.15', level='final', child='3.12.15'):
    m, directory, _, root, calls, observed = host_model
    target = tmp_path / 'explicit-bundle'; shutil.copytree(directory, target)
    plan = json.loads((target / 'plan.json').read_text()); plan['python_full_version'] = '3.12.15'
    (target / 'plan.json').write_bytes(m._json(plan))
    report = json.loads((target / 'report.json').read_text()); report['python_full_version'] = '3.12.15'
    (target / 'report.json').write_bytes(m._json(report))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = json.loads((target / 'manifest.json').read_text())
    manifest['files']['plan.json'] = sha(target / 'plan.json')
    manifest['files']['report.json'] = sha(target / 'report.json')
    manifest['plan_sha256'] = sha(target / 'plan.json')
    (target / 'manifest.json').write_bytes(m._json(manifest))
    version = namedtuple('Version', 'major minor micro releaselevel serial')(*map(int, host.split('.')), level, 0)
    monkeypatch.setattr(m.sys, 'version_info', version)
    observed['python_full_version'] = child
    return m, target, sha(target / 'manifest.json'), root, calls


def test_host_patch_mismatch_holds_before_directory_or_subprocess(host_model, tmp_path, monkeypatch):
    m, directory, digest, root, calls = explicit_host(host_model, tmp_path, monkeypatch, host='3.12.14')
    with pytest.raises(ValueError): m.install(directory, digest)
    assert not root.exists() and calls == []


def test_matching_final_host_and_native_patch_are_recorded_without_startup(host_model, tmp_path, monkeypatch):
    m, directory, digest, root, calls = explicit_host(host_model, tmp_path, monkeypatch)
    result = m.install(directory, digest)
    assert result['expected_python_full_version'] == '3.12.15'
    assert result['observation']['python_full_version'] == '3.12.15'
    assert result['application_started'] is False and result['service_installed'] is False
    assert len(calls) == 3 and (root / 'installation.json').exists()


def test_native_child_patch_mismatch_cannot_write_receipt(host_model, tmp_path, monkeypatch):
    m, directory, digest, root, calls = explicit_host(host_model, tmp_path, monkeypatch, child='3.12.14')
    with pytest.raises(ValueError): m.install(directory, digest)
    assert len(calls) == 3 and not (root / 'installation.json').exists()


def test_prerelease_host_cannot_satisfy_a_final_patch_plan(host_model, tmp_path, monkeypatch):
    m, directory, digest, root, calls = explicit_host(host_model, tmp_path, monkeypatch, level='candidate')
    with pytest.raises(ValueError): m.install(directory, digest)
    assert not root.exists() and calls == []
