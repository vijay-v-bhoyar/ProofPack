"""Additional original probes for wheel claims and copied installer phase boundaries."""
import hashlib
from pathlib import Path
import zipfile

import pytest

from test_host_install_bundle import inputs, replace_dependency
from test_host_install_execution import bundle, host_model


def test_mixed_windows_and_arm_tag_is_not_an_arm_only_artifact(inputs):
    m, plan, review, house, _ = inputs
    replace_dependency(plan, house, 'numpy', tag='cp312-cp312-manylinux_2_28_aarch64.win_amd64')
    with pytest.raises(ValueError): m.prepare(plan, review, house)


def test_missing_wheel_metadata_is_rejected_even_when_filename_is_compatible(inputs):
    m, plan, review, house, _ = inputs
    p = next(p for p in house.iterdir() if p.name.startswith('numpy-'))
    temporary = p.with_suffix('.tmp')
    with zipfile.ZipFile(p) as source, zipfile.ZipFile(temporary, 'w') as out:
        for info in source.infolist():
            if not info.filename.endswith('.dist-info/WHEEL'): out.writestr(info, source.read(info))
    temporary.replace(p); plan['wheels'][p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    with pytest.raises(ValueError): m.prepare(plan, review, house)


def test_changed_copy_after_venv_holds_before_pip(host_model, monkeypatch):
    m, directory, digest, root, calls, observed = host_model
    original = m._run
    def changed(command, timeout):
        result = original(command, timeout)
        if len(calls) == 1: (root / 'requirements.lock').write_text('changed after venv')
        return result
    monkeypatch.setattr(m, '_run', changed)
    with pytest.raises(ValueError): m.install(directory, digest)
    assert len(calls) == 1 and not (root / 'installation.json').exists()


def test_changed_copy_during_receipt_invalidates_only_owned_completion_marker(host_model, monkeypatch):
    m, directory, digest, root, calls, _ = host_model
    original = m._write_new
    def changed(path, data):
        original(path, data)
        if path.name == 'installation.json': (root / 'host.service').write_text('changed at completion')
    monkeypatch.setattr(m, '_write_new', changed)
    with pytest.raises(ValueError): m.install(directory, digest)
    assert len(calls) == 3 and not (root / 'installation.json').exists()
    assert (root / 'host.service').exists()
