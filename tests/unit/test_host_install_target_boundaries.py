"""Malformed reviewed JSON cannot escape sanitized before-effect installation holds."""
import hashlib
import json
import shutil

import pytest

from test_host_install_execution import bundle, host_model
from test_host_install_python_target import explicit_host


def rewrite_report(m, directory, value):
    path = directory / 'report.json'; path.write_bytes(m._json(value))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest_path = directory / 'manifest.json'
    manifest = json.loads(manifest_path.read_text()); manifest['files']['report.json'] = sha(path)
    manifest_path.write_bytes(m._json(manifest))
    return sha(manifest_path)


@pytest.mark.parametrize('report', [None, [], 'private-fixture-do-not-echo', True])
def test_wrong_report_shape_returns_sanitized_cli_hold_before_effect(host_model, tmp_path, monkeypatch, capsys, report):
    m, original, _, root, calls, _ = host_model
    directory = tmp_path / 'malformed'; shutil.copytree(original, directory)
    digest = rewrite_report(m, directory, report)
    monkeypatch.setattr(m, '__file__', str(directory / 'install.py'))
    assert m.main(['--bundle-sha256', digest]) == 2
    output = capsys.readouterr()
    assert not output.out and 'INSTALL_HELD' in output.err
    assert 'private-fixture-do-not-echo' not in output.err
    assert not root.exists() and calls == []


def test_report_patch_disagreement_holds_before_effect(host_model, tmp_path, monkeypatch, capsys):
    m, directory, _, root, calls = explicit_host(host_model, tmp_path, monkeypatch)
    report = json.loads((directory / 'report.json').read_text()); report['python_full_version'] = '3.12.14'
    digest = rewrite_report(m, directory, report)
    monkeypatch.setattr(m, '__file__', str(directory / 'install.py'))
    assert m.main(['--bundle-sha256', digest]) == 2
    output = capsys.readouterr()
    assert not output.out and 'INSTALL_HELD' in output.err
    assert not root.exists() and calls == []
