"""Named service-group consistency on a synthetic host; no account or host mutations."""
import importlib
import sys
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize('kind', ['missing', 'different', 'root', 'matching'])
def test_service_unit_named_group_must_match_existing_service_account(monkeypatch, tmp_path, kind):
    m = importlib.import_module('install_host_bundle')
    monkeypatch.setattr(m.sys, 'platform', 'linux')
    monkeypatch.setattr(m.platform, 'machine', lambda: 'aarch64')
    monkeypatch.setattr(m.platform, 'libc_ver', lambda: ('glibc', '2.28'))
    monkeypatch.setattr(m.sys, 'implementation', SimpleNamespace(name='cpython'))
    monkeypatch.setattr(m.sys, 'version_info', (3, 12))
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setitem(sys.modules, 'pwd', SimpleNamespace(getpwnam=lambda n: SimpleNamespace(pw_uid=1001, pw_gid=1001)))
    def group(name):
        assert name == 'proofpack'
        if kind == 'missing': raise KeyError('missing service group')
        return SimpleNamespace(gr_gid={'different': 1002, 'root': 0, 'matching': 1001}[kind])
    monkeypatch.setitem(sys.modules, 'grp', SimpleNamespace(getgrnam=group))
    monkeypatch.setattr(m, '_ordinary', lambda *a, **k: None)  # Explicit synthetic host trust.
    monkeypatch.setattr(m, 'INSTALL_ROOT', tmp_path / 'not-created')
    if kind == 'matching':
        assert m._host_preflight() is None
    else:
        with pytest.raises((ValueError, KeyError)): m._host_preflight()
    assert not (tmp_path / 'not-created').exists()
