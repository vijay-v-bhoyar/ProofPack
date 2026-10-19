"""Real compressed-tag compatibility and bounded CLI checks, using fake dependency payloads."""
import json

import pytest

from test_host_install_bundle import inputs, replace_dependency


def test_py2_py3_universal_wheel_is_compatible_without_accepting_foreign_native_tags(inputs):
    m, plan, review, house, _ = inputs
    replace_dependency(plan, house, 'six', tag='py2.py3-none-any')
    assert m.prepare(plan, review, house)['report.json']['status'] == 'PREPARED_INSTALL_REVIEW'


@pytest.mark.parametrize('which', ['wheel-count', 'file-size', 'total-size'])
def test_bound_is_checked_before_bundle_output(inputs, monkeypatch, which):
    m, plan, review, house, _ = inputs
    monkeypatch.setattr(m, {'wheel-count': 'MAX_WHEELS', 'file-size': 'MAX_FILE', 'total-size': 'MAX_TOTAL'}[which], 1)
    with pytest.raises(ValueError): m.prepare(plan, review, house)


@pytest.mark.parametrize('raw', ['{"schema_version":1,"schema_version":1}', '{"schema_version":NaN}'])
def test_cli_rejects_duplicate_and_nonfinite_json_without_private_echo(tmp_path, raw, capsys):
    import prepare_host_install as m
    p = tmp_path / 'private-fixture.json'; p.write_text(raw)
    out = tmp_path / 'must-not-exist'
    assert m.main(['--plan', str(p), '--review', str(tmp_path / 'missing'), '--wheelhouse', str(tmp_path / 'missing'), '--output', str(out)]) == 2
    captured = capsys.readouterr()
    assert not out.exists() and not captured.out
    assert 'INSTALL_BUNDLE_HELD' in captured.err and str(p) not in captured.err and raw not in captured.err
