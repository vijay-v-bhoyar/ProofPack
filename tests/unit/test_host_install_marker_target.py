"""Unspecified target patch/kernel facts cannot silently select dependency closure."""
import pytest

from test_host_install_bundle import inputs, replace_dependency


@pytest.mark.parametrize('marker', [
    'python_full_version > "3.12.0"',
    'implementation_version > "3.12.0"',
    'platform_release == "6.1"',
    'platform_version == "release"',
])
def test_unknown_patch_or_kernel_marker_holds_before_any_install_bundle(inputs, marker):
    m, plan, review, house, _ = inputs
    replace_dependency(plan, house, 'numpy', requires=['never-supplied; ' + marker])
    with pytest.raises(ValueError): m.prepare(plan, review, house)
