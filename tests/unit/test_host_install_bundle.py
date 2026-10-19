"""Synthetic metadata is never an ARM binary or privileged-host acceptance proof."""
import hashlib
import importlib
import io
import json
from pathlib import Path
import shutil
import zipfile

import pytest

W = Path(__file__).resolve().parents[2]
APP = W / '.runtime/dist/proofpack-0.1.0-py3-none-any.whl'


def module():
    return importlib.import_module('prepare_host_install')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wheel(name, version='1.0', *, tag='py3-none-any', requires=(), extra=(), python='>=3.12,<3.13', entries=None):
    normalized = name.replace('-', '_')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        prefix = f'{normalized}-{version}.dist-info/'
        metadata = f'Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nRequires-Python: {python}\n'
        metadata += ''.join(f'Requires-Dist: {r}\n' for r in requires)
        metadata += ''.join(f'Provides-Extra: {e}\n' for e in extra)
        z.writestr(prefix + 'METADATA', metadata)
        z.writestr(prefix + 'WHEEL', f'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n')
        z.writestr(prefix + 'RECORD', '')
        for key, data in (entries or {normalized + '/__init__.py': '# synthetic only\n'}).items():
            z.writestr(key, data)
    return f'{normalized}-{version}-{tag}.whl', output.getvalue()


@pytest.fixture
def inputs(tmp_path):
    m = module()
    review = tmp_path / 'review'
    import prepare_aws_review as deployment
    review_plan = json.loads((W / '.loop/repairs/aws-review-pack/synthetic-plan-v1.json').read_text())
    review_plan['artifact_sha256'] = digest(APP.read_bytes())
    original_root = deployment.ROOT
    try:
        deployment.ROOT = tmp_path  # Isolated fixture output only; all target values remain synthetic.
        deployment.write_pack(review_plan, review)
    finally:
        deployment.ROOT = original_root
    house = tmp_path / 'wheelhouse'; house.mkdir()
    shutil.copyfile(APP, house / APP.name)
    # These are fake pure metadata fixtures, not actual dependencies or installable CV proof.
    from email.parser import BytesParser
    from packaging.requirements import Requirement
    with zipfile.ZipFile(APP) as z:
        meta = BytesParser().parsebytes(z.read('proofpack-0.1.0.dist-info/METADATA'))
    for raw in meta.get_all('Requires-Dist', []):
        req = Requirement(raw)
        version = next(iter(req.specifier)).version
        name, data = wheel(req.name, version)
        (house / name).write_bytes(data)
    plan = dict(schema_version=1, review_manifest_sha256=digest((review / 'manifest.json').read_bytes()),
                artifact_sha256=digest(APP.read_bytes()),
                wheels={p.name: digest(p.read_bytes()) for p in sorted(house.iterdir())})
    return m, plan, review, house, tmp_path


def replace_dependency(plan, house, name, **kwargs):
    from packaging.utils import parse_wheel_filename, canonicalize_name
    matches = [p for p in house.iterdir() if parse_wheel_filename(p.name)[0] == canonicalize_name(name)]
    assert len(matches) == 1
    old = matches[0]; version = str(parse_wheel_filename(old.name)[1])
    old.unlink(); del plan['wheels'][old.name]
    filename, data = wheel(name, version, **kwargs)
    (house / filename).write_bytes(data); plan['wheels'][filename] = digest(data)


def test_complete_metadata_bundle_is_deterministic_source_bound_and_offline(inputs):
    m, plan, review, house, _ = inputs
    a = m.prepare(plan, review, house); b = m.prepare(plan, review, house)
    assert a == b
    assert a['report.json']['status'] == 'PREPARED_INSTALL_REVIEW'
    assert a['report.json']['native_arm_installation'] == 'NOT_RUN'
    assert a['report.json']['install_authorized'] is False
    assert a['report.json']['beta_decision'] == 'NO_GO'
    assert a['report.json']['runtime_members'] == 161
    lock = a['requirements.lock'].decode()
    assert 'proofpack==0.1.0 --hash=sha256:' + plan['artifact_sha256'] in lock
    assert len(lock.splitlines()) == len(plan['wheels'])
    assert a['host.service'] == (review / 'host.service').read_bytes()
    assert a['install.py'] == (W / 'scripts/install_host_bundle.py').read_bytes()


@pytest.mark.parametrize('change', ['unknown', 'version', 'hash', 'reviewhash', 'missing', 'extra-file', 'duplicate-dist', 'stale-app'])
def test_bad_plan_or_payload_is_rejected_before_output(inputs, change):
    m, plan, review, house, _ = inputs
    if change == 'unknown': plan['approve'] = True
    elif change == 'version': plan['schema_version'] = True
    elif change == 'hash': plan['artifact_sha256'] = 'a' * 64
    elif change == 'reviewhash': plan['review_manifest_sha256'] = 'a' * 64
    elif change == 'missing': next(p for p in house.iterdir() if p.name != APP.name).unlink()
    elif change == 'extra-file': (house / 'credentials.txt').write_text('do not print fixture')
    elif change == 'duplicate-dist':
        n, data = wheel('numpy', '999.0'); (house / n).write_bytes(data); plan['wheels'][n] = digest(data)
    else:
        with zipfile.ZipFile(house / APP.name, 'a') as z: z.writestr('proofpack/stale.py', '# stale\n')
        plan['wheels'][APP.name] = digest((house / APP.name).read_bytes())
        plan['artifact_sha256'] = plan['wheels'][APP.name]
    with pytest.raises((ValueError, OSError)):
        m.prepare(plan, review, house)


@pytest.mark.parametrize('tag', ['cp312-cp312-win_amd64', 'cp312-cp312-manylinux_2_28_x86_64',
                                'cp313-cp313-manylinux_2_28_aarch64', 'cp312-cp312-musllinux_1_2_aarch64',
                                'cp312-cp312-linux_aarch64', 'cp312-cp312-manylinux_2_29_aarch64'])
def test_wrong_native_wheel_target_is_rejected(inputs, tag):
    m, plan, review, house, _ = inputs
    replace_dependency(plan, house, 'numpy', tag=tag)
    with pytest.raises(ValueError): m.prepare(plan, review, house)


def test_compatible_manylinux_floor_and_abi3_are_accepted(inputs):
    m, plan, review, house, _ = inputs
    replace_dependency(plan, house, 'numpy', tag='cp310-abi3-manylinux_2_17_aarch64')
    assert m.prepare(plan, review, house)['report.json']['status'] == 'PREPARED_INSTALL_REVIEW'


@pytest.mark.parametrize('change', ['transitive-missing', 'transitive-version', 'url', 'python', 'unknown-extra', 'unreachable', 'pth', 'traversal', 'duplicate-member', 'metadata-name'])
def test_dependency_and_archive_boundaries_are_enforced(inputs, change):
    m, plan, review, house, _ = inputs
    kwargs = {}
    if change == 'transitive-missing': kwargs['requires'] = ['never-supplied>=1']
    elif change == 'transitive-version': kwargs['requires'] = ['numpy<1']
    elif change == 'url': kwargs['requires'] = ['external @ https://example.invalid/private.whl']
    elif change == 'python': kwargs['python'] = '>=3.13'
    elif change == 'unknown-extra': kwargs['requires'] = ['numpy[missing]']
    elif change == 'pth': kwargs['entries'] = {'danger.pth': 'import os\n'}
    elif change == 'traversal': kwargs['entries'] = {'../escape': 'no'}
    if change in ('unreachable',):
        n, data = wheel('unreachable'); (house / n).write_bytes(data); plan['wheels'][n] = digest(data)
    elif change in ('duplicate-member', 'metadata-name'):
        replace_dependency(plan, house, 'numpy')
        p = next(p for p in house.iterdir() if p.name.startswith('numpy-'))
        with zipfile.ZipFile(p, 'a') as z:
            if change == 'duplicate-member': z.writestr('numpy/__init__.py', '# duplicate\n')
            else: z.writestr('other-1.0.dist-info/METADATA', 'Name: other\nVersion: 1.0\n')
        plan['wheels'][p.name] = digest(p.read_bytes())
    else: replace_dependency(plan, house, 'numpy', **kwargs)
    with pytest.raises(ValueError): m.prepare(plan, review, house)


def test_linux_marker_and_requested_extra_closure_are_followed(inputs):
    m, plan, review, house, _ = inputs
    replace_dependency(plan, house, 'numpy', requires=['pillow; sys_platform == "win32"', 'cryptography; extra == "secure"'], extra=['secure'])
    replace_dependency(plan, house, 'pillow', requires=['numpy[secure]'])
    result = m.prepare(plan, review, house)
    assert 'numpy' in result['report.json']['distributions']


@pytest.mark.parametrize('which', ['payload', 'review-status', 'updates', 'review-extra'])
def test_review_completion_and_create_only_boundary(inputs, which):
    m, plan, review, house, _ = inputs
    if which == 'payload': (review / 'operator-handoff.md').write_text('changed')
    elif which == 'review-extra': (review / 'unreviewed.txt').write_text('extra')
    else:
        p = review / 'deployment-review.json'; d = json.loads(p.read_text())
        if which == 'review-status': d['deploy_authorized'] = True
        else: d['updates_supported'] = True
        p.write_text(json.dumps(d))
        manifest = json.loads((review / 'manifest.json').read_text())
        manifest['files'][p.name] = digest(p.read_bytes())
        (review / 'manifest.json').write_text(json.dumps(manifest))
        plan['review_manifest_sha256'] = digest((review / 'manifest.json').read_bytes())
    with pytest.raises(ValueError): m.prepare(plan, review, house)


def test_bundle_marker_hashes_and_nonoverwrite(inputs, monkeypatch):
    m, plan, review, house, tmp = inputs
    monkeypatch.setattr(m, 'ROOT', tmp)
    out = tmp / 'new-bundle'
    manifest = m.write_bundle(plan, review, house, out)
    assert json.loads((out / 'manifest.json').read_text()) == manifest
    assert all(digest((out / n).read_bytes()) == h for n, h in manifest['files'].items())
    with pytest.raises(FileExistsError): m.write_bundle(plan, review, house, out)
    assert not (tmp / 'escape').exists()


@pytest.mark.parametrize('phase', ['before-marker', 'during-marker'])
def test_partial_or_mutated_bundle_never_has_completion_marker(inputs, monkeypatch, phase):
    m, plan, review, house, tmp = inputs
    monkeypatch.setattr(m, 'ROOT', tmp)
    original = m._write_new
    def changed(path, data):
        original(path, data)
        if (phase == 'before-marker' and path.name == 'report.json') or (phase == 'during-marker' and path.name == 'manifest.json'):
            (path.parent / 'requirements.lock').write_text('changed')
    monkeypatch.setattr(m, '_write_new', changed)
    with pytest.raises(OSError): m.write_bundle(plan, review, house, tmp / 'partial')
    assert not (tmp / 'partial/manifest.json').exists()
    assert (tmp / 'partial/requirements.lock').exists()


def test_plan_mutation_during_write_does_not_retarget_manifest(inputs, monkeypatch):
    m, plan, review, house, tmp = inputs
    monkeypatch.setattr(m, 'ROOT', tmp)
    expected = digest(m._json(plan)); original = m._write_new
    def changed(path, data):
        plan['artifact_sha256'] = 'f' * 64
        original(path, data)
    monkeypatch.setattr(m, '_write_new', changed)
    assert m.write_bundle(plan, review, house, tmp / 'snapshot')['plan_sha256'] == expected


def test_output_cannot_escape_checkout(inputs, monkeypatch):
    m, plan, review, house, tmp = inputs
    root = tmp / 'workspace'; root.mkdir(); monkeypatch.setattr(m, 'ROOT', root)
    with pytest.raises(ValueError): m.write_bundle(plan, review, house, tmp / 'outside')
