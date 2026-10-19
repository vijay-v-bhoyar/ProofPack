"""Installation identity contract; temporary synthetic files are not host attestation."""
import hashlib
import importlib
from pathlib import Path
import zipfile

import pytest


def installer():
    return importlib.import_module('proofpack.runtime.installation')


def archive(path, payload, *, extra=()):
    metadata={
        'proofpack-0.1.0.dist-info/METADATA':b'Metadata-Version: 2.4\nName: proofpack\nVersion: 0.1.0\n',
        'proofpack-0.1.0.dist-info/WHEEL':b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        'proofpack-0.1.0.dist-info/entry_points.txt':b'[console_scripts]\nproofpack-host = proofpack.runtime.host:main\n',
        'proofpack-0.1.0.dist-info/top_level.txt':b'proofpack\n',
        'proofpack-0.1.0.dist-info/RECORD':b'synthetic inventory; not installation evidence\n'}
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,content in (payload|metadata).items():z.writestr(name,content)
        for name,content in extra:z.writestr(name,content)
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def local_payload(tmp_path):
    package=tmp_path/'services/api/proofpack'
    payload={'proofpack/__init__.py':b'__version__ = "0.1.0"\n',
        'proofpack/runtime/installation.py':b'# synthetic application payload\n',
        'proofpack/web/index.html':b'<script type="module" src="/assets/main.js"></script>',
        'proofpack/web/assets/main.js':b'console.log("synthetic");'}
    for name,content in payload.items():
        p=package.parent/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(content)
    wheel=tmp_path/'proofpack-0.1.0-py3-none-any.whl';digest=archive(wheel,payload)
    return package,payload,wheel,digest


def install_context(monkeypatch,local_payload):
    mod=installer();package,payload,wheel,digest=local_payload
    monkeypatch.setattr(mod,'__file__',str(package/'runtime/installation.py'))
    return mod,mod.InstallationConfig(str(wheel)),package,payload,wheel,digest


@pytest.mark.parametrize('source_layout',[False,True],ids=['packaged-web','source-web'])
def test_exact_disk_and_immutable_served_bytes_match_approved_archive(monkeypatch,local_payload,source_layout):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    if source_layout:
        web=package.parents[2]/'apps/web/dist';web.parent.mkdir(parents=True);(package/'web').rename(web)
    else:web=package/'web'
    from proofpack.runtime.public_web import freeze_web
    frozen=freeze_web(web)
    result=mod.verify_installation(config,digest,frozen_web=frozen)
    assert result.artifact_sha256==digest and result.backend_files==2 and result.web_files==2
    assert result.authority=='none'


@pytest.mark.parametrize('fault',['digest','changed-code','missing-code','extra-code','extra-web','changed-frozen-web','missing-wheel'])
def test_changed_or_missing_installation_is_held(monkeypatch,local_payload,fault):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    from proofpack.runtime.public_web import freeze_web,FrozenWeb,PublicAsset
    frozen=freeze_web(package/'web')
    if fault=='digest':digest='0'*64
    elif fault=='changed-code':(package/'__init__.py').write_bytes(b'# changed')
    elif fault=='missing-code':(package/'__init__.py').unlink()
    elif fault=='extra-code':(package/'extra.py').write_bytes(b'# unexpected')
    elif fault=='extra-web':(package/'web/assets/extra.js').write_bytes(b'# unexpected')
    elif fault=='missing-wheel':wheel.unlink()
    else:frozen=FrozenWeb(tuple(PublicAsset(a.path,a.media_type,a.content+b' ') for a in frozen.assets))
    with pytest.raises(mod.InstallationUnavailable,match='Local installation verification failed'):
        mod.verify_installation(config,digest,frozen_web=frozen)


@pytest.mark.parametrize('name',['../outside.py','/outside.py','proofpack/../outside.py','proofpack\\outside.py',
    'proofpack/extra.pth','proofpack/RUNTIME/installation.py','other/extra.py','proofpack/web/assets/nested/extra.js'])
def test_unsafe_or_unexpected_archive_members_are_rejected(monkeypatch,local_payload,name):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    digest=archive(wheel,payload,extra=[(name,b'bad')])
    with pytest.raises(mod.InstallationUnavailable):mod.verify_installation(config,digest)


@pytest.mark.parametrize('clock',[[1,5_000_000_001],[2,1]],ids=['original-deadline','rollback'])
def test_original_validation_allowance_is_not_renewed(monkeypatch,local_payload,clock):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    values=iter(clock)
    with pytest.raises(mod.InstallationUnavailable):mod.verify_installation(config,digest,tick_ns=lambda:next(values))


@pytest.mark.parametrize('path',['relative.whl','https://example.test/a.whl','C:relative.whl'])
def test_installation_input_cannot_select_relative_or_remote_artifacts(path):
    with pytest.raises(ValueError):installer().InstallationConfig(path)


def test_cache_directory_does_not_expand_verified_executable_inventory(monkeypatch,local_payload):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    cache=package/'__pycache__';cache.mkdir();(cache/'ignored.pyc').write_bytes(b'generated cache')
    assert mod.verify_installation(config,digest).backend_files==2


def test_archive_is_read_only_and_has_no_extraction_effect(monkeypatch,local_payload):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    before={p.relative_to(package.parent.parent.parent).as_posix():p.read_bytes() for p in package.parents[2].rglob('*') if p.is_file()}
    mod.verify_installation(config,digest)
    after={p.relative_to(package.parent.parent.parent).as_posix():p.read_bytes() for p in package.parents[2].rglob('*') if p.is_file()}
    assert before==after and hashlib.sha256(wheel.read_bytes()).hexdigest()==digest
