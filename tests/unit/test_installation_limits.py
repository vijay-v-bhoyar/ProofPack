"""Adversarial artifact/file bounds and mid-validation replacement, with local fixtures."""
import hashlib
from pathlib import Path
import stat
import zipfile

import pytest

from test_configured_installation import local_payload,install_context,archive


@pytest.mark.parametrize('fault',['duplicate','symlink','directory','bad-package-name','bad-package-version','special-local-file','nested-web','unknown-web'])
def test_no_unapproved_payload_even_when_expected_archive_digest_matches(monkeypatch,local_payload,fault):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    if fault=='duplicate':
        with pytest.warns(UserWarning):digest=archive(wheel,payload,extra=[('proofpack/__init__.py',payload['proofpack/__init__.py'])])
    elif fault in {'symlink','directory','bad-package-name','bad-package-version'}:
        with zipfile.ZipFile(wheel) as z:items=[(i,z.read(i)) for i in z.infolist()]
        with zipfile.ZipFile(wheel,'w') as z:
            for info,content in items:
                if info.filename=='proofpack/__init__.py' and fault in {'symlink','directory'}:
                    info.create_system=3;info.external_attr=((stat.S_IFLNK if fault=='symlink' else stat.S_IFDIR)|0o644)<<16
                if info.filename.endswith('/METADATA'):
                    if fault=='bad-package-name':content=content.replace(b'Name: proofpack',b'Name: other')
                    if fault=='bad-package-version':content=content.replace(b'Version: 0.1.0',b'Version: 0.2.0')
                z.writestr(info,content)
    elif fault=='special-local-file':
        (package/'extra.pth').write_bytes(b'unapproved code')
        payload['proofpack/extra.pth']=b'unapproved code';archive(wheel,payload)
    else:
        name='assets/nested/extra.js' if fault=='nested-web' else 'assets/extra.pth'
        p=package/'web'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'bad')
        payload['proofpack/web/'+name]=b'bad';archive(wheel,payload)
    digest=hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(mod.InstallationUnavailable):mod.verify_installation(config,digest)


@pytest.mark.parametrize('fault',['archive-bytes','member-count','member-bytes'])
def test_fixed_archive_size_and_member_limits(monkeypatch,local_payload,fault):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    if fault=='archive-bytes':
        with wheel.open('r+b') as stream:stream.truncate(32*1024*1024+1)
    elif fault=='member-count':
        with zipfile.ZipFile(wheel,'w') as z:
            for n in range(1025):z.writestr('proofpack/x'+str(n)+'.py',b'x')
    else:
        payload['proofpack/__init__.py']=b'x'*(4*1024*1024+1);archive(wheel,payload)
    digest=hashlib.sha256(wheel.read_bytes()).hexdigest()
    with pytest.raises(mod.InstallationUnavailable):mod.verify_installation(config,digest)


def test_final_inventory_rejects_change_after_a_file_was_already_compared(monkeypatch,local_payload):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    original=mod._read;changed=[]
    def change_after_read(path,*args):
        result=original(path,*args)
        if path.name=='index.html':
            (package/'__init__.py').write_bytes(b'# changed after original comparison')
            changed.append(True)
        return result
    monkeypatch.setattr(mod,'_read',change_after_read)
    with pytest.raises(mod.InstallationUnavailable):mod.verify_installation(config,digest)
    assert changed==[True]


@pytest.mark.parametrize('which',['file','directory','parent'])
def test_reparse_attributes_are_rejected_even_without_python_symlink_flag(monkeypatch,local_payload,which):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    from types import SimpleNamespace
    target=package/'__init__.py' if which=='file' else package if which=='directory' else package.parent
    original=Path.lstat;entered=[]
    def metadata(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        if path==target:
            entered.append(True)
            return SimpleNamespace(st_mode=value.st_mode,st_file_attributes=0x400)
        return value
    monkeypatch.setattr(Path,'lstat',metadata)
    with pytest.raises(mod.InstallationUnavailable):mod.verify_installation(config,digest)
    assert entered


def test_real_windows_handle_and_path_identity_are_both_pinned(monkeypatch,local_payload):
    mod,config,package,payload,wheel,digest=install_context(monkeypatch,local_payload)
    original=mod.os.fstat;seen=[]
    def pin(fd):
        value=original(fd);seen.append((value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns));return value
    monkeypatch.setattr(mod.os,'fstat',pin)
    assert mod.verify_installation(config,digest).backend_files==2
    assert len(seen)>=10 and all(value[2]>0 for value in seen)
