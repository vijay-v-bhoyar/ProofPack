"""Frozen-byte boot, real ASGI routing on models; not an external-user evaluation."""
from pathlib import Path
import re
import anyio
import pytest
from fastapi.testclient import TestClient
from proofpack.runtime.public_web import freeze_web,FrozenWeb,PublicAsset,MAX_PACKAGE_BYTES,MAX_INDEX_BYTES
from proofpack.evidence.privacy_admission import REGISTRY,AdmissionHeld
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
from proofpack.evidence.repository import StoreUnavailable
from proofpack.runtime.ownership import ResourceOwner
from test_owner_metadata_http import client_world,BASE,no_sdk
from test_owner_metadata import create
from test_privacy_admission import world,hold


def package(tmp_path):
    (tmp_path/'assets').mkdir()
    (tmp_path/'index.html').write_text('<!doctype html><script type="module" src="/assets/main-hash.js"></script><link rel="stylesheet" href="/assets/main-hash.css">')
    (tmp_path/'assets/main-hash.js').write_bytes(b'console.log("synthetic boot")')
    (tmp_path/'assets/main-hash.css').write_bytes(b'body{color:black}')
    return tmp_path


def test_freezes_complete_exact_bytes_and_ignores_later_filesystem_changes(tmp_path):
    root=package(tmp_path);frozen=freeze_web(root);before=tuple((a.path,a.content,a.sha256) for a in frozen.assets)
    (root/'assets/main-hash.js').write_bytes(b'CHANGED PRIVATE FILE')
    (root/'assets/extra-hash.js').write_bytes(b'new file')
    assert tuple((a.path,a.content,a.sha256) for a in frozen.assets)==before
    assert frozen.get('/assets/extra-hash.js') is None
    with pytest.raises(AttributeError):frozen.assets=()


@pytest.mark.parametrize('fault',['missing','external','traversal','wrong_type','inline','no_module','unsupported','count','index_limit','package_limit'])
def test_rejects_incomplete_or_unbounded_boot_package(tmp_path,fault):
    root=package(tmp_path)
    if fault=='missing':(root/'assets/main-hash.js').unlink()
    elif fault=='external':(root/'index.html').write_text('<script type="module" src="https://foreign.invalid/a.js"></script>')
    elif fault=='traversal':(root/'index.html').write_text('<script type="module" src="/assets/../private.js"></script>')
    elif fault=='wrong_type':(root/'index.html').write_text('<script type="module" src="/assets/main-hash.css"></script>')
    elif fault=='inline':(root/'index.html').write_text('<script type="module">secret()</script>')
    elif fault=='no_module':(root/'index.html').write_text('<script src="/assets/main-hash.js"></script>')
    elif fault=='unsupported':(root/'assets/private.json').write_text('{}')
    elif fault=='count':
        for n in range(7):(root/('assets/extra-'+str(n)+'.js')).write_text('synthetic')
    elif fault=='index_limit':(root/'index.html').write_bytes(b'x'*(MAX_INDEX_BYTES+1))
    else:(root/'assets/main-hash.js').write_bytes(b'x'*MAX_PACKAGE_BYTES)
    with pytest.raises(ValueError):freeze_web(root)


@pytest.mark.parametrize('path,kind',[('/api/v1/users','text/javascript'),('/assets/../secret.js','text/javascript'),('/assets/private.json','text/css')])
def test_frozen_package_cannot_declare_an_api_or_arbitrary_path_public(path,kind):
    with pytest.raises(ValueError):FrozenWeb((PublicAsset('/','text/html',b'index'),PublicAsset(path,kind,b'body')))


def test_owner_enabled_boot_remains_public_while_held_but_private_routes_do_not():
    service,actor,repo,clock,owner,client,headers=client_world();create(service,actor);client.cookies.clear()
    with client:
        page=client.get('/');assert page.status_code==200 and 'ProofPack' in page.text
        assets=re.findall(r'(?:src|href)="(/assets/[^"]+)"',page.text);assert assets
        for path in assets:
            response=client.get(path);assert response.status_code==200 and response.content
            assert client.head(path).status_code==200 and client.head(path).content==b''
            assert response.headers['cache-control']=='no-store' and response.headers['x-content-type-options']=='nosniff'
        assert client.get(BASE+'/context').status_code==401
        for method,path in [('GET','/api/v1/users'),('GET','/assets/private.json'),('POST','/'),('GET','/assets/extra.js'),('GET','/assets//x.js')]:
            assert client.request(method,path,headers={'x-user-role':'owner','X-Metadata-Bypass':'true'}).status_code==503
    assert not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)


def test_owner_disabled_boot_keeps_ordinary_gate_semantics():
    service,actor,repo,clock,owner,client,headers=client_world(enabled=False);create(service,actor)
    with client:assert client.get('/').status_code==503


@pytest.mark.parametrize('failure',['release','cancel','expires','encoded'])
def test_public_response_is_registered_and_uncertainty_retains_resource(tmp_path,monkeypatch,failure):
    admission,repo,runtime,clock=world();hold(admission);owner=ResourceOwner();frozen=freeze_web(package(tmp_path));messages=[];called=[]
    async def app(scope,receive,send):
        called.append(True);assert not owner.wait_for_drain(0)
        assert all(v['kind']=='public_asset' for v in repo.rows[REGISTRY].data['active'].values())
        if failure=='cancel':raise anyio.get_cancelled_exc_class()()
        if failure=='expires':clock.value+=500
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'public'})
    if failure=='release':
        def failed(work):raise StoreUnavailable('synthetic private release failure')
        monkeypatch.setattr(admission,'_release_public_asset',failed)
    boundary=MetadataAdmissionBoundary(app,admission=admission,lease_ms=500,attempts=1,resource_owner=owner,owner_control=True,public_web=frozen)
    async def run():
        async def receive():return {'type':'http.request','body':b''}
        async def send(message):messages.append(message)
        scope={'type':'http','path':'/','raw_path':b'/%2f' if failure=='encoded' else b'/','method':'GET'}
        if failure=='cancel':
            with pytest.raises(anyio.get_cancelled_exc_class()):await boundary(scope,receive,send)
        else:await boundary(scope,receive,send)
    anyio.run(run)
    if failure in ['release','cancel']:assert repo.rows[REGISTRY].data['active'] and not owner.wait_for_drain(0)
    else:
        assert messages[0]['status']==503 and not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)
        if failure=='encoded':assert not called


def test_application_delivers_the_captured_package_not_later_disk_bytes(tmp_path,monkeypatch):
    root=package(tmp_path);original=(root/'assets/main-hash.js').read_bytes()
    monkeypatch.setattr('proofpack.runtime.public_web.freeze_web',lambda directory:freeze_web(root))
    service,actor,repo,clock,owner,client,headers=client_world();create(service,actor)
    (root/'assets/main-hash.js').write_bytes(b'NEW UNREVIEWED BODY')
    (root/'assets/extra-hash.js').write_bytes(b'UNADMITTED')
    with client:
        assert client.get('/assets/main-hash.js').content==original
        assert client.get('/assets/extra-hash.js').status_code==503
    assert not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)


def test_installed_public_boot_requires_capacity_for_its_captured_package(tmp_path):
    admission,repo,runtime,clock=world(capacity=2);frozen=freeze_web(package(tmp_path))
    with pytest.raises(ValueError):MetadataAdmissionBoundary(lambda *args:None,admission=admission,lease_ms=500,attempts=1,
        resource_owner=ResourceOwner(),owner_control=True,public_web=frozen)
    assert not repo.rows[REGISTRY].data['active']
