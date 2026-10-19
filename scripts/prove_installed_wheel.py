"""Offline wheel installation and ASGI asset proof outside the repository."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT=Path(__file__).resolve().parents[1]

CHILD=r'''
import contextlib,hashlib,importlib.metadata,io,json,sys
from pathlib import Path
target=Path(sys.argv[1]).resolve();sys.path.insert(0,str(target))
import boto3
def forbidden(*args,**kwargs):raise AssertionError('installed smoke must not discover credentials')
boto3.Session=forbidden
import proofpack.app as module
assert Path(module.__file__).resolve().is_relative_to(target)
from fastapi.testclient import TestClient
root=Path(module.__file__).parent/'web'
assert (root/'index.html').is_file()
assets=[]
with TestClient(module.app,base_url='https://proofpack.test') as client:
    index=client.get('/');assert index.status_code==200 and index.content==(root/'index.html').read_bytes()
    for path in sorted((root/'assets').rglob('*')):
        if path.is_file():
            url='/assets/'+path.relative_to(root/'assets').as_posix()
            response=client.get(url);assert response.status_code==200 and response.content==path.read_bytes()
            assets.append({'path':path.relative_to(root).as_posix(),'sha256':hashlib.sha256(response.content).hexdigest()})
    assert assets and client.get('/health/ready').status_code==503
    assert client.get('/api/v1/me').status_code==503
distribution=importlib.metadata.distribution('proofpack')
entry=next(item for item in distribution.entry_points if item.name=='proofpack' and item.group=='console_scripts')
output=io.StringIO()
with contextlib.redirect_stdout(output):
    try:entry.load()(['--help'])
    except SystemExit as error:assert error.code==0
assert 'check-config' in output.getvalue()
print(json.dumps({'status':'PASS','scope':'installed_wheel_local_ASGI_only','index_sha256':hashlib.sha256(index.content).hexdigest(),
    'assets':assets,'entrypoint':'proofpack.runtime.host:main','readiness':'DENIED','credential_discovery':'NOT_CALLED'}))
'''


def main():
    version=tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    wheels=list((ROOT/'.runtime/dist').glob('proofpack-'+version+'-*.whl'))
    if len(wheels)!=1:raise RuntimeError('one current built wheel required')
    wheel=wheels[0]
    with tempfile.TemporaryDirectory(prefix='proofpack-wheel-') as temporary:
        work=Path(temporary).resolve()
        assert work.parent==Path(tempfile.gettempdir()).resolve() and work.name.startswith('proofpack-wheel-')
        site=work/'site'
        subprocess.run([sys.executable,'-m','pip','--disable-pip-version-check','install','--no-index','--no-deps','--target',str(site),str(wheel)],
            check=True,cwd=work,timeout=45,env={**os.environ,'PIP_NO_INDEX':'1'})
        result=subprocess.run([sys.executable,'-I','-c',CHILD,str(site)],check=True,cwd=work,timeout=45,
            capture_output=True,text=True,encoding='utf-8',errors='replace')
        report=json.loads(result.stdout);report['wheel_sha256']=hashlib.sha256(wheel.read_bytes()).hexdigest()
        frontend=ROOT/'apps/web/dist'
        assert report['index_sha256']==hashlib.sha256((frontend/'index.html').read_bytes()).hexdigest()
        expected=[{'path':path.relative_to(frontend).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted((frontend/'assets').rglob('*')) if path.is_file()]
        assert report['assets']==expected,'installed wheel must contain exactly the current built frontend'
        report['wheel']=wheel.relative_to(ROOT).as_posix();report['beta_decision']='NO_GO'
        (ROOT/'evidence/local/installed-wheel.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,indent=2))


if __name__=='__main__':main()
