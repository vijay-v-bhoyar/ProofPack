"""Owned loopback Uvicorn serving the actual built frontend, with no auth bypass."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import socket
import subprocess
import sys
import time
import json
import httpx

ROOT=Path(__file__).resolve().parents[1]


@contextmanager
def local_web():
    output=ROOT/'evidence/local';output.mkdir(exist_ok=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    endpoint='http://127.0.0.1:'+str(port);process=None
    report={'scope':'owned_local_unconfigured_app_and_built_frontend','endpoint':endpoint,'terminated':False}
    try:
        expected=(ROOT/'apps/web/dist/index.html').read_bytes()
        report['index_sha256']=hashlib.sha256(expected).hexdigest()
        with (output/'browser-server.log').open('wb') as log:
            process=subprocess.Popen([sys.executable,'-m','uvicorn','proofpack.app:app','--app-dir','services/api',
                '--host','127.0.0.1','--port',str(port)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
            report['pid']=process.pid;deadline=time.monotonic()+20
            with httpx.Client(timeout=1,trust_env=False) as client:
                while True:
                    if process.poll() is not None:raise RuntimeError('owned local web process exited')
                    try:
                        response=client.get(endpoint+'/')
                        if response.status_code==200 and response.content==expected:break
                    except httpx.HTTPError:pass
                    if time.monotonic()>=deadline:raise RuntimeError('owned web startup or exact index verification failed')
                    time.sleep(.1)
                assert client.get(endpoint+'/health/ready').status_code==503
                assert process.poll() is None
            yield endpoint
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            report['terminated']=process.poll() is not None;report['exit_code']=process.returncode
        (output/'browser-server.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
