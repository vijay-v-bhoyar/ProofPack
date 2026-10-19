"""Real loopback Uvicorn access-log probe with only synthetic callback values."""
import multiprocessing
from pathlib import Path
import socket
import time

import httpx


def run_server(port, log_path):
    import uvicorn
    from proofpack.app import create_app
    config={
        'version':1,'disable_existing_loggers':False,
        'formatters':{'plain':{'format':'%(levelname)s %(message)s'}},
        'handlers':{'file':{'class':'logging.FileHandler','filename':log_path,'formatter':'plain','encoding':'utf-8'}},
        'loggers':{'uvicorn':{'handlers':['file'],'level':'INFO','propagate':False},
            'uvicorn.access':{'handlers':['file'],'level':'INFO','propagate':False},
            'uvicorn.error':{'handlers':['file'],'level':'INFO','propagate':False}}}
    uvicorn.run(create_app(),host='127.0.0.1',port=port,log_config=config,
        access_log=True,proxy_headers=False)


def test_real_server_access_log_hides_callback_queries_even_on_denial(tmp_path):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    log_path=tmp_path/'access.log'
    process=multiprocessing.get_context('spawn').Process(target=run_server,args=(port,str(log_path)))
    process.start()
    try:
        with httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=1) as client:
            deadline=time.monotonic()+15
            while True:
                assert process.is_alive(),'owned local server exited before readiness'
                try:
                    if client.get('/health/live').status_code==200:break
                except httpx.TransportError:pass
                assert time.monotonic()<deadline,'owned local server startup timed out'
                time.sleep(.05)
            assert client.get('/api/v1/auth/callback?state='+'s'*43+'&code=synthetic-secret-code').status_code==503
            assert client.get('/api/v1/auth/callback?state=%XX&code=synthetic-bad-code').status_code==400
            assert client.get('/api/v1/auth/unknown?code=synthetic-unknown-code').status_code==404
        text=log_path.read_text(encoding='utf-8')
        assert '/api/v1/auth/callback HTTP/1.1' in text
        assert '/api/v1/auth/unknown HTTP/1.1' in text
        for private in ('synthetic-secret-code','synthetic-bad-code','synthetic-unknown-code','s'*43,'state=','code=','%XX'):
            assert private not in text
        (Path(__file__).resolve().parents[2]/'evidence/local/signin-access-redaction.log').write_text(text,encoding='utf-8')
    finally:
        if process.is_alive():process.terminate()
        process.join(timeout=5)
        if process.is_alive():process.kill();process.join(timeout=5)
    assert not process.is_alive()
