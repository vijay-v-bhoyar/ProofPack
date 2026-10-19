from fastapi.testclient import TestClient

from proofpack.app import create_app


def test_public_liveness_reveals_no_runtime_or_secrets_and_readiness_denied():
    with TestClient(create_app()) as client:
        live=client.get('/health/live')
        assert live.status_code==200
        assert live.json()=={"status":"ok"}
        assert live.headers['cache-control']=='no-store'
        policy={parts[0]:parts[1:] for part in live.headers['content-security-policy'].split(';') if (parts:=part.split())}
        assert policy['default-src']==["'self'"] and policy['img-src']==["'self'",'blob:']
        assert policy['object-src']==["'none'"] and policy['frame-ancestors']==["'none'"]
        assert client.get('/health/ready').status_code==503
        runtime=client.get('/api/v1/admin/runtime')
        assert runtime.status_code==503 and runtime.json()['code']=='DEPENDENCY_UNAVAILABLE'
        assert 'runtime_epoch' not in runtime.text and 'artifact_sha256' not in runtime.text
        denied=client.post('/api/v1/inspections',json={"passed":True})
        assert denied.status_code==503 and 'PASSED_CURRENT' not in denied.text
        assert client.get('/openapi.json').status_code==404
