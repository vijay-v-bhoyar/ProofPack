"""Configured ASGI/local-store review of genuine historical publication; synthetic providers."""
from dataclasses import replace
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case,identity
from test_owner_review_host import configuration
from proofpack.runtime.composition import create_configured_app
from proofpack.evidence.owner_metadata import OwnerMetadataLimits
from proofpack.evidence.privacy_admission import AdmissionConfiguration,REGISTRY
from proofpack.evidence.repository import Key,Write
from proofpack.auth.http import COOKIE


@pytest.fixture
def configured_review_case(world,publication_case,composition_case,request):
    # Produce history before constructing the new configured runtime. Do not revive
    # the earlier runtime or copy/fabricate its records to satisfy admission.
    _,capture,started,operator,_,_,_,_,_,observe=publication_case
    observe();ident=started['inspection_id'];key=Key('state','inspection#'+ident)
    row=world[1].snapshot((key,))[key]
    capture.stations.close(operator,inspection_id=ident,expected_version=row.revision,
        expected_epoch=int(row.data['station_epoch']),reason='configured owner review fixture',
        disposition='cancelled',idempotency_key='close-before-configured-review')
    _,base,clients,stub,_=composition_case
    assert clients.dynamodb.meta.endpoint_url==world[1].client.meta.endpoint_url
    enabled=getattr(request,'param',True)
    config=replace(base,auth=world[0].config,
        oauth=replace(base.oauth,deployment=world[1].deployment),
        objects=replace(base.objects,deployment=world[1].deployment),
        state_table=world[1].tables['state'],events_table=world[1].tables['events'],
        metadata_admission=AdmissionConfiguration(8,20000,20000,15000,3,'c'*64),
        owner_metadata=OwnerMetadataLimits(10,20,100,20000),
        owner_metadata_review=configuration() if enabled else None)
    identity(stub);app=create_configured_app(config,clients,clock_ms=world[2])
    app.state.runtime_control.start();app.state.metadata_admission.initialize('c'*64)
    basepath='/api/v1/privacy/metadata-requests'
    headers={'Origin':config.app_origin,'X-CSRF-Token':world[4].csrf}
    with TestClient(app,base_url=config.app_origin) as client:
        client.cookies.set(COOKIE,world[4].cookie)
        context=client.get(basepath+'/context');assert context.status_code==200,context.text
        c=context.json()
        held=client.post(basepath,json={'inspection_ids':[ident],'expected_gate_version':c['gate_version'],
            'expected_control_version':c['control_version'],'interruption_acknowledged':True},
            headers=headers|{'Idempotency-Key':'configured-review-create'})
        assert held.status_code==201,held.text
        record=held.json();body={'expected_request_version':record['state_version'],
            'expected_gate_version':record['gate_version'],'expected_control_version':record['control_version']}
        yield app,client,headers,basepath+'/'+record['id']+'/review',body,record
    assert app.state.composition_status=='closed' and app.state.resource_owner.wait_for_drain(0)


def test_actual_configured_review_uses_shared_services_and_no_business_writes(configured_review_case,monkeypatch):
    app,client,headers,path,body,request=configured_review_case
    service=app.state.owner_metadata_review_service;owner=app.state.owner_metadata_service
    assert service.requests is owner and service.reader.admission is app.state.metadata_admission
    assert service.reader.resource_owner is owner.resource_owner is app.state.resource_owner
    assert service.reader.tick is owner.tick_ns
    repository=owner.repository;transact=repository.transact;writes=[]
    def guarded(changes,checks=()):
        assert all(w.key==REGISTRY for w in changes),'review performed a business metadata mutation'
        writes.extend(changes);return transact(changes,checks)
    monkeypatch.setattr(repository,'transact',guarded)
    response=client.post(path,json=body,headers=headers)
    assert response.status_code==200,response.text
    r=response.json();assert r['id']==request['id'] and r['scope_sha256']==request['scope_sha256']
    assert r['counts']['AFFECTED']>0 and r['counts']['UNRESOLVED']>0
    assert sum(r['counts'].values())==r['total_records'] and r['historical'] and r['read_only']
    assert not r['can_confirm_cleanup'] and not r['erasure_complete'] and not r['request_fulfilled']
    assert writes and not repository.snapshot((REGISTRY,))[REGISTRY].data['active']


@pytest.mark.parametrize('fault',['origin','cookie','stale'])
def test_actual_configured_review_denies_before_private_inventory(configured_review_case,monkeypatch,fault):
    app,client,headers,path,body,_=configured_review_case
    monkeypatch.setattr(app.state.owner_metadata_review_service.reader,'read_accounting',lambda **kw:pytest.fail('denied configured review reached inventory'))
    if fault=='origin':headers=headers|{'Origin':'https://foreign.invalid'}
    elif fault=='cookie':client.cookies.clear()
    else:body=body|{'expected_request_version':999}
    response=client.post(path,json=body,headers=headers)
    assert response.status_code=={'origin':403,'cookie':401,'stale':409}[fault],response.text


def test_actual_configured_final_source_race_returns_minimized_hold(configured_review_case,monkeypatch):
    app,client,headers,path,body,_=configured_review_case;service=app.state.owner_metadata_review_service
    original=service.reader.read_accounting;changed=[]
    def phantom(**kw):
        result=original(**kw);service.requests.repository.transact((Write(Key('state','unknown-configured-review#'+path.split('/')[-2]),None,{'private':'NEVER_DISCLOSE'}),));changed.append(True)
        return result
    monkeypatch.setattr(service.reader,'read_accounting',phantom)
    response=client.post(path,json=body,headers=headers)
    assert response.status_code==503 and response.json()['code']=='METADATA_REVIEW_HELD'
    assert changed==[True] and 'NEVER_DISCLOSE' not in response.text


@pytest.mark.parametrize('configured_review_case',[False],indirect=True)
def test_actual_omitted_review_remains_ordinary_held_work(configured_review_case):
    app,client,headers,path,body,_=configured_review_case
    assert app.state.owner_metadata_review_service is None
    response=client.post(path,json=body,headers=headers)
    assert response.status_code==503 and response.json()['code']=='METADATA_MAINTENANCE'
