"""Actual ASGI/owned local stores; identities and acknowledgments are synthetic."""
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world, repository_factory, invite_and_join
from test_inspection_handoffs import setup_case
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Role
from proofpack.stations.service import inspection_key, StationService


def application(case,world,*,installed=True):
    service=case[0]
    return create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,
        recipe_service=service.stations.recipes,station_service=service.stations,**({'handoff_service':service} if installed else {}))


def post_headers(credentials,key='http-handoff',version=1):
    return {'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'If-Match':str(version),'Idempotency-Key':key}


def body(case):return {'recipient_user_id':case[4],'expected_epoch':1,'reason_code':'support_needed','stop_acknowledged':True}


def test_installed_http_request_and_reviewer_response_keep_capture_stopped(world,recipe):
    case=setup_case(world,recipe);service,started,_,_,_,credentials,review_credentials=case;url='/api/v1/inspections/'+started['inspection_id']+'/handoffs'
    with TestClient(application(case,world),base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/handoffs/inbox').status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        empty=client.get(url+'/latest');assert empty.status_code==200,empty.text
        assert empty.json()['handoff'] is None and empty.json()['inspection_id']==started['inspection_id']
        assert empty.json()['historical'] is True and empty.json()['machine_approval'] is False and empty.json()['capture_transferred'] is False
        assert client.post(url,json=body(case),headers={'If-Match':'1','Idempotency-Key':'no-origin'}).status_code==403
        created=client.post(url,json=body(case),headers=post_headers(credentials));assert created.status_code==201,created.text
        view=created.json();assert view['recorded_status']=='pending' and view['pending_eligible'] and not view['acknowledged']
        assert created.headers['cache-control']=='no-store' and 'sender_session_id' not in created.text and 'cookie#' not in created.text
        client.cookies.set(COOKIE,review_credentials.cookie)
        inbox=client.get('/api/v1/handoffs/inbox');assert inbox.status_code==200,inbox.text
        assert [x['id'] for x in inbox.json()['requests']]==[view['id']] and 'pending_eligible' not in inbox.json()['requests'][0]
        response=client.post(url+'/'+view['id']+'/respond',json={'decision':'accepted','request_sha256':view['request_sha256'],
            'expected_inspection_version':view['inspection_state_version'],'acknowledge_no_capture_transfer':True},
            headers=post_headers(review_credentials,'http-response',view['state_version']))
        assert response.status_code==200,response.text
        assert response.json()['acknowledged'] and response.json()['current_assignment'] and not response.json()['machine_approval'] and not response.json()['capture_transferred']
        client.cookies.set(COOKIE,credentials.cookie)
        latest=client.get(url+'/latest');assert latest.status_code==200,latest.text
        assert latest.json()['id']==view['id'] and latest.json()['recorded_status']=='accepted'
        work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        assert work.data['state']=='REVIEW_REQUIRED' and work.data['corrections']==0


def test_owner_only_and_other_reviewer_cannot_read_or_respond_to_a_request(world,recipe):
    case=setup_case(world,recipe);_,started,_,_,_,credentials,_=case
    other_id,other_credentials,*_=invite_and_join(world,'unassigned-http-reviewer',roles=(Role.REVIEWER,))
    url='/api/v1/inspections/'+started['inspection_id']+'/handoffs'
    with TestClient(application(case,world),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie);created=client.post(url,json=body(case),headers=post_headers(credentials));assert created.status_code==201,created.text
        view=created.json()
        for forbidden in (world[4],other_credentials):
            client.cookies.set(COOKIE,forbidden.cookie)
            assert client.get(url+'/'+view['id']).status_code==403
            response=client.post(url+'/'+view['id']+'/respond',json={'decision':'accepted','request_sha256':view['request_sha256'],
                'expected_inspection_version':view['inspection_state_version'],'acknowledge_no_capture_transfer':True},headers=post_headers(forbidden,'not-assigned-'+other_id))
            assert response.status_code==403,response.text


@pytest.mark.parametrize('change',[{'expected_epoch':True},{'expected_epoch':'1'},{'stop_acknowledged':False},
    {'stop_acknowledged':1},{'reason_code':'force_pass'},{'send_email':True}])
def test_malformed_or_unacknowledged_http_intent_is_rejected_without_a_request(world,recipe,change):
    case=setup_case(world,recipe);_,started,_,_,_,credentials,_=case
    with TestClient(application(case,world),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        response=client.post('/api/v1/inspections/'+started['inspection_id']+'/handoffs',json={**body(case),**change},headers=post_headers(credentials))
        assert response.status_code==400,response.text
        assert response.json()['code']=='INVALID_REQUEST' and not response.json()['retryable']
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data.get('handoff_count',0)==0 and work.data['state']=='CREATED'


@pytest.mark.parametrize('chunked',[False,True])
def test_handoff_json_body_is_bounded_before_framework_parsing(world,recipe,chunked):
    case=setup_case(world,recipe);_,started,_,_,_,credentials,_=case
    def stream():
        yield b' '*4096;yield b' '*4096;yield b'{}'
    with TestClient(application(case,world),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        response=client.post('/api/v1/inspections/'+started['inspection_id']+'/handoffs',content=stream() if chunked else b' '*8192+b'{}',
            headers={**post_headers(credentials),'Content-Type':'application/json'})
        assert response.status_code==413,response.text


def test_absent_handoff_service_has_no_implicit_fallback(world,recipe):
    case=setup_case(world,recipe);_,started,_,_,_,credentials,_=case
    with TestClient(application(case,world,installed=False),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        response=client.post('/api/v1/inspections/'+started['inspection_id']+'/handoffs',json=body(case),headers=post_headers(credentials))
        assert response.status_code==503,response.text


def test_application_rejects_a_handoff_service_from_another_station_graph(world,recipe):
    case=setup_case(world,recipe);service=case[0]
    other=StationService(service.access,service.runtime,service.stations.recipes)
    with pytest.raises(ValueError,match='handoffs must share exact application'):create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,
        recipe_service=service.stations.recipes,station_service=other,handoff_service=service)
