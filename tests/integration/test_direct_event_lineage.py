"""Actual local publication events; no physical/provider or cleanup acceptance."""
from test_access_lifecycle import repository_factory,world,publication_case


def test_direct_bootstrap_runtime_and_capture_events_have_private_resource_bindings(world,publication_case):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    observe()
    expected={'access#':{'bootstrap'},'runtime#':{'runtime_started'},'capture#':{'observation_admitted','observation_completed'}}
    for prefix,kinds in expected.items():
        rows,cursor=world[1].query(prefix=prefix,table='events',limit=100)
        selected=[row for row in rows if row.data.get('kind') in kinds]
        assert cursor is None and {row.data['kind'] for row in selected}==kinds
        for row in selected:
            assert 'resource_bindings' in row.data,'direct '+row.data['kind']+' event lacks typed resource bindings'
            binding=row.data['resource_bindings']
            assert binding['schema_version']==1 and binding['deployment']==world[1].deployment
            assert binding['writes'] or binding['checks']
            assert all(ref['table']!='events' and not ref['resource'].startswith('idempotency#') for ref in (*binding['writes'],*binding['checks']))


def test_direct_admission_idempotency_and_event_share_exact_bindings_and_do_not_repeat(world,recipe):
    from test_access_lifecycle import capture_world,capture_permit
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    permit=capture_permit(capture,started,operator)
    arguments=dict(inspection_id=started['inspection_id'],expected_version=permit['inspection_state_version'],
        permit_id=permit['permit_id'],nonce=permit['nonce'],sequence=permit['sequence'],payload=b'synthetic unprocessed bytes',idempotency_key='direct-replay',content_type='image/png')
    result=capture.admit(operator,**arguments)
    replays=[row for row in world[1].query(prefix='idempotency#',limit=100)[0] if row.data['result'].get('observation_id')==result['id']]
    events=[row for row in world[1].query(prefix='capture#',table='events',limit=100)[0] if row.data.get('kind')=='observation_admitted']
    assert len(replays)==len(events)==1
    assert replays[0].data['resource_bindings']==events[0].data['resource_bindings']
    again=capture.admit(operator,**arguments)
    assert again=={'id':result['id'],'inspection_id':started['inspection_id'],'sequence':permit['sequence'],'replayed':True}
    assert len([row for row in world[1].query(prefix='capture#',table='events',limit=100)[0] if row.data.get('kind')=='observation_admitted'])==1


def test_expiry_during_direct_preparation_prevents_admission_and_replay_write(world,recipe,monkeypatch):
    import pytest
    from test_access_lifecycle import capture_world,capture_permit
    from proofpack.capture.service import permit_key
    from proofpack.auth.policy import Denied
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    permit=capture_permit(capture,started,operator);pkey=permit_key(permit['permit_id']);prior=world[1].snapshot((pkey,))[pkey]
    prepare=world[0]._prepare_linked
    def expire(operation,*args,**kwargs):
        value=prepare(operation,*args,**kwargs)
        if operation=='observation_admitted':clock.value=int(prior.data['observation_deadline_tick_ns'])
        return value
    monkeypatch.setattr(world[0],'_prepare_linked',expire)
    arguments=dict(inspection_id=started['inspection_id'],expected_version=permit['inspection_state_version'],
        permit_id=permit['permit_id'],nonce=permit['nonce'],sequence=permit['sequence'],payload=b'synthetic bytes',idempotency_key='direct-expiry',content_type='image/png')
    with pytest.raises(Denied):capture.admit(operator,**arguments)
    assert world[1].snapshot((pkey,))[pkey]==prior
    assert capture._upload_operation(operator,**arguments)[2] is None
    assert world[1].query(prefix='capture#',table='events',limit=100)[0]==[]


def test_nested_shared_domain_event_and_returned_result_are_frozen_and_linked(world):
    from uuid import uuid4
    from proofpack.evidence.repository import Key,Write
    service,repo,clock,uid,credentials,owner=world
    key=Key('state','lineage-nested#'+str(uuid4()));event=Key('events','nested#'+str(uuid4()))
    result={'id':key.resource,'values':['original']};event_data={'kind':'nested_domain_event'}
    idem,body_hash,prior=service._idempotency(owner,'nested-shared','nested-shared',{'effect':key.resource})
    def mutate():result['values'].append('later');event_data['kind']='changed-after-preparation'
    returned=service._record(owner,'nested-shared',idem,body_hash,result,
        (Write(key,None,{}),Write(event,None,event_data)),before_commit=mutate)
    stored=repo.snapshot((event,idem));binding=stored[idem].data['resource_bindings']
    assert returned==stored[idem].data['result']=={'id':key.resource,'values':['original']}
    assert stored[event].data['kind']=='nested_domain_event' and stored[event].data['resource_bindings']==binding
    assert [ref['resource'] for ref in binding['writes']]==[key.resource]
    access=[row for row in repo.query(prefix='access#',table='events',limit=100)[0] if row.data.get('kind')=='nested-shared']
    assert len(access)==1 and access[0].data['resource_bindings']==binding


from test_erasure import erasure_case,reference_case,commit,list_page,step


def test_erasure_progress_has_bound_job_asset_and_private_audit(world,erasure_case):
    job=commit(world,erasure_case);list_page(erasure_case)
    current=step(world,erasure_case,job,'direct-progress')
    assert current['status']=='metadata_pending' and current['erasure_complete'] is False
    events=world[1].query(prefix='erasure#',table='events',limit=100)[0]
    assert len(events)==1 and events[0].data['resource_bindings']['operation']=='asset_erasure_progress'
    resources={ref['resource'] for ref in events[0].data['resource_bindings']['writes']}
    assert 'maintenance-job#'+job['id'] in resources and 'asset#'+erasure_case[1] in resources


def test_authorized_erasure_progress_finishes_after_final_logout_but_private_read_is_denied(world,erasure_case,monkeypatch):
    import pytest
    from proofpack.auth.policy import Denied
    from proofpack.evidence.erasure import job_key
    job=commit(world,erasure_case);list_page(erasure_case);transact=world[1].transact;changed=False
    def revoke(writes,checks=()):
        nonlocal changed
        if not changed and any(value.key.table=='events' and value.key.resource.startswith('erasure#') for value in writes):
            changed=True;service=erasure_case[0]
            service.access.logout(world[4].cookie,world[4].csrf)
        return transact(writes,checks)
    monkeypatch.setattr(world[1],'transact',revoke)
    with pytest.raises(Denied):step(world,erasure_case,job,'direct-logout-race')
    events=world[1].query(prefix='erasure#',table='events',limit=100)[0]
    assert changed and len(events)==1
    binding=events[0].data['resource_bindings']
    assert binding['operation']=='asset_erasure_progress'
    assert all(not ref['resource'].startswith(('session#','user#','cookie#')) for ref in binding['checks'])
    retained=world[1].snapshot((job_key(job['id']),))[job_key(job['id'])]
    assert retained.data['status']=='metadata_pending' and retained.data['progress'][erasure_case[1]]['live_versions_removed']
    with pytest.raises(Denied):erasure_case[0].job(world[5],job['id'])


def test_real_direct_transaction_preserves_full_capacity_and_atomic_stale_rejection(world):
    from uuid import uuid4
    import pytest
    from proofpack.evidence.repository import Key,Write,StoreConflict
    service,repo,*_=world;prefix='direct-capacity#'+str(uuid4())+'#'
    keys=tuple(Key('state',prefix+str(i)) for i in range(99));event=Key('events',prefix+'event')
    service._commit_linked('capacity',(*tuple(Write(key,None,{'count':1}) for key in keys),Write(event,None,{})))
    rows=repo.snapshot((*keys,event))
    assert all(rows.values()) and len(rows[event].data['resource_bindings']['writes'])==99
    nextkeys=tuple(Key('state',prefix+'next#'+str(i)) for i in range(98));nextevent=Key('events',prefix+'next-event')
    with pytest.raises(StoreConflict):
        service._commit_linked('capacity',(Write(keys[0],2,{'count':2}),*tuple(Write(key,None,{}) for key in nextkeys),Write(nextevent,None,{})))
    values=repo.snapshot((keys[0],*nextkeys,nextevent))
    assert values[keys[0]]==rows[keys[0]] and all(values[key] is None for key in (*nextkeys,nextevent))


import pytest


@pytest.mark.parametrize('fault',['wall_deadline','runtime_replaced','execution_gate'])
def test_erasure_final_service_guard_after_link_preparation_holds_progress(world,erasure_case,monkeypatch,fault):
    from uuid import uuid4
    from proofpack.auth.policy import Denied
    from proofpack.evidence.repository import StoreConflict
    from proofpack.evidence.erasure import job_key
    from proofpack.runtime.control import RuntimeControl
    service=erasure_case[0];job=commit(world,erasure_case);list_page(erasure_case)
    prepare=service.access._prepare_linked;triggered=False;gate_open=True
    def gate():
        if not gate_open:raise Denied('trusted execution gate closed')
    def interrupt(operation,writes,checks=()):
        nonlocal triggered,gate_open
        frozen=prepare(operation,writes,checks)
        if operation=='asset_erasure_progress':
            triggered=True
            if fault=='wall_deadline':world[2].value+=service.lease_ms
            elif fault=='runtime_replaced':
                RuntimeControl(service.access,instance_id=str(uuid4()),artifact_sha256=service.runtime.artifact_sha256,
                    controls_sha256=service.runtime.controls_sha256,environment=service.runtime.environment).start()
            else:gate_open=False
        return frozen
    monkeypatch.setattr(service.access,'_prepare_linked',interrupt)
    with pytest.raises((Denied,StoreConflict)):
        service.advance(world[5],job['id'],expected_version=job['state_version'],idempotency_key='guard-after-prepare',execution_gate=gate)
    assert triggered and world[1].query(prefix='erasure#',table='events',limit=100)[0]==[]
    row=world[1].snapshot((job_key(job['id']),))[job_key(job['id'])]
    assert row.data['status']=='processing' and not row.data['progress'][erasure_case[1]]['live_versions_removed']
