"""Owned local transactions; synthetic identities/state, no human acknowledgment."""
import pytest
from test_access_lifecycle import world, repository_factory, station_world, acquire_station, start_station, invite_and_join, proof
from proofpack.auth.policy import Role, Denied
from proofpack.evidence.repository import Write, StoreConflict, StoreUnavailable
from proofpack.stations.service import inspection_key, station_key
from proofpack.runtime.control import DATA, ALLOCATION, integer


def setup_case(world,recipe,*,operator_roles=None,**overrides):
    from proofpack.stations.handoffs import InspectionHandoffs, HandoffLimits
    stations,enrolled,created,operator,credentials,_=station_world(world,recipe)
    if operator_roles is not None:
        world[0].change_access(world[5],user_id=operator.member.data['id'],roles=operator_roles,enabled=True,
            expected_version=integer(operator.member.data['access_version']),idempotency_key='operator-explicit-roles')
        credentials=world[0].login(proof(world[2],'operator'));operator=world[0].resolve(credentials.cookie)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    reviewer_id,reviewer_credentials,reviewer,*_=invite_and_join(world,'handoff-reviewer',roles=(Role.REVIEWER,))
    limits={'max_requests':4,'lifetime_ms':3600000,'reads_per_minute':60,'read_window_ms':5000,'page_size':20,'metadata_retention_ms':30*86400000,**overrides}
    service=InspectionHandoffs(stations,limits=HandoffLimits(**limits))
    return service,started,operator,reviewer,reviewer_id,credentials,reviewer_credentials


def request(case,*,actor=None,target=None,key='request',expected=None):
    from proofpack.stations.handoffs import HandoffRequest
    service,started,operator,_,reviewer_id,*_=case
    work=service.repository.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    return service.request(actor or operator,started['inspection_id'],expected_version=work.revision if expected is None else expected,
        request=HandoffRequest(recipient_user_id=target or reviewer_id,expected_epoch=integer(work.data['station_epoch']),reason_code='support_needed',stop_acknowledged=True),
        idempotency_key=key)


def respond(case,view,*,actor=None,decision='accepted',key='respond'):
    from proofpack.stations.handoffs import HandoffResponse
    service,started,_,reviewer,*_=case
    return service.respond(actor or reviewer,started['inspection_id'],view['id'],expected_version=view['state_version'],
        response=HandoffResponse(decision=decision,request_sha256=view['request_sha256'],expected_inspection_version=view['inspection_state_version'],acknowledge_no_capture_transfer=True),
        idempotency_key=key)


def test_request_stops_the_same_inspection_without_resetting_budgets_or_transferring_capture(world,recipe):
    case=setup_case(world,recipe);service,started,operator,*_=case
    key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
    # Authored prior state, not a verified physical or current-result fixture.
    values={**work.data,'state':'PASSED_CURRENT','corrections':2,'model_requests':2,'original_attempts_reserved':3,
        'deadline_tick_ns':99999999999,'stable_ticks_ns':[1,2,3],'current_action_id':'a0000000-0000-4000-8000-000000000001'}
    world[1].transact((Write(key,work.revision,values),))
    station=world[1].snapshot((station_key(work.data['station_id']),))[station_key(work.data['station_id'])]
    allocation=world[1].snapshot((ALLOCATION,))[ALLOCATION]
    view=request(case);after=world[1].snapshot((key,))[key]
    assert view['recorded_status']=='pending' and view['pending_eligible'] and not view['current_assignment']
    assert after.data['state']=='REVIEW_REQUIRED' and after.data['deadline_tick_ns']==0 and after.data['stable_ticks_ns']==[]
    assert after.data['current_action_id'] is None and after.data['corrections']==2 and after.data['model_requests']==2 and after.data['original_attempts_reserved']==3
    assert after.data['originating_session_id']==operator.session.data['id'] and after.data['handoff_count']==1
    assert world[1].snapshot((station.key,ALLOCATION))=={station.key:station,ALLOCATION:allocation}
    assert view['historical'] and not view['machine_approval'] and not view['capture_transferred']
    assert view['request']['kit_reference']==work.data['kit_id'] and view['request']['station_name']==station.data['name']


def test_designated_reviewer_accepts_but_cannot_restore_observing_or_change_station_owner(world,recipe):
    case=setup_case(world,recipe);service,started,operator,reviewer,*_=case
    created=request(case);accepted=respond(case,created)
    assert accepted['recorded_status']=='accepted' and accepted['acknowledged'] and accepted['current_assignment']
    assert not accepted['pending_eligible'] and not accepted['machine_approval'] and not accepted['capture_transferred']
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['state']=='REVIEW_REQUIRED' and work.data['accepted_handoff_id']==created['id']
    station=world[1].snapshot((station_key(work.data['station_id']),))[station_key(work.data['station_id'])]
    assert station.data['owner_session_id']==operator.session.data['id']!=reviewer.session.data['id']


@pytest.mark.parametrize('decision',['declined','cancelled'])
def test_decline_or_sender_cancel_never_becomes_an_acknowledged_transfer(world,recipe,decision):
    from proofpack.stations.handoffs import HandoffCancel
    case=setup_case(world,recipe);service,started,operator,*_=case;created=request(case)
    result=respond(case,created,decision='declined') if decision=='declined' else service.cancel(operator,started['inspection_id'],created['id'],
        expected_version=created['state_version'],request=HandoffCancel(request_sha256=created['request_sha256']),idempotency_key='cancel')
    assert result['recorded_status']==decision and not result['acknowledged'] and not result['current_assignment']
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['state']=='REVIEW_REQUIRED' and work.data.get('accepted_handoff_id') is None


def test_retries_preserve_original_lifetime_count_and_decision(world,recipe):
    from proofpack.stations.handoffs import HandoffRequest, HandoffResponse
    case=setup_case(world,recipe);service,started,operator,reviewer,reviewer_id,*_=case
    created=request(case);world[2].value+=100
    again=request(case,expected=created['request']['source_inspection_revision'])
    assert again['id']==created['id'] and again['request']['expires_at_ms']==created['request']['expires_at_ms']
    accepted=respond(case,again);world[2].value+=100
    same=service.respond(reviewer,started['inspection_id'],created['id'],expected_version=created['state_version'],
        response=HandoffResponse(decision='accepted',request_sha256=created['request_sha256'],expected_inspection_version=again['inspection_state_version'],acknowledge_no_capture_transfer=True),idempotency_key='respond')
    assert same['id']==accepted['id'] and same['decision']==accepted['decision']
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['handoff_count']==1
    with pytest.raises(StoreConflict):service.request(operator,started['inspection_id'],expected_version=created['request']['source_inspection_revision'],
        request=HandoffRequest(recipient_user_id=reviewer_id,expected_epoch=integer(work.data['station_epoch']),reason_code='capture_interrupted',stop_acknowledged=True),idempotency_key='request')


@pytest.mark.parametrize('change',['sender_logout','recipient_revoke','data','inspection','station','expiry'])
def test_changed_authority_or_context_holds_pending_acceptance(world,recipe,change):
    from proofpack.auth.service import user_key
    case=setup_case(world,recipe);service,started,operator,reviewer,reviewer_id,*_=case;created=request(case)
    if change=='sender_logout':world[0].logout(case[5].cookie,case[5].csrf)
    elif change=='recipient_revoke':
        key=user_key(reviewer_id);row=world[1].snapshot((key,))[key]
        world[1].transact((Write(key,row.revision,{**row.data,'access_version':row.data['access_version']+1}),))
    elif change=='expiry':world[2].value=created['request']['expires_at_ms']
    else:
        key=DATA if change=='data' else inspection_key(started['inspection_id'])
        if change=='station':
            work=world[1].snapshot((key,))[key];key=station_key(work.data['station_id'])
        row=world[1].snapshot((key,))[key]
        patch={'epoch':row.data['epoch']+1} if change in {'data','station'} else {'disposition':'rework'}
        world[1].transact((Write(key,row.revision,{**row.data,**patch}),))
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):respond(case,created)
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data.get('accepted_handoff_id') is None and work.data['state']=='REVIEW_REQUIRED'


def test_self_owner_only_and_unrelated_reviewer_cannot_acknowledge(world,recipe):
    case=setup_case(world,recipe);service,started,operator,_,reviewer_id,*_=case
    with pytest.raises(Denied):request(case,target=operator.member.data['id'])
    with pytest.raises(Denied):request(case,target=world[3])
    created=request(case)
    with pytest.raises(Denied):respond(case,created,actor=operator)
    with pytest.raises(Denied):service.read(world[5],started['inspection_id'],created['id'])
    _,_,other,*_=invite_and_join(world,'other-reviewer',roles=(Role.REVIEWER,))
    with pytest.raises(Denied):respond(case,created,actor=other)


def test_successor_decline_keeps_the_previously_accepted_reviewer(world,recipe):
    case=setup_case(world,recipe);service,started,operator,reviewer,*_=case
    first=respond(case,request(case));other_id,_,other,*_=invite_and_join(world,'successor-reviewer',roles=(Role.REVIEWER,))
    successor=request(case,actor=reviewer,target=other_id,key='successor')
    assert service.read(operator,started['inspection_id'],first['id'])['current_assignment']
    declined=respond(case,successor,actor=other,decision='declined',key='decline-successor')
    assert not declined['acknowledged'] and service.read(operator,started['inspection_id'],first['id'])['current_assignment']


def test_successor_acceptance_is_separate_and_replaces_only_review_assignment(world,recipe):
    case=setup_case(world,recipe);service,started,operator,reviewer,*_=case
    first=respond(case,request(case));other_id,_,other,*_=invite_and_join(world,'successor-reviewer',roles=(Role.REVIEWER,))
    successor=request(case,actor=reviewer,target=other_id,key='successor')
    accepted=respond(case,successor,actor=other,key='accept-successor')
    assert accepted['current_assignment'] and not service.read(operator,started['inspection_id'],first['id'])['current_assignment']
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['state']=='REVIEW_REQUIRED' and work.data['originating_user_id']==operator.member.data['id'] and work.data['handoff_count']==2


@pytest.mark.parametrize('change',['retention','decision_actor','decision_request','decision_ack','decision_future','signature'])
def test_stored_outcome_and_retention_must_remain_bound_to_the_exact_request(world,recipe,change):
    from proofpack.stations.handoffs import handoff_key
    from proofpack.calibrations.dependencies import digest
    case=setup_case(world,recipe);service,started,operator,*_=case;accepted=respond(case,request(case))
    key=handoff_key(started['inspection_id'],accepted['id']);row=world[1].snapshot((key,))[key];updated={**row.data}
    if change=='retention':updated['metadata_expires_at_ms']+=1000
    elif change=='signature':updated['request_sha256']='f'*64
    else:
        decision={**row.data['decision']}
        if change=='decision_actor':decision['actor_user_id']=operator.member.data['id']
        if change=='decision_request':decision['handoff_id']='f0000000-0000-4000-8000-000000000001'
        if change=='decision_ack':decision['acknowledge_no_capture_transfer']=False
        if change=='decision_future':decision['at_ms']=world[2]()+1000
        updated.update(decision=decision,decision_sha256=digest(decision))
    world[1].transact((Write(key,row.revision,updated),))
    with pytest.raises(StoreUnavailable):service.read(operator,started['inspection_id'],accepted['id'])


def test_combined_operator_reviewer_roles_do_not_allow_self_assignment(world,recipe):
    case=setup_case(world,recipe,operator_roles=(Role.OPERATOR,Role.REVIEWER))
    assert Role.REVIEWER in case[2].principal.roles
    with pytest.raises(Denied):request(case,target=case[2].member.data['id'])


@pytest.mark.parametrize('kind',['request','response'])
def test_lost_commit_response_recovers_original_intent_once(world,recipe,monkeypatch,kind):
    from proofpack.stations.handoffs import handoff_key
    case=setup_case(world,recipe);service,started,*_=case
    created=request(case) if kind=='response' else None
    commit=service.access._commit
    def lost(writes,checks=()):
        commit(writes,checks)
        if any(w.key.resource.startswith('inspection-handoff#') and w.data['status']==('accepted' if kind=='response' else 'pending') for w in writes):
            raise StoreUnavailable('synthetic lost commit acknowledgment')
    with monkeypatch.context() as patch:
        patch.setattr(service.access,'_commit',lost)
        with pytest.raises(StoreUnavailable):
            if kind=='response':respond(case,created)
            else:request(case,expected=1)
    result=respond(case,created) if kind=='response' else request(case,expected=1)
    key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
    assert work.data['handoff_count']==1
    assert result['recorded_status']==('accepted' if kind=='response' else 'pending')
    rows,_=world[1].query(prefix='inspection-handoff#'+started['inspection_id']+'#')
    assert len(rows)==1 and rows[0].key==handoff_key(started['inspection_id'],result['id'])


def test_an_eligible_pending_request_cannot_be_silently_replaced(world,recipe):
    case=setup_case(world,recipe);created=request(case)
    with pytest.raises(StoreConflict):request(case,key='another-intent')
    assert case[0].latest(case[2],case[1]['inspection_id'])['id']==created['id']


def test_explicit_supersession_keeps_expiry_and_consumed_count_in_history(world,recipe):
    case=setup_case(world,recipe,lifetime_ms=1000);service,started,operator,*_=case
    first=request(case);world[2].value+=1000
    second=request(case,key='new-support-intent')
    old=service.read(operator,started['inspection_id'],first['id'])
    assert old['recorded_status']=='superseded' and old['request']['expires_at_ms']==first['request']['expires_at_ms']
    assert not old['acknowledged'] and not second['acknowledged'] and second['id']!=first['id']
    row=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert row.data['handoff_count']==2 and row.data['state']=='REVIEW_REQUIRED'


def test_cancelled_requests_never_refund_the_original_inspection_budget(world,recipe):
    from proofpack.stations.handoffs import HandoffCancel, HandoffLimited
    case=setup_case(world,recipe,max_requests=2);service,started,operator,*_=case
    for i in range(2):
        created=request(case,key='budget-'+str(i))
        service.cancel(operator,started['inspection_id'],created['id'],expected_version=created['state_version'],
            request=HandoffCancel(request_sha256=created['request_sha256']),idempotency_key='cancel-'+str(i))
        world[2].value+=1000
    with pytest.raises(HandoffLimited):request(case,key='over-budget')
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['handoff_count']==2 and work.data['corrections']==0 and work.data['state']=='REVIEW_REQUIRED'


def test_inbox_is_paged_recipient_history_and_grants_no_response_authority(world,recipe):
    from proofpack.stations.handoffs import HandoffCancel
    case=setup_case(world,recipe,page_size=2);service,started,operator,reviewer,*_=case
    expected=set()
    for i in range(3):
        view=request(case,key='inbox-'+str(i));expected.add(view['id'])
        service.cancel(operator,started['inspection_id'],view['id'],expected_version=view['state_version'],
            request=HandoffCancel(request_sha256=view['request_sha256']),idempotency_key='inbox-cancel-'+str(i));world[2].value+=1000
    first=service.inbox(reviewer);second=service.inbox(reviewer,cursor=first['next_cursor'])
    assert len(first['requests'])==2 and len(second['requests'])==1 and second['next_cursor'] is None
    assert {x['id'] for x in first['requests']+second['requests']}==expected
    assert all(x['historical'] and not x['machine_approval'] and 'pending_eligible' not in x for x in first['requests']+second['requests'])
    _,_,other,*_=invite_and_join(world,'unassigned-inbox-reviewer',roles=(Role.REVIEWER,))
    assert service.inbox(other)['requests']==[]
    with pytest.raises(Denied):service.inbox(world[5])
    with pytest.raises(Denied):service.inbox(operator)


@pytest.mark.parametrize('source',['recipient','sender','data','station','inspection'])
def test_source_change_at_final_response_commit_cannot_publish_acceptance(world,recipe,monkeypatch,source):
    from proofpack.auth.service import user_key
    case=setup_case(world,recipe);service,started,operator,_,reviewer_id,*_=case;created=request(case)
    commit=service.access._commit
    def change(writes,checks=()):
        if any(w.key.resource.startswith('inspection-handoff#') and w.data['status']=='accepted' for w in writes):
            key=user_key(reviewer_id if source=='recipient' else operator.member.data['id']) if source in {'recipient','sender'} else DATA if source=='data' else inspection_key(started['inspection_id'])
            if source=='station':
                work=world[1].snapshot((key,))[key];key=station_key(work.data['station_id'])
            row=world[1].snapshot((key,))[key]
            field='access_version' if source in {'recipient','sender'} else 'epoch' if source in {'data','station'} else None
            updated={**row.data,field:row.data[field]+1} if field else {**row.data,'disposition':'rework'}
            world[1].transact((Write(key,row.revision,updated),))
        return commit(writes,checks)
    with monkeypatch.context() as patch:
        patch.setattr(service.access,'_commit',change)
        with pytest.raises((StoreConflict,Denied)):respond(case,created)
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data.get('accepted_handoff_id') is None and work.data['state']=='REVIEW_REQUIRED'


def test_expiry_at_last_response_gate_preserves_unaccepted_stopped_work(world,recipe,monkeypatch):
    case=setup_case(world,recipe,lifetime_ms=1000);service,started,*_=case;created=request(case)
    quota=service.stations._quota
    def expire(ident):
        result=quota(ident);world[2].value=created['request']['expires_at_ms'];return result
    with monkeypatch.context() as patch:
        patch.setattr(service.stations,'_quota',expire)
        with pytest.raises(StoreUnavailable):respond(case,created)
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data.get('accepted_handoff_id') is None and work.data['state']=='REVIEW_REQUIRED'


def test_expired_pending_metadata_is_not_delivered_as_eligible(world,recipe,monkeypatch):
    case=setup_case(world,recipe,lifetime_ms=1000);service,started,operator,*_=case;created=request(case)
    record=service.access._record
    def expire(*args,**kwargs):
        result=record(*args,**kwargs)
        if args[1]=='handoff-read':world[2].value=created['request']['expires_at_ms']
        return result
    with monkeypatch.context() as patch:
        patch.setattr(service.access,'_record',expire)
        with pytest.raises(StoreUnavailable):service.read(operator,started['inspection_id'],created['id'])
    expired=service.read(operator,started['inspection_id'],created['id'])
    assert expired['effective_status']=='expired' and not expired['pending_eligible']


def test_read_quota_and_public_shape_do_not_leak_private_authority(world,recipe):
    import json
    from proofpack.stations.handoffs import HandoffLimited
    case=setup_case(world,recipe,reads_per_minute=1);service,started,operator,*_=case;view=request(case)
    assert type(view['request']['source_inspection_revision']) is int and type(view['request']['expires_at_ms']) is int
    assert 'cookie#' not in json.dumps(view) and 'sender_session_id' not in json.dumps(view)
    with pytest.raises(HandoffLimited):service.read(operator,started['inspection_id'],view['id'])


@pytest.mark.parametrize('operation',['read','latest','inbox'])
def test_whole_metadata_window_includes_authorization_and_source_lookup(world,recipe,monkeypatch,operation):
    case=setup_case(world,recipe);service,started,operator,reviewer,*_=case;view=request(case)
    clock={'value':0};service.tick_ns=lambda:clock['value']
    target=service.repository if operation=='inbox' else service
    name='query' if operation=='inbox' else '_base';original=getattr(target,name)
    def delayed(*args,**kwargs):
        result=original(*args,**kwargs);clock['value']+=service.limits.read_window_ms*1000000;return result
    with monkeypatch.context() as patch:
        patch.setattr(target,name,delayed)
        with pytest.raises(StoreUnavailable):
            if operation=='read':service.read(operator,started['inspection_id'],view['id'])
            elif operation=='latest':service.latest(operator,started['inspection_id'])
            else:service.inbox(reviewer)


@pytest.mark.parametrize('who',['sender','recipient'])
def test_fresh_mfa_signin_with_unchanged_grants_does_not_invalidate_pending_support(world,recipe,who):
    from proofpack.auth.service import user_key
    case=setup_case(world,recipe);created=request(case)
    original=case[2] if who=='sender' else case[3];key=user_key(original.member.data['id']);before=world[1].snapshot((key,))[key]
    world[2].value+=1
    credentials=world[0].login(proof(world[2],'operator' if who=='sender' else 'handoff-reviewer',mfa=True))
    current=world[0].resolve(credentials.cookie);after=world[1].snapshot((key,))[key]
    assert after.revision>before.revision and after.data['access_version']==before.data['access_version']
    accepted=respond(case,created,actor=current if who=='recipient' else None)
    assert accepted['acknowledged'] and accepted['current_assignment'] and not accepted['capture_transferred']


def test_original_requester_can_withdraw_pending_support_after_reauthentication(world,recipe):
    from proofpack.stations.handoffs import HandoffCancel
    case=setup_case(world,recipe);service,started,operator,*_=case;created=request(case)
    credentials=world[0].login(proof(world[2],'operator',mfa=True));current=world[0].resolve(credentials.cookie)
    assert current.member.data['id']==operator.member.data['id'] and current.session.data['id']!=operator.session.data['id']
    cancelled=service.cancel(current,started['inspection_id'],created['id'],expected_version=created['state_version'],
        request=HandoffCancel(request_sha256=created['request_sha256']),idempotency_key='withdraw-after-signin')
    assert cancelled['recorded_status']=='cancelled' and not cancelled['acknowledged']
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['state']=='REVIEW_REQUIRED' and work.data['handoff_count']==1


def test_latest_read_does_not_switch_to_an_unbound_snapshot_during_replacement(world,recipe,monkeypatch):
    from proofpack.stations.handoffs import HandoffCancel
    case=setup_case(world,recipe);service,started,operator,*_=case;first=request(case)
    original=service._base;armed={'value':True}
    def replace_after_lookup(*args,**kwargs):
        context=original(*args,**kwargs)
        if armed['value']:
            armed['value']=False
            service.cancel(operator,started['inspection_id'],first['id'],expected_version=first['state_version'],
                request=HandoffCancel(request_sha256=first['request_sha256']),idempotency_key='cancel-before-new')
            request(case,key='replacement-during-read')
        return context
    with monkeypatch.context() as patch:
        patch.setattr(service,'_base',replace_after_lookup)
        with pytest.raises(StoreConflict):service.latest(operator,started['inspection_id'])


def test_successor_does_not_extend_the_inspections_metadata_retention(world,recipe):
    from proofpack.stations.handoffs import handoff_key
    from proofpack.auth.service import ResourceUnavailable
    case=setup_case(world,recipe);service,started,*_=case
    respond(case,request(case));other_id,_,_,*_=invite_and_join(world,'retention-successor',roles=(Role.REVIEWER,))
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    deadline=integer(work.data['created_at_ms'])+30*86400000
    world[2].value=deadline-500
    credentials=world[0].login(proof(world[2],'handoff-reviewer',mfa=True));reviewer=world[0].resolve(credentials.cookie)
    successor=request(case,actor=reviewer,target=other_id,key='retention-successor')
    row=world[1].snapshot((handoff_key(started['inspection_id'],successor['id']),))[handoff_key(started['inspection_id'],successor['id'])]
    assert successor['request']['expires_at_ms']<=deadline and integer(row.data['metadata_expires_at_ms'])<=deadline
    world[2].value=deadline
    with pytest.raises((ResourceUnavailable,StoreUnavailable)):service.read(reviewer,started['inspection_id'],successor['id'])


def test_handoff_blocks_new_capture_without_invoking_a_worker(world,recipe):
    from proofpack.capture.service import CaptureService
    case=setup_case(world,recipe);service,started,operator,*_=case;request(case)
    def forbidden(*args):raise AssertionError('review-required handoff cannot allocate a capture worker')
    capture=CaptureService(service.stations,worker_guard=forbidden)
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    with pytest.raises(StoreConflict,match='cannot accept capture'):
        capture.issue(operator,inspection_id=started['inspection_id'],expected_version=work.revision,expected_epoch=integer(work.data['station_epoch']),idempotency_key='forbidden-capture')
