"""Genuine auth/runtime/station writers, modeled station rows; no SDK or CV proof."""
from copy import deepcopy
from uuid import uuid4
import pytest
from test_auth_head_integrity import world, no_sdk
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import Write, StoreConflict, StoreUnavailable
from proofpack.recipes.service import RecipeService
from proofpack.runtime.control import RuntimeControl
from proofpack.stations.service import StationService, station_key, inspection_key


def setup():
    access, repo, proof, credentials, uid = world()
    owner = access.resolve(credentials.cookie)
    access.change_access(owner, user_id=uid, roles=['owner','operator'], enabled=True,
        expected_version=owner.member.data['access_version'], idempotency_key='explicit-combined-duty')
    credentials = access.login(proof)
    operator = access.resolve(credentials.cookie)
    runtime = RuntimeControl(access, instance_id=str(uuid4()), artifact_sha256='a'*64,
        controls_sha256='b'*64, environment='test')
    runtime.start()
    recipes = RecipeService(access, environment='test', artifact_sha256='a'*64)
    service = StationService(access, runtime, recipes)
    sid, ident = str(uuid4()), str(uuid4())
    # Minimal representative model rows, not an enrolled/qualified station claim.
    repo.transact((
        Write(station_key(sid), None, {'id':sid, 'epoch':1, 'active_inspection_id':ident,
            'owner_session_id':operator.session.data['id']}),
        Write(inspection_key(ident), None, {'id':ident, 'station_id':sid, 'station_epoch':1,
            'state':'CREATED', 'pending_sequence':None, 'latest_disposition_id':None,
            'originating_user_id':uid, 'originating_session_id':operator.session.data['id']}),
    ))
    args = dict(inspection_id=ident, expected_version=1, expected_epoch=1, disposition='rework',
        reason='Synthetic manual recheck', human_check_confirmed=False, idempotency_key='same-intent')
    return service, operator, credentials, proof, args


@pytest.mark.parametrize('boundary', ['same-intent', 'changed-body', 'revoked-session'])
def test_delayed_replay_observation_uses_original_result_only_for_exact_current_actor(monkeypatch, boundary):
    service, operator, credentials, proof, args = setup()
    access, repo = service.access, service.repository
    original = access._idempotency
    reached = []
    winner = []
    expected = {}

    def interleave(actor, operation, key, body):
        observed = original(actor, operation, key, body)
        if operation == 'inspection-disposition:'+args['inspection_id'] and not reached:
            assert observed[2] is None
            reached.append(operation)
            winning = {**args, 'reason':'Different original intent'} if boundary=='changed-body' else args
            winner.append(service.record_disposition(operator, **winning))
            if boundary=='revoked-session': access.logout(credentials.cookie, credentials.csrf)
            expected.update(deepcopy(repo.rows))
        return observed

    monkeypatch.setattr(access, '_idempotency', interleave)
    try:
        if boundary=='same-intent':
            delayed = service.record_disposition(operator, **args)
            assert delayed == winner[0]
            assert delayed['decision']['machine_approval'] is delayed['decision']['independent_truth_verified'] is False
        else:
            with pytest.raises((Denied,StoreConflict)):
                service.record_disposition(operator, **args)
    finally:
        assert reached and expected and repo.rows == expected
    assert sum(k.resource.startswith('human-disposition#') for k in repo.rows) == 1


@pytest.mark.parametrize('fault', ['version','epoch','pending','closed','foreign-session'])
def test_absent_matching_replay_preserves_current_write_denials(fault):
    service, operator, credentials, proof, args = setup()
    repo = service.repository
    key = inspection_key(args['inspection_id'])
    if fault=='version': args['expected_version'] = 99
    elif fault=='epoch': args['expected_epoch'] = 99
    elif fault in {'pending','closed'}:
        row = repo.snapshot((key,))[key]
        repo.transact((Write(key,row.revision,{**row.data,**({'pending_sequence':1} if fault=='pending' else {'state':'CLOSED'})}),))
        args['expected_version'] = 2
    else:
        credentials = service.access.login(proof)
        operator = service.access.resolve(credentials.cookie)
    before = deepcopy(repo.rows)
    with pytest.raises((Denied,StoreConflict)):
        service.record_disposition(operator, **args)
    assert repo.rows == before


def test_lost_commit_reply_preserves_original_exact_record_and_rejects_body_reuse():
    service, operator, credentials, proof, args = setup()
    repo = service.repository
    repo.lose_reply = True
    with pytest.raises(StoreUnavailable): service.record_disposition(operator, **args)
    before = deepcopy(repo.rows)
    replay = service.record_disposition(operator, **args)
    assert replay['inspection_state_version'] == 2 and repo.rows == before
    assert sum(k.resource.startswith('human-disposition#') for k in repo.rows) == 1
    with pytest.raises(StoreConflict): service.record_disposition(operator, **{**args,'reason':'Changed body'})
    assert repo.rows == before
