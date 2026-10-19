"""Unmodified access writers on modeled storage; no provider or user proof."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from decimal import Decimal
import pytest
from botocore.client import BaseClient
from test_auth_head_integrity import world
from proofpack.auth.service import IdentityProof, digest
from proofpack.auth.policy import Role
from proofpack.evidence.repository import Key


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args, **kwargs): raise AssertionError('pure transfer history attempted SDK')
    monkeypatch.setattr(BaseClient, '_make_api_call', deny)


def family(accepted=False):
    access, repo, owner_proof, credentials, owner_id = world()
    access.config = replace(access.config, notice_version='synthetic-v1', notice_text='synthetic notice')
    invite = access.create_invitation(access.resolve(credentials.cookie), target_subject='transfer-target',
        target_email='target@example.test', roles=[Role.OPERATOR.value], ttl_seconds=60, idempotency_key='invite')
    target_proof = IdentityProof(owner_proof.issuer, 'transfer-target', 'target@example.test',
        True, True, 1000, 100000, 'Synthetic target')
    restricted = access.login(target_proof, invitation_id=invite['id'])
    access.accept_invitation(access.resolve(restricted.cookie, allow_invitee=True), invitation_id=invite['id'],
        capability=invite['capability'], idempotency_key='accept-invite',
        notice_version='synthetic-v1', notice_sha256=digest('synthetic notice'))
    target_credentials = access.login(target_proof)
    target = access.resolve(target_credentials.cookie)
    transfer = access.begin_transfer(access.resolve(credentials.cookie), target_id=target.member.data['id'],
        expected_target_version=1, idempotency_key='begin')
    if accepted:
        access.accept_transfer(target, transfer_id=transfer['id'], idempotency_key='accept')
    root = repo.rows[Key('state', 'owner-transfer#'+transfer['id'])]
    rows = tuple(row for row in repo.rows.values() if
        row.data.get('resource_bindings', {}).get('operation') in {'begin-transfer', 'accept-transfer'})
    return root, rows, repo


def limits():
    from proofpack.evidence.transfer_history import TransferHistoryLimits
    return TransferHistoryLimits(100, 1000000, 100, 10000, 100000)


def run(root, rows, **kwargs):
    from proofpack.evidence.transfer_history import discover
    return discover(root, rows, **({'deployment':'synthetic', 'limits':limits(),
        'deadline_ns':10000, 'tick':lambda:1, 'checkpoint':lambda:None} | kwargs))


@pytest.mark.parametrize('accepted', [False, True])
def test_real_writer_history_is_immutable_deterministic_private_and_non_authorizing(accepted):
    root, rows, repo = family(accepted); before = deepcopy(repo.rows)
    result = run(root, rows)
    assert result.state == ('ACCEPTED_HISTORY' if accepted else 'PENDING_HISTORY')
    assert result == run(root, tuple(reversed(rows))) and repo.rows == before
    assert len(result.records) == 1+len(rows) and result.dependencies
    assert result.historical is True and result.read_only is True
    assert result.can_confirm_cleanup is False and result.grants_current_access is False
    assert all(token not in repr(result) for token in
        (root.data['id'], root.data['source_id'], root.data['target_id'], 'cookie#', 'session#'))
    with pytest.raises(FrozenInstanceError): result.work = 0


@pytest.mark.parametrize('accepted', [False, True])
def test_integral_decimal_storage_variants(accepted):
    root, rows, _ = family(accepted)
    def stored(v):
        if type(v) is int: return Decimal(v)
        if type(v) is dict: return {k:stored(x) for k,x in v.items()}
        if type(v) is list: return [stored(x) for x in v]
        return v
    assert run(root, rows) == run(replace(root, data=stored(root.data)),
        tuple(replace(row, data=stored(row.data)) for row in rows))


@pytest.mark.parametrize('fault', ['extra-root', 'same-target', 'bool-version', 'float-version',
    'nan-version', 'sNaN-version', 'infinite-version', 'zero-version', 'wrong-key', 'wrong-revision',
    'unknown-state', 'bad-expiry', 'missing-begin', 'missing-accept', 'missing-replay',
    'duplicate', 'foreign', 'extra-event', 'extra-result', 'changed-body', 'changed-root',
    'changed-peer-binding', 'wrong-actor-user', 'changed-session', 'late-accept', 'accept-before-begin'])
def test_corrupt_or_incomplete_history_holds(fault):
    from proofpack.evidence.transfer_history import TransferHistoryHeld
    root, rows, _ = family(True); root = deepcopy(root); rows = deepcopy(rows); kwargs = {}
    begin = next(row for row in rows if row.key.table=='events' and row.data['kind']=='begin-transfer')
    accept = next(row for row in rows if row.key.table=='events' and row.data['kind']=='accept-transfer')
    replay = next(row for row in rows if row.key.table=='state' and row.data['resource_bindings']['operation']=='begin-transfer')
    if fault=='extra-root': root.data['inspection_id']='private'
    elif fault=='same-target': root.data['target_id']=root.data['source_id']
    elif fault.endswith('-version'):
        root.data['source_version']={'bool-version':True,'float-version':1.0,'nan-version':Decimal('NaN'),
            'sNaN-version':Decimal('sNaN'),'infinite-version':Decimal('Infinity'),'zero-version':0}[fault]
    elif fault=='wrong-key': root=replace(root,key=Key('events',root.key.resource))
    elif fault=='wrong-revision': root=replace(root,revision=True)
    elif fault=='unknown-state': root.data['status']='finished'
    elif fault=='bad-expiry': root.data['expires_at_ms']=0
    elif fault=='missing-begin': rows=tuple(row for row in rows if row.data['resource_bindings']['operation']!='begin-transfer')
    elif fault=='missing-accept': rows=tuple(row for row in rows if row.data['resource_bindings']['operation']!='accept-transfer')
    elif fault=='missing-replay': rows=tuple(row for row in rows if row!=replay)
    elif fault=='duplicate': rows+=rows[:1]
    elif fault=='foreign': kwargs['deployment']='foreign'
    elif fault=='extra-event': begin.data['inspection_id']='private'
    elif fault=='extra-result': replay.data['result']['inspection_id']='private'
    elif fault=='changed-body': replay.data['body_hash']='0'*64
    elif fault=='changed-root': root.data['source_version']+=1
    elif fault=='changed-peer-binding': begin.data['resource_bindings']['checks'][0]['sha256']='0'*64
    elif fault=='wrong-actor-user':
        for row in rows:
            if row.data['resource_bindings']['operation']=='begin-transfer':
                for ref in row.data['resource_bindings']['checks']:
                    if ref['resource']=='user#'+root.data['source_id']: ref['resource']='user#'+root.data['id']
                row.data['resource_bindings']['checks'].sort(key=lambda ref:(ref['table'],ref['resource']))
    elif fault=='changed-session': begin.data['session_id']=root.data['id']
    elif fault=='late-accept': accept.data['at_ms']=root.data['expires_at_ms']
    elif fault=='accept-before-begin': accept.data['at_ms']=0
    with pytest.raises(TransferHistoryHeld): run(root,rows,**kwargs)


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
def test_each_exact_budget_and_one_below(field):
    from proofpack.evidence.transfer_history import TransferHistoryHeld
    root,rows,_=family(True);value=run(root,rows)
    amount={'max_records':len(value.records),'max_payload_bytes':value.payload_bytes,
        'max_dependencies':len(value.dependencies),'max_work':value.work,'max_summary_bytes':value.summary_bytes}[field]
    assert run(root,rows,limits=replace(limits(),**{field:amount}))==value
    with pytest.raises(TransferHistoryHeld): run(root,rows,limits=replace(limits(),**{field:amount-1}))


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
@pytest.mark.parametrize('value',[True,0,-1,'1',1.5,2**63])
def test_implicit_or_unbounded_limits_rejected(field,value):
    with pytest.raises(ValueError): replace(limits(),**{field:value})


@pytest.mark.parametrize('fault',['deadline','backwards','checkpoint','mutate-root'])
def test_original_fence_and_source_mutation_never_publish_partial_history(fault):
    from proofpack.evidence.transfer_history import TransferHistoryHeld
    root,rows,_=family(True);calls=[0]
    def check():
        calls[0]+=1
        if calls[0]==8:
            if fault=='checkpoint': raise RuntimeError('original authority lost')
            if fault=='mutate-root': root.data['target_version']+=1
    ticks=iter([1,0])
    kwargs={'checkpoint':check}
    if fault=='deadline':kwargs['tick']=lambda:10000
    if fault=='backwards':kwargs['tick']=lambda:next(ticks,0)
    with pytest.raises(RuntimeError if fault=='checkpoint' else TransferHistoryHeld):run(root,rows,**kwargs)


def test_deadline_expiry_during_final_authority_callback_cannot_publish_history():
    from proofpack.evidence.transfer_history import TransferHistoryHeld
    root,rows,_=family(True);measure=[0]
    def measured():measure[0]+=1
    run(root,rows,checkpoint=measured)
    calls=[0];now=[1]
    def expires():
        calls[0]+=1
        if calls[0]==measure[0]:now[0]=10000
    with pytest.raises(TransferHistoryHeld):run(root,rows,checkpoint=expires,tick=lambda:now[0])


@pytest.mark.parametrize('fault',['creation-sha','accepted-sha','extra-check','extra-write','accept-body','truthy-result'])
def test_matching_peer_envelopes_still_require_exact_business_semantics(fault):
    from proofpack.evidence.transfer_history import TransferHistoryHeld
    root,rows,_=family(True);rows=deepcopy(rows)
    operation='begin-transfer' if fault=='creation-sha' else 'accept-transfer'
    peers=[row for row in rows if row.data['resource_bindings']['operation']==operation]
    for row in peers:
        binding=row.data['resource_bindings']
        if fault in {'creation-sha','accepted-sha'}:
            next(ref for ref in binding['writes'] if ref['resource']==root.key.resource)['sha256']='0'*64
        elif fault=='extra-check':
            binding['checks'].append({'table':'state','resource':'unknown-context','revision':1,'sha256':'a'*64})
            binding['checks'].sort(key=lambda ref:(ref['table'],ref['resource']))
        elif fault=='extra-write':
            binding['writes'].append({'table':'state','resource':'unknown-content','previous_revision':None,'revision':1,'sha256':'a'*64})
            binding['writes'].sort(key=lambda ref:(ref['table'],ref['resource']))
        elif row.key.table=='state':
            if fault=='accept-body':row.data['body_hash']='0'*64
            else:row.data['result']['sign_in_required']=1
    with pytest.raises(TransferHistoryHeld):run(root,rows)


def test_mutation_in_last_authority_callback_is_detected():
    from proofpack.evidence.transfer_history import TransferHistoryHeld
    root,rows,_=family(True);measure=[0]
    def measured():measure[0]+=1
    run(root,rows,checkpoint=measured)
    calls=[0]
    def mutates():
        calls[0]+=1
        if calls[0]==measure[0]:root.data['target_version']+=1
    with pytest.raises(TransferHistoryHeld):run(root,rows,checkpoint=mutates)
