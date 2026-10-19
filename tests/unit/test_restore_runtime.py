"""Protected source runtime transitions on synthetic release/SDK rows only."""
from copy import deepcopy
from uuid import uuid4
import pytest

from restore_consumer_model import auth_world
from test_restore_oauth import rotate
from proofpack.auth.service import AccessService
from proofpack.evidence.repository import DynamoRepository, Key, StoreUnavailable, StoreConflict
from proofpack.runtime.control import RuntimeControl, RUNTIME, DATA, ALLOCATION


def runtime(access, *, instance=None, artifact=None):
    return RuntimeControl(access,instance_id=instance or str(uuid4()),
        artifact_sha256=artifact or 'b'*64,controls_sha256='e'*64,environment='test')


def setup():
    access,fence,client,ids,proof,clock=auth_world()
    return access,fence,client,ids,clock


def item(repo,client,key):
    return client.items[client.identity(repo.tables[key.table],repo.key(key))]


def plain(access,client,clock):
    repo=DynamoRepository(client,deployment=access.repository.deployment,state_table=access.repository.tables['state'],
        events_table=access.repository.tables['events'])
    return AccessService(repo,access.config,clock_ms=lambda:clock[0])


def test_protected_first_start_and_new_incarnation_advance_data_atomically_without_enablement():
    access,fence,client,ids,clock=setup();first=runtime(access);first.start()
    first_data=access.repository.snapshot((DATA,))[DATA]
    marker=Key('state','runtime-start#'+first.instance_id)
    row=access.repository.snapshot((marker,))[marker]
    assert row.data['startup_schema_version']==2
    assert row.data['restore_generation_sha256']==fence.generation_sha256()=='c'*64
    assert (row.data['previous_data_epoch'],row.data['data_epoch'],first_data.data['epoch'])==(0,1,1)
    before=access.repository.snapshot((RUNTIME,DATA,ALLOCATION))
    second=runtime(access);second.start();after=access.repository.snapshot((RUNTIME,DATA,ALLOCATION))
    assert after[DATA].data['epoch']==2 and after[DATA].revision==first_data.revision+1
    assert after[RUNTIME].data['runtime_epoch']==before[RUNTIME].data['runtime_epoch']+1
    assert after[RUNTIME].data['control_version']==before[RUNTIME].data['control_version']+1
    assert after[RUNTIME].data['inspection_enabled'] is False
    assert after[RUNTIME].data['enable_receipt_id'] is None and after[ALLOCATION]==before[ALLOCATION]
    transaction=[v for name,v in client.calls if name=='transact_write_items'][-1]
    keys={v['Put']['Item']['sk']['S'] for v in transaction['TransactItems'] if 'Put' in v}
    assert {'runtime','data-authority','runtime-start#'+second.instance_id}<=keys


def test_exact_retry_and_new_object_readback_do_not_repeat_data_advancement():
    access,fence,client,ids,clock=setup();first=runtime(access);handle=first.start()
    before=deepcopy(client.items);client.calls.clear()
    assert first.start()==handle and runtime(access,instance=first.instance_id).start()==handle
    assert client.items==before and not any(n=='transact_write_items' for n,_ in client.calls)


def test_unknown_commit_reply_requires_exact_readback_without_new_epoch_or_event():
    access,fence,client,ids,clock=setup();first=runtime(access);client.lost_reply=True
    with pytest.raises(StoreUnavailable):first.start()
    assert first.handle is None
    client.lost_reply=False;before=deepcopy(client.items);handle=first.start()
    marker=access.repository.snapshot((Key('state','runtime-start#'+first.instance_id),))[Key('state','runtime-start#'+first.instance_id)]
    assert marker.data['startup_schema_version']==2 and handle.epoch==1 and client.items==before
    assert len([v for (_,_,key),v in client.items.items() if key.startswith('runtime#')])==1


def test_superseded_marker_cannot_reclaim_current_runtime_or_return_old_handle():
    access,fence,client,ids,clock=setup();first=runtime(access);first.start();runtime(access).start()
    before=deepcopy(client.items);stale=runtime(access,instance=first.instance_id)
    with pytest.raises((StoreConflict,StoreUnavailable)):stale.start()
    assert stale.handle is None and client.items==before


def test_changed_release_rejects_old_marker_and_fresh_incarnation_rotates_data():
    access,fence,client,ids,clock=setup();first=runtime(access);first.start()
    current_repo=rotate(access.repository,fence,client,ids)
    current=AccessService(current_repo,access.config,clock_ms=lambda:clock[0]);before=deepcopy(client.items)
    old=runtime(current,instance=first.instance_id)
    with pytest.raises((StoreConflict,StoreUnavailable)):old.start()
    assert old.handle is None and client.items==before
    fresh=runtime(current);fresh.start()
    assert current_repo.snapshot((DATA,))[DATA].data['epoch']==2
    assert current_repo.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
    with pytest.raises(StoreUnavailable):first.start()


@pytest.mark.parametrize('direction',['legacy-to-protected','protected-to-unfenced'])
def test_startup_marker_cannot_cross_protection_boundary(direction):
    access,fence,client,ids,clock=setup();unfenced=plain(access,client,clock)
    writer,reader=(unfenced,access) if direction=='legacy-to-protected' else (access,unfenced)
    first=runtime(writer);first.start();before=deepcopy(client.items)
    second=runtime(reader,instance=first.instance_id)
    with pytest.raises((StoreConflict,StoreUnavailable)):second.start()
    assert second.handle is None and client.items==before


@pytest.mark.parametrize('fault',['boolean_version','float_version','missing_generation','uppercase_generation','extra_field','bad_previous_epoch','nonincrementing_epoch'])
def test_corrupt_startup_marker_never_returns_a_handle_or_repairs_history(fault):
    access,fence,client,ids,clock=setup();first=runtime(access);first.start()
    body=item(access.repository,client,Key('state','runtime-start#'+first.instance_id))['data']['M']
    if fault=='boolean_version':body['startup_schema_version']={'BOOL':True}
    elif fault=='float_version':
        # A nonintegral Dynamo number is retained losslessly and rejected.
        body['startup_schema_version']={'N':'2.5'}
    elif fault=='missing_generation':body.pop('restore_generation_sha256',None)
    elif fault=='uppercase_generation':body['restore_generation_sha256']={'S':'A'*64}
    elif fault=='extra_field':body['unreviewed']={'BOOL':True}
    elif fault=='bad_previous_epoch':body['previous_data_epoch']={'N':'-1'}
    else:body['data_epoch']={'N':'0'}
    before=deepcopy(client.items);retry=runtime(access,instance=first.instance_id)
    with pytest.raises((StoreUnavailable,StoreConflict)):retry.start()
    assert retry.handle is None and client.items==before


@pytest.mark.parametrize('head,field',[(DATA,'epoch'),(RUNTIME,'runtime_epoch'),(RUNTIME,'control_version')])
def test_exhausted_startup_counter_holds_without_partial_write(head,field):
    access,fence,client,ids,clock=setup();runtime(access).start()
    item(access.repository,client,head)['data']['M'][field]={'N':str(2**63-2)}
    before=deepcopy(client.items);next_runtime=runtime(access)
    with pytest.raises(StoreUnavailable):next_runtime.start()
    assert next_runtime.handle is None and client.items==before


@pytest.mark.parametrize('head',[DATA,ALLOCATION])
def test_missing_existing_head_is_not_recreated_by_protected_start(head):
    access,fence,client,ids,clock=setup();runtime(access).start()
    client.items.pop(client.identity(access.repository.tables[head.table],access.repository.key(head)))
    before=deepcopy(client.items)
    with pytest.raises(StoreUnavailable):runtime(access).start()
    assert client.items==before


def test_wrong_runtime_artifact_cannot_use_protected_release():
    access,fence,client,ids,clock=setup();before=deepcopy(client.items);wrong=runtime(access,artifact='f'*64)
    with pytest.raises(StoreUnavailable):wrong.start()
    assert wrong.handle is None and client.items==before


def test_concurrent_data_revision_change_blocks_entire_runtime_commit():
    access,fence,client,ids,clock=setup();runtime(access).start();before=deepcopy(client.items)
    raw=item(access.repository,client,DATA)
    def change():
        raw['revision']={'N':str(int(raw['revision']['N'])+1)}
        raw['data']['M']['epoch']={'N':'2'}
    client.before_commit=change;next_runtime=runtime(access)
    with pytest.raises(StoreConflict):next_runtime.start()
    expected=deepcopy(before);expected[client.identity(access.repository.tables['state'],access.repository.key(DATA))]=deepcopy(raw)
    assert next_runtime.handle is None and client.items==expected


@pytest.mark.parametrize('when',['before-commit','after-commit'])
def test_release_revocation_never_returns_startup_handle(when):
    access,fence,client,ids,clock=setup();first=runtime(access);before=deepcopy(client.items)
    if when=='before-commit':client.before_commit=lambda:client.items.pop(ids[2],None)
    else:
        original=client.transact_write_items
        def revoke(**kwargs):
            result=original(**kwargs);client.items.pop(ids[2]);return result
        client.transact_write_items=revoke
    with pytest.raises((StoreConflict,StoreUnavailable)):first.start()
    assert first.handle is None
    if when=='before-commit':
        before.pop(ids[2]);assert client.items==before
    else:
        assert item(access.repository,client,DATA)['data']['M']['epoch']=={'N':'1'}
