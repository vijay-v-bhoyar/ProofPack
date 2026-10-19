"""Read-only protected startup observation on synthetic SDK rows."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import pytest

from test_restore_runtime import setup, runtime, plain, item
from test_restore_oauth import rotate
from proofpack.auth.service import AccessService
from proofpack.runtime.control import RUNTIME, DATA, ALLOCATION
from proofpack.evidence.repository import Key, StoreConflict, StoreUnavailable


def test_observe_exact_startup_returns_frozen_versions_without_handle_or_writes():
    access,fence,client,ids,clock=setup();original=runtime(access);handle=original.start()
    observer=runtime(access,instance=original.instance_id);before=deepcopy(client.items);client.calls.clear()
    result=observer.observe_startup()
    assert result.instance_id==handle.instance_id and result.runtime_epoch==handle.epoch
    assert result.data_epoch==result.startup_data_epoch==1
    assert result.restore_generation_sha256=='c'*64 and result.read_only is True and result.authority=='none'
    assert result.runtime_state_version>=1 and result.data_state_version==result.marker_state_version==1
    assert result.observed_at_ms==clock[0] and observer.handle is None
    assert client.items==before
    assert not any(name in {'transact_write_items','query'} for name,_ in client.calls)
    with pytest.raises(FrozenInstanceError):result.data_epoch=99


def test_unknown_commit_can_be_observed_without_repeating_startup_or_advancing_data():
    access,fence,client,ids,clock=setup();original=runtime(access);client.lost_reply=True
    with pytest.raises(StoreUnavailable):original.start()
    client.lost_reply=False;before=deepcopy(client.items);client.calls.clear()
    observer=runtime(access,instance=original.instance_id);result=observer.observe_startup()
    assert result.data_epoch==1 and observer.handle is None and original.handle is None
    assert client.items==before and not any(name=='transact_write_items' for name,_ in client.calls)


@pytest.mark.parametrize('fault',['missing-marker','different-instance','superseded','missing-data','missing-allocation','legacy','unfenced'])
def test_invalid_or_unprotected_observation_has_no_startup_fallback(fault):
    access,fence,client,ids,clock=setup();original=runtime(access);original.start()
    ident=original.instance_id;observer_access=access
    if fault=='missing-marker':client.items.pop(client.identity(access.repository.tables['state'],access.repository.key(Key('state','runtime-start#'+ident))))
    elif fault=='different-instance':ident=runtime(access).instance_id
    elif fault=='superseded':runtime(access).start()
    elif fault=='missing-data':client.items.pop(client.identity(access.repository.tables['state'],access.repository.key(DATA)))
    elif fault=='missing-allocation':client.items.pop(client.identity(access.repository.tables['state'],access.repository.key(ALLOCATION)))
    elif fault=='legacy':
        body=item(access.repository,client,Key('state','runtime-start#'+ident))['data']['M']
        for key in ('startup_schema_version','restore_generation_sha256','previous_data_epoch','data_epoch'):body.pop(key)
    else:observer_access=plain(access,client,clock)
    before=deepcopy(client.items);observer=runtime(observer_access,instance=ident);client.calls.clear()
    with pytest.raises((StoreConflict,StoreUnavailable)):observer.observe_startup()
    assert observer.handle is None and client.items==before
    assert not any(name in {'transact_write_items','query'} for name,_ in client.calls)


def test_changed_release_does_not_rebind_the_original_start():
    access,fence,client,ids,clock=setup();original=runtime(access);original.start()
    current_repo=rotate(access.repository,fence,client,ids);current=AccessService(current_repo,access.config,clock_ms=lambda:clock[0])
    before=deepcopy(client.items);observer=runtime(current,instance=original.instance_id)
    with pytest.raises((StoreUnavailable,StoreConflict)):observer.observe_startup()
    assert observer.handle is None and client.items==before


def test_visible_head_change_between_observation_snapshots_holds_without_retry():
    access,fence,client,ids,clock=setup();original=runtime(access);original.start()
    calls=[];old=access.repository.snapshot
    def changing(keys):
        result=old(keys)
        if RUNTIME in keys and DATA in keys:
            calls.append(tuple(keys))
            if len(calls)==1:
                raw=item(access.repository,client,DATA);raw['revision']={'N':str(int(raw['revision']['N'])+1)}
                raw['data']['M']['epoch']={'N':'2'}
        return result
    access.repository.snapshot=changing;observer=runtime(access,instance=original.instance_id)
    with pytest.raises(StoreUnavailable):observer.observe_startup()
    assert observer.handle is None and len(calls)==2


def test_observation_with_lost_protected_release_returns_no_diagnostic_authority():
    access,fence,client,ids,clock=setup();original=runtime(access);original.start();client.items.pop(ids[2])
    before=deepcopy(client.items);observer=runtime(access,instance=original.instance_id)
    with pytest.raises(StoreUnavailable):observer.observe_startup()
    assert observer.handle is None and client.items==before
