"""Exact physical startup revision identities; synthetic SDK metadata only."""
from copy import deepcopy
import pytest
from test_restore_runtime import setup, runtime, item
from proofpack.evidence.repository import Key, StoreUnavailable


@pytest.mark.parametrize('revision',[{'BOOL':True},{'N':'1.5'},{'S':'1'},{'N':'0'},{'N':'-1'},
    {'N':'NaN'},{'N':'Infinity'},{'N':str(2**63)}],
    ids=['boolean','fraction','string','zero','negative','nan','infinity','overflow'])
@pytest.mark.parametrize('entry',['snapshot','startup'])
def test_physical_revision_cannot_be_coerced_into_an_immutable_startup_identity(revision,entry):
    access,fence,client,ids,clock=setup();first=runtime(access);first.start()
    key=Key('state','runtime-start#'+first.instance_id)
    item(access.repository,client,key)['revision']=revision
    before=deepcopy(client.items);retry=runtime(access,instance=first.instance_id)
    with pytest.raises(StoreUnavailable):
        if entry=='snapshot':access.repository.snapshot((key,))
        else:retry.start()
    assert retry.handle is None and client.items==before


@pytest.mark.parametrize('encoded,expected',[('1',1),('1.0',1),(str(2**63-1),2**63-1)])
def test_lossless_physical_revision_range_remains_readable(encoded,expected):
    access,fence,client,ids,clock=setup();first=runtime(access);first.start()
    key=Key('state','runtime-start#'+first.instance_id)
    item(access.repository,client,key)['revision']={'N':encoded}
    actual=access.repository.snapshot((key,))[key]
    assert type(actual.revision) is int and actual.revision==expected
