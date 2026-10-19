"""Both observed frames must satisfy typed head invariants, even if == masks a type change."""
import pytest
from test_restore_runtime import setup,runtime,item
from proofpack.evidence.repository import Key,StoreUnavailable
from proofpack.runtime.control import RUNTIME,DATA


@pytest.mark.parametrize('head,field,value',[
    ('runtime','inspection_enabled',{'N':'0'}),
    ('runtime','runtime_epoch',{'BOOL':True}),
    ('data','epoch',{'BOOL':True}),
    ('marker','previous_data_epoch',{'BOOL':False})],
    ids=['runtime-enabled-number','runtime-epoch-bool','data-epoch-bool','marker-previous-bool'])
def test_second_frame_is_typed_even_when_python_numeric_equality_hides_corruption(head,field,value):
    access,fence,client,ids,clock=setup();original=runtime(access);original.start()
    marker=Key('state','runtime-start#'+original.instance_id);keys={'runtime':RUNTIME,'data':DATA,'marker':marker}
    native=access.repository.snapshot;frames=[]
    def corrupt_after_first_snapshot(requested):
        result=native(requested)
        if RUNTIME in requested and DATA in requested:
            frames.append(tuple(requested))
            if len(frames)==1:item(access.repository,client,keys[head])['data']['M'][field]=value
        return result
    access.repository.snapshot=corrupt_after_first_snapshot;client.calls.clear()
    observer=runtime(access,instance=original.instance_id)
    with pytest.raises(StoreUnavailable):observer.observe_startup()
    assert observer.handle is None and len(frames)==2
    assert not any(name in {'query','transact_write_items'} for name,_ in client.calls)
