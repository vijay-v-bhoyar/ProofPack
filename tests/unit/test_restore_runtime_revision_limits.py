"""A readable final row revision cannot be used as a new previous revision."""
from copy import deepcopy
import pytest
from test_restore_runtime import setup, runtime, item
from proofpack.runtime.control import RUNTIME, DATA
from proofpack.evidence.repository import StoreUnavailable


@pytest.mark.parametrize('head',[RUNTIME,DATA])
def test_exhausted_physical_revision_holds_startup_before_linked_write_preparation(head):
    access,fence,client,ids,clock=setup();runtime(access).start()
    item(access.repository,client,head)['revision']={'N':str(2**63-1)}
    before=deepcopy(client.items);current=runtime(access)
    with pytest.raises(StoreUnavailable):current.start()
    assert current.handle is None and client.items==before
