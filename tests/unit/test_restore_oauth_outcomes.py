"""Late/unknown OAuth outcomes remain spent; no provider exchange is performed."""
from copy import deepcopy
import pytest

from test_restore_oauth import setup, flows, parts, row
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import StoreUnavailable


@pytest.mark.parametrize('operation',['begin','consume'])
@pytest.mark.parametrize('fault',['expiry','backwards'])
def test_final_binding_check_cannot_extend_absolute_expiry_or_move_time_back(operation,fault):
    repo,fence,client,ids,clock,config=setup();service=flows(repo,clock,config)
    started=service.begin();state,cookie=parts(started);original=client.transact_write_items;commits=[]
    def advance(**kwargs):
        result=original(**kwargs);commits.append(deepcopy(kwargs))
        clock[0]=started.expires_at_ms if fault=='expiry' else clock[0]-1
        return result
    client.transact_write_items=advance
    with pytest.raises(Denied):
        if operation=='begin':service.begin()
        else:service.consume(state=state,browser_cookie=cookie)
    assert len(commits)==1
    if operation=='consume':
        assert row(repo,client,state)['data']['M']['status']=={'S':'consumed'}


@pytest.mark.parametrize('operation',['begin','consume'])
def test_lost_write_reply_returns_no_material_and_does_not_refund_or_reopen(operation):
    repo,fence,client,ids,clock,config=setup();service=flows(repo,clock,config)
    state,cookie=parts(service.begin());client.calls.clear();client.lost_reply=True
    with pytest.raises(StoreUnavailable):
        if operation=='begin':service.begin()
        else:service.consume(state=state,browser_cookie=cookie)
    writes=[kw for name,kw in client.calls if name=='transact_write_items']
    assert len(writes)==1
    client.lost_reply=False
    if operation=='consume':
        assert row(repo,client,state)['data']['M']['status']=={'S':'consumed'}
        with pytest.raises(Denied):service.consume(state=state,browser_cookie=cookie)
    else:
        pending=[v for (_,_,key),v in client.items.items() if key.startswith('oauth-flow#')]
        quota=next(v for (_,_,key),v in client.items.items() if key=='oauth-quota#login')
        assert len(pending)==2 and quota['data']['M']['count']=={'N':'2'}
        assert all(v['data']['M']['status']=={'S':'pending'} for v in pending)
