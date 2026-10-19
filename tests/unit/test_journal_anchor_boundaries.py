"""Additional original-budget and canonical-item probes."""
from dataclasses import replace
from copy import deepcopy
import pytest
from test_journal_anchors import world, init, prepare, seal, opts, row
from proofpack.evidence.journal_anchors import JournalAnchorStore
from proofpack.evidence.erasure_journal import JournalHeld


@pytest.mark.parametrize('operation',['initialize','seal','history'])
@pytest.mark.parametrize('field',['max_sdk_calls','max_work'])
def test_exact_reserved_capacity_passes_and_one_below_holds(operation,field):
    v=world();root=init(v)
    if operation=='seal':prepare(v);expected_calls,expected_work=21,80
    elif operation=='history':prepare(v);point=seal(v,root.checkpoint).checkpoint;expected_calls,expected_work=69,176
    else:expected_calls,expected_work=10,32
    exact=expected_calls if field=='max_sdk_calls' else expected_work
    for delta in [0,-1]:
        vv=world();rr=init(vv) if operation!='initialize' else None
        if operation!='initialize':prepare(vv)
        if operation=='history':pp=seal(vv,rr.checkpoint).checkpoint
        bounds=replace(vv[0].limits,**{field:exact+delta})
        store=JournalAnchorStore(vv[1],genesis_sha256='9'*64,limits=bounds)
        vv=(store,*vv[1:]);before=deepcopy(vv[2].items)
        def execute():
            if operation=='initialize':return init(vv)
            if operation=='seal':return seal(vv,rr.checkpoint)
            return store.read_history(expected_head=pp,**opts())
        if delta==0:assert execute().historical
        else:
            with pytest.raises(JournalHeld):execute()
            assert vv[2].items==before


def test_full_anchor_item_byte_bound_is_checked_before_atomic_commit():
    v=world();root=init(v);prepare(v)
    # The root fits this limit but the complete two-intent anchor does not.
    bounds=replace(v[0].limits,max_item_bytes=900)
    store=JournalAnchorStore(v[1],genesis_sha256='9'*64,limits=bounds)
    before=deepcopy(v[2].items)
    with pytest.raises(JournalHeld):seal((store,*v[1:]),root.checkpoint)
    assert v[2].items==before


def test_backward_clock_holds_before_effects():
    v=world();values=iter([10,9])
    with pytest.raises(JournalHeld):init(v,tick=lambda:next(values))
    assert not v[2].calls


def test_configured_limits_cannot_change_during_original_operation():
    v=world();count=[0]
    def changed():
        count[0]+=1
        if count[0]==2:object.__setattr__(v[0].limits,'max_sdk_calls',True)
    with pytest.raises(JournalHeld):init(v,checkpoint=changed)
    assert not v[2].calls
