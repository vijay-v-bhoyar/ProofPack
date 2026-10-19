"""Real local SDK/storage, synthetic enrollment; no provider or erasure authority."""
from dataclasses import replace
from copy import deepcopy
import pytest
from botocore.exceptions import ReadTimeoutError
from test_access_lifecycle import repository_factory
from test_erasure_journal_store import journal_case
from test_journal_scope_store import scope_case
from proofpack.evidence.journal_scope import append_journal_scope
from proofpack.evidence.journal_anchors import JournalAnchorStore, JournalAnchorLimits
from proofpack.evidence.erasure_journal import JournalHeld, JournalConflict


def case(value):
    j,c,r,intents,keys,before,kw,digest=scope_case(value)
    store=JournalAnchorStore(j,genesis_sha256='9'*64,limits=JournalAnchorLimits(4,8,4096,256,10000))
    options={k:v for k,v in kw.items() if k!='limits'}
    root=store.initialize(**options)
    kw['limits']=replace(kw['limits'],max_sdk_calls=24,max_work=12)
    return store,j,c,r,intents,keys,before,kw,options,digest,root


def record(v):return append_journal_scope(v[1],v[4],expected_sha256=v[9],**v[7])
def seal(v,**changes):return v[0].seal(v[4],expected_head=v[10].checkpoint,scope_sha256=v[9],**(v[8]|changes))


def test_actual_atomic_seal_exact_retry_and_complete_checkpoint_traversal(journal_case):
    v=case(journal_case);record(v);point=seal(v)
    assert seal(v)==point
    result=v[0].read_history(expected_head=point.checkpoint,**v[8])
    assert result.scopes==1 and result.intents==2 and result.sealed_history_complete
    assert not any((result.can_erase,result.restore_authorized,result.request_fulfilled,result.global_history_complete,result.independent_iam_verified))
    assert v[3].inventory_snapshot(v[5])==v[6]


@pytest.mark.parametrize('phase',['initialize','seal'])
def test_actual_lost_transaction_reply_uses_durable_readback(journal_case,monkeypatch,phase):
    j,c,repo,intents,keys,before,kw,digest=scope_case(journal_case)
    store=JournalAnchorStore(j,genesis_sha256='9'*64,limits=JournalAnchorLimits(4,8,4096,256,10000))
    options={k:v for k,v in kw.items() if k!='limits'};call=c._make_api_call
    def lost(operation,parameters):
        result=call(operation,parameters)
        if operation=='TransactWriteItems':raise ReadTimeoutError(endpoint_url='http://synthetic-local-lost-reply')
        return result
    if phase=='initialize':
        monkeypatch.setattr(c,'_make_api_call',lost);assert store.initialize(**options).checkpoint.sequence==0
    else:
        root=store.initialize(**options)
        kw['limits']=replace(kw['limits'],max_sdk_calls=24,max_work=12);append_journal_scope(j,intents,expected_sha256=digest,**kw)
        monkeypatch.setattr(c,'_make_api_call',lost)
        assert store.seal(intents,expected_head=root.checkpoint,scope_sha256=digest,**options).checkpoint.sequence==1
    assert repo.inventory_snapshot(keys)==before


@pytest.mark.parametrize('fault',['anchor_missing','root_missing','intent_missing','anchor_corrupt'])
def test_actual_broken_history_never_accepts_partial_checkpoint(journal_case,fault):
    v=case(journal_case);record(v);point=seal(v).checkpoint
    store,j,c=v[:3]
    if fault=='intent_missing':key=j._key(v[4][0].reference_sha256,v[4][0].resource_sha256)
    else:key=store._key('anchor-root' if fault=='root_missing' else 'anchor#'+point.digest)
    if fault=='anchor_corrupt':
        value=c.get_item(TableName=j.table,Key=key,ConsistentRead=True)['Item'];value['sha256']['S']='f'*64;c.put_item(TableName=j.table,Item=value)
    else:c.delete_item(TableName=j.table,Key=key)
    with pytest.raises(JournalHeld):store.read_history(expected_head=point,**v[8])
    assert v[3].inventory_snapshot(v[5])==v[6]


def test_actual_competing_scope_cannot_advance_stale_original_head(journal_case):
    v=case(journal_case);record(v);first=seal(v)
    intents=tuple(replace(i,reference_sha256='7'*64) for i in v[4])
    from proofpack.evidence.journal_scope import journal_scope_sha256
    digest=journal_scope_sha256(v[1],intents,**v[7]);append_journal_scope(v[1],intents,expected_sha256=digest,**v[7])
    with pytest.raises(JournalConflict):v[0].seal(intents,expected_head=v[10].checkpoint,scope_sha256=digest,**v[8])
    second=v[0].seal(intents,expected_head=first.checkpoint,scope_sha256=digest,**v[8])
    assert v[0].read_history(expected_head=second.checkpoint,**v[8]).intents==4
    assert v[3].inventory_snapshot(v[5])==v[6]


def test_actual_manifest_keeps_original_scope_and_primary_rows(journal_case):
    v=case(journal_case);record(v);point=seal(v)
    result=v[0].read_manifest(expected_head=point.checkpoint,**v[8])
    assert result.receipt.sealed_history_complete and result.receipt.intents==2
    assert result.source_deployment==v[3].deployment
    assert result.source_tables==tuple(sorted(v[3].tables.items()))
    assert result.journal_arn==v[1].table_arn
    assert len(result.scopes)==1 and result.scopes[0].checkpoint==point.checkpoint
    assert result.scopes[0].scope_sha256==v[9] and result.scopes[0].intents==v[4]
    assert not any((result.receipt.can_erase,result.receipt.restore_authorized,result.receipt.request_fulfilled))
    assert v[3].inventory_snapshot(v[5])==v[6]


def test_actual_empty_manifest_has_no_invented_intents(journal_case):
    v=case(journal_case);result=v[0].read_manifest(expected_head=v[10].checkpoint,**v[8])
    assert result.scopes==() and result.receipt.intents==0
    assert v[3].inventory_snapshot(v[5])==v[6]


@pytest.mark.parametrize('fault',['anchor_missing','root_missing','intent_missing','anchor_corrupt'])
def test_actual_manifest_never_returns_partial_broken_history(journal_case,fault):
    v=case(journal_case);record(v);point=seal(v).checkpoint;store,j,c=v[:3]
    if fault=='intent_missing':key=j._key(v[4][0].reference_sha256,v[4][0].resource_sha256)
    else:key=store._key('anchor-root' if fault=='root_missing' else 'anchor#'+point.digest)
    if fault=='anchor_corrupt':
        value=c.get_item(TableName=j.table,Key=key,ConsistentRead=True)['Item'];value['sha256']['S']='f'*64;c.put_item(TableName=j.table,Item=value)
    else:c.delete_item(TableName=j.table,Key=key)
    with pytest.raises(JournalHeld):store.read_manifest(expected_head=point,**v[8])
    assert v[3].inventory_snapshot(v[5])==v[6]
