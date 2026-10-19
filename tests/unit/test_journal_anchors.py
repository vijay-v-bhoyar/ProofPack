"""Local SDK model protocol, not independent IAM, provider or restore evidence."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import json
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError
from test_erasure_journal import Client, setup, append
from proofpack.evidence.erasure_journal import DynamoErasureJournal, JournalHeld, JournalConflict
from proofpack.evidence.journal_scope import JournalScopeLimits, journal_scope_sha256
from proofpack.evidence.journal_anchors import JournalAnchorStore, JournalAnchorLimits, AnchorCheckpoint


class AnchorClient(Client):
    def __init__(self):super().__init__();self.after_transaction=None
    def query(self,**kw):
        self.calls.append(('query',deepcopy(kw)))
        assert kw['ConsistentRead'] and kw['Limit']==1
        items=[deepcopy(v) for k,v in self.items.items() if k[0]==kw['ExpressionAttributeValues'][':pk']['S']][:1]
        return {'Count':len(items),'Items':items}
    def transact_write_items(self,**kw):
        self.calls.append(('transact_write_items',deepcopy(kw)))
        changes=[]
        for row in kw['TransactItems']:
            v=row['Put'];key=tuple(v['Item'][k]['S'] for k in ('pk','sk'));old=self.items.get(key)
            if (v['ConditionExpression'].startswith('attribute_not_exists') and old is not None
                    or v['ConditionExpression']=='#body = :old' and (old is None or old['body']!=v['ExpressionAttributeValues'][':old'])):
                raise ClientError({'Error':{'Code':'TransactionCanceledException'}},'TransactWriteItems')
            changes.append((key,deepcopy(v['Item'])))
        self.items.update(changes)
        if self.after_transaction:self.after_transaction()
        return {}


def world():
    journal,_,repo,intent=setup();client=AnchorClient();repo.client=client
    journal=DynamoErasureJournal(repo,journal_table=journal.table,expected_table_arn=journal.table_arn,limits=journal.limits)
    store=JournalAnchorStore(journal,genesis_sha256='9'*64,limits=JournalAnchorLimits(4,12,4096,256,10000))
    intents=tuple(replace(intent,resource_sha256=x*64) for x in ('1','2'))
    return store,journal,client,intents


def opts(**changes):return dict(deadline_ns=1000,tick=lambda:1,checkpoint=lambda:None)|changes


def init(v,**changes):return v[0].initialize(**opts(**changes))


def seal(v,point,**changes):
    store,journal,client,intents=v
    bounds=JournalScopeLimits(len(intents),4096,5*len(intents),3*len(intents)+2)
    digest=journal_scope_sha256(journal,intents,limits=bounds,**opts())
    return store.seal(intents,expected_head=point,scope_sha256=digest,**opts(**changes))


def prepare(v):
    for intent in v[3]:append(v[1],intent)


def row(v,name):return tuple(v[0]._key(name)[k]['S'] for k in ('pk','sk'))


def test_empty_enrollment_exact_retry_seal_and_checkpoint_bound_history():
    v=world();root=init(v);before=deepcopy(v[2].items)
    assert init(v).checkpoint==root.checkpoint and v[2].items==before
    prepare(v);sealed=seal(v,root.checkpoint);snapshot=deepcopy(v[2].items)
    assert seal(v,root.checkpoint)==sealed and v[2].items==snapshot
    result=v[0].read_history(expected_head=sealed.checkpoint,**opts())
    assert result.sealed_history_complete and result.scopes==1 and result.intents==2
    assert result.historical and all(getattr(result,k) is False for k in ['can_erase','restore_authorized','request_fulfilled','global_history_complete','independent_iam_verified'])
    assert not sealed.sealed_history_complete and v[2].items==snapshot
    with pytest.raises(FrozenInstanceError):result.can_erase=True


def test_storage_read_unavailable_is_a_held_outcome(monkeypatch):
    v=world()
    def unavailable(**kw):raise ReadTimeoutError(endpoint_url='https://synthetic.invalid')
    monkeypatch.setattr(v[2],'get_item',unavailable)
    with pytest.raises(JournalHeld):init(v)
    assert not v[2].items


def test_bool_root_schema_cannot_be_reenrolled_as_exact_original():
    v=world();init(v);store,_,client,_=v
    body=store._root();body['schema']=True
    op=type('Op',(),{'check':lambda self,*a:None})()
    client.items[row(v,'anchor-root')]=store._item('anchor-root',body,op)
    point=AnchorCheckpoint(0,store._digest(body))
    client.items[row(v,'anchor-head')]=store._item('anchor-head',store._head(point),op)
    with pytest.raises(JournalHeld):init(v)


@pytest.mark.parametrize('field',['max_scopes','max_total_intents','max_item_bytes','max_sdk_calls','max_work'])
@pytest.mark.parametrize('bad',[True,0,-1,1.5])
def test_explicit_typed_limits(field,bad):
    v=world()
    with pytest.raises(ValueError):replace(v[0].limits,**{field:bad})


def test_nonempty_partition_never_bootstraps_history_over_existing_intents():
    v=world();prepare(v);before=deepcopy(v[2].items)
    with pytest.raises(JournalHeld):init(v)
    assert before==v[2].items


@pytest.mark.parametrize('phase',['initialize','seal'])
def test_lost_transaction_reply_reconciles_only_exact_durable_state(phase):
    v=world()
    def lost():raise ReadTimeoutError(endpoint_url='https://synthetic.invalid')
    if phase=='initialize':v[2].after_transaction=lost;assert init(v).checkpoint.sequence==0
    else:
        root=init(v);prepare(v);v[2].after_transaction=lost
        assert seal(v,root.checkpoint).checkpoint.sequence==1


@pytest.mark.parametrize('field,bad',[('max_sdk_calls',9),('max_work',31)])
def test_initialization_reserves_original_budget_before_io(field,bad):
    v=world();limits=replace(v[0].limits,**{field:bad})
    store=JournalAnchorStore(v[1],genesis_sha256='9'*64,limits=limits)
    with pytest.raises(JournalHeld):store.initialize(**opts())
    assert not v[2].calls


def test_wrong_genesis_never_resets_existing_enrollment():
    v=world();init(v);before=deepcopy(v[2].items)
    other=JournalAnchorStore(v[1],genesis_sha256='8'*64,limits=v[0].limits)
    with pytest.raises(JournalHeld):other.initialize(**opts())
    assert before==v[2].items


def test_partial_intent_scope_cannot_seal_or_advance_head():
    v=world();root=init(v);append(v[1],v[3][0]);before=deepcopy(v[2].items)
    with pytest.raises(JournalHeld):seal(v,root.checkpoint)
    assert before==v[2].items


def test_stale_competing_head_cannot_branch_or_overwrite():
    v=world();root=init(v);prepare(v);first=seal(v,root.checkpoint)
    other=(v[0],v[1],v[2],tuple(replace(x,reference_sha256='7'*64) for x in v[3]));prepare(other)
    before=deepcopy(v[2].items)
    with pytest.raises(JournalConflict):seal(other,root.checkpoint)
    assert before==v[2].items
    second=seal(other,first.checkpoint)
    result=v[0].read_history(expected_head=second.checkpoint,**opts())
    assert result.scopes==2 and result.intents==4


@pytest.mark.parametrize('fault',['root','head','anchor','intent','digest'])
def test_missing_or_corrupt_history_never_returns_partial_completeness(fault):
    v=world();root=init(v);prepare(v);point=seal(v,root.checkpoint).checkpoint
    name={'root':'anchor-root','head':'anchor-head','anchor':'anchor#'+point.digest}.get(fault)
    if name:del v[2].items[row(v,name)]
    elif fault=='intent':
        intent=v[3][0];key=tuple(v[1]._key(intent.reference_sha256,intent.resource_sha256)[k]['S'] for k in ('pk','sk'));del v[2].items[key]
    else:v[2].items[row(v,'anchor#'+point.digest)]['sha256']['S']='f'*64
    before=deepcopy(v[2].items)
    with pytest.raises((JournalHeld,JournalConflict)):v[0].read_history(expected_head=point,**opts())
    assert before==v[2].items


@pytest.mark.parametrize('fault',['late','cancelled','configuration'])
def test_context_change_after_transaction_withholds_acknowledgment(fault):
    v=world();clock=[1];stopped=[False]
    def changed():
        stopped[0]=True
        if fault=='late':clock[0]=1000
        if fault=='configuration':v[0].genesis_sha256='8'*64
    def checkpoint():
        if stopped[0] and fault=='cancelled':raise JournalHeld('synthetic current authority cancelled')
    v[2].after_transaction=changed
    with pytest.raises(JournalHeld):init(v,tick=lambda:clock[0],checkpoint=checkpoint)
    assert len(v[2].items)==2  # Original outcome is retained, never rolled back.


def test_untrusted_or_advanced_checkpoint_cannot_accept_current_history():
    v=world();root=init(v);prepare(v);seal(v,root.checkpoint)
    with pytest.raises(JournalConflict):v[0].read_history(expected_head=root.checkpoint,**opts())


def test_history_scope_and_total_intent_bounds_are_independent():
    v=world();root=init(v);prepare(v);first=seal(v,root.checkpoint)
    other=(v[0],v[1],v[2],tuple(replace(x,reference_sha256='7'*64) for x in v[3]));prepare(other);second=seal(other,first.checkpoint)
    for limits in [replace(v[0].limits,max_scopes=1),replace(v[0].limits,max_total_intents=3)]:
        store=JournalAnchorStore(v[1],genesis_sha256='9'*64,limits=limits)
        with pytest.raises(JournalHeld):store.read_history(expected_head=second.checkpoint,**opts())


def test_manifest_returns_complete_original_scopes_and_source_identity_without_writes():
    v=world();root=init(v);prepare(v);first=seal(v,root.checkpoint)
    other=(v[0],v[1],v[2],tuple(replace(x,reference_sha256='7'*64) for x in v[3]))
    prepare(other);second=seal(other,first.checkpoint);before=deepcopy(v[2].items);v[2].calls.clear()
    result=v[0].read_manifest(expected_head=second.checkpoint,**opts())
    assert result.receipt.sealed_history_complete is True
    assert result.source_deployment==v[1].repository.deployment
    assert result.source_tables==tuple(sorted(v[1].repository.tables.items()))
    assert result.journal_arn==v[1].table_arn
    assert type(result.scopes) is tuple and len(result.scopes)==2
    for scope,point,intents in zip(result.scopes,[second.checkpoint,first.checkpoint],[other[3],v[3]],strict=True):
        assert scope.checkpoint==point and scope.intents==intents
        raw=json.loads(before[row(v,'anchor#'+point.digest)]['body']['S'])
        assert scope.scope_sha256==raw['scope_sha256']
        assert type(scope.intents) is tuple and all(a is not b for a,b in zip(scope.intents,intents,strict=True))
        with pytest.raises(FrozenInstanceError):scope.scope_sha256='f'*64
    assert before==v[2].items
    assert not any(name in {'put_item','transact_write_items','delete_item'} for name,_ in v[2].calls)
    for field in ['can_erase','restore_authorized','request_fulfilled','global_history_complete','independent_iam_verified']:
        assert getattr(result.receipt,field) is False
    with pytest.raises(FrozenInstanceError):result.source_deployment='changed'


def test_manifest_empty_enrollment_has_no_fabricated_scope():
    v=world();point=init(v).checkpoint
    result=v[0].read_manifest(expected_head=point,**opts())
    assert result.scopes==() and result.receipt.scopes==0 and result.receipt.intents==0
    assert result.receipt.sealed_history_complete is True


@pytest.mark.parametrize('fault',['root','head','anchor','intent','digest','stale_head','deadline','cancelled','configuration'])
def test_manifest_withholds_complete_output_on_original_history_or_context_failure(fault):
    v=world();root=init(v);prepare(v);point=seal(v,root.checkpoint).checkpoint;options=opts()
    if fault in {'root','head','anchor'}:
        name={'root':'anchor-root','head':'anchor-head','anchor':'anchor#'+point.digest}[fault];del v[2].items[row(v,name)]
    elif fault=='intent':
        i=v[3][0];key=tuple(v[1]._key(i.reference_sha256,i.resource_sha256)[k]['S'] for k in ('pk','sk'));del v[2].items[key]
    elif fault=='digest':v[2].items[row(v,'anchor#'+point.digest)]['sha256']['S']='f'*64
    elif fault=='stale_head':point=root.checkpoint
    elif fault=='deadline':options['tick']=lambda:1000
    elif fault=='configuration':v[1].repository.tables['state']='restored-state'
    else:
        def cancelled():raise JournalHeld('synthetic cancellation')
        options['checkpoint']=cancelled
    before=deepcopy(v[2].items)
    with pytest.raises((JournalHeld,JournalConflict)):v[0].read_manifest(expected_head=point,**options)
    assert before==v[2].items


@pytest.mark.parametrize('field,value',[('max_scopes',1),('max_total_intents',3),('max_sdk_calls',1),('max_work',1)])
def test_manifest_reuses_original_complete_history_bounds(field,value):
    v=world();root=init(v);prepare(v);first=seal(v,root.checkpoint)
    other=(v[0],v[1],v[2],tuple(replace(x,reference_sha256='7'*64) for x in v[3]));prepare(other);second=seal(other,first.checkpoint)
    store=JournalAnchorStore(v[1],genesis_sha256='9'*64,limits=replace(v[0].limits,**{field:value}))
    before=deepcopy(v[2].items)
    with pytest.raises(JournalHeld):store.read_manifest(expected_head=second.checkpoint,**opts())
    assert before==v[2].items


@pytest.mark.parametrize('fault',['deadline','cancelled','source','limits'])
def test_manifest_final_delivery_rechecks_original_context(monkeypatch,fault):
    v=world();point=init(v).checkpoint;original=JournalAnchorStore._receipt;clock=[1];stopped=[False]
    def receipt(self,*args,**kwargs):
        result=original(self,*args,**kwargs)
        if fault=='deadline':clock[0]=1000
        elif fault=='source':self.journal.repository.tables['state']='different-state'
        elif fault=='limits':object.__setattr__(self.limits,'max_scopes',True)
        else:stopped[0]=True
        return result
    def checkpoint():
        if stopped[0]:raise JournalHeld('cancelled before manifest delivery')
    monkeypatch.setattr(JournalAnchorStore,'_receipt',receipt)
    with pytest.raises(JournalHeld):v[0].read_manifest(expected_head=point,**opts(tick=lambda:clock[0],checkpoint=checkpoint))
