"""Protocol faults; synthetic SDK responses are not provider evidence."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import json

from botocore.exceptions import ClientError, ReadTimeoutError
import pytest

from proofpack.evidence.erasure_journal import (
    DynamoErasureJournal, JournalIntent, JournalLimits, JournalHeld, JournalConflict,
)
from proofpack.evidence.repository import DynamoRepository

ARN='arn:aws:dynamodb:us-east-1:000000000000:table/journal-test'


class Client:
    def __init__(self):
        self.meta=SimpleNamespace(config=SimpleNamespace(
            retries={'total_max_attempts':1},connect_timeout=1,read_timeout=1))
        self.items={};self.calls=[];self.after_put=None;self.hide_readback=False
        self.description={'TableName':'journal-test','TableArn':ARN,'TableStatus':'ACTIVE',
            'KeySchema':[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
            'AttributeDefinitions':[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}]}
        self.ttl={'TimeToLiveDescription':{'TimeToLiveStatus':'DISABLED'}}
    def describe_table(self,**kw):
        self.calls.append(('describe_table',deepcopy(kw)));return {'Table':deepcopy(self.description)}
    def describe_time_to_live(self,**kw):
        self.calls.append(('describe_time_to_live',deepcopy(kw)));return deepcopy(self.ttl)
    def get_item(self,**kw):
        self.calls.append(('get_item',deepcopy(kw)))
        assert kw['ConsistentRead'] is True
        key=tuple(kw['Key'][k]['S'] for k in ('pk','sk'))
        return {} if key not in self.items or self.hide_readback else {'Item':deepcopy(self.items[key])}
    def put_item(self,**kw):
        self.calls.append(('put_item',deepcopy(kw)))
        assert kw['ConditionExpression']=='attribute_not_exists(#pk) AND attribute_not_exists(#sk)'
        key=tuple(kw['Item'][k]['S'] for k in ('pk','sk'))
        if key in self.items:raise ClientError({'Error':{'Code':'ConditionalCheckFailedException'}},'PutItem')
        self.items[key]=deepcopy(kw['Item'])
        if self.after_put:self.after_put()
        return {}


def setup(*,calls=7,bytes=4096):
    client=Client();repo=DynamoRepository(client,deployment='synthetic-deployment',state_table='state-test',events_table='events-test')
    service=DynamoErasureJournal(repo,journal_table='journal-test',expected_table_arn=ARN,
                                limits=JournalLimits(bytes,calls))
    intent=JournalIntent('a'*64,'b'*64,1,'c'*64,'d'*64,'e'*64,100)
    return service,client,repo,intent


def append(service,intent,**changes):
    options={'deadline_ns':1000,'tick':lambda:1,'checkpoint':lambda:None};options.update(changes)
    return service.append(intent,**options)


def read(service,intent,**changes):
    options={'deadline_ns':1000,'tick':lambda:1,'checkpoint':lambda:None};options.update(changes)
    return service.read(reference_sha256=intent.reference_sha256,resource_sha256=intent.resource_sha256,**options)


def test_append_exact_retry_and_readback_preserve_original_intent():
    service,client,_,intent=setup()
    first=append(service,intent);before=deepcopy(client.items)
    assert first==append(service,intent)==read(service,intent)
    assert first.intent==intent and not first.can_erase and not first.restore_authorized and not first.request_fulfilled
    assert client.items==before and sum(name=='put_item' for name,_ in client.calls)==1
    assert {v['TableName'] for _,v in client.calls}=={'journal-test'}
    assert all(word not in repr(first) for word in ('synthetic-deployment','source_payload','confirmation'))


@pytest.mark.parametrize('field,value',[('source_revision',2),('created_at_ms',101),('source_payload_sha256','f'*64),('classification_sha256','f'*64),('confirmation_sha256','f'*64)])
def test_changed_intent_cannot_overwrite_original(field,value):
    service,client,_,intent=setup();append(service,intent);before=deepcopy(client.items)
    with pytest.raises(JournalConflict):append(service,replace(intent,**{field:value}))
    assert client.items==before and sum(n=='put_item' for n,_ in client.calls)==1


def test_committed_put_lost_reply_reconciles_actual_original_record():
    service,client,_,intent=setup()
    def lost():raise ReadTimeoutError(endpoint_url='http://synthetic.invalid')
    client.after_put=lost
    assert append(service,intent).intent==intent
    assert sum(n=='put_item' for n,_ in client.calls)==1


def test_missing_readback_after_put_is_uncertain_with_effect_retained():
    service,client,_,intent=setup();client.after_put=lambda:setattr(client,'hide_readback',True)
    with pytest.raises(JournalHeld):append(service,intent)
    assert len(client.items)==1 and sum(n=='put_item' for n,_ in client.calls)==1
    client.hide_readback=False
    assert append(service,intent).intent==intent
    assert sum(n=='put_item' for n,_ in client.calls)==1


@pytest.mark.parametrize('mutate',[
    lambda item:item.update(extra={'S':'unreviewed'}),
    lambda item:item.update(sha256={'S':'f'*64}),
    lambda item:item['data']['M'].update(created_at_ms={'N':'0'}),
    lambda item:item['data']['M'].update(source_revision={'BOOL':True}),
    lambda item:item['data']['M'].update(source_revision={'N':str(2**63)}),
    lambda item:item['data']['M'].update(kind={'S':'other'}),
])
def test_corrupt_stored_record_never_returns_acknowledgment(mutate):
    service,client,_,intent=setup();append(service,intent)
    mutate(next(iter(client.items.values())))
    with pytest.raises(JournalHeld):read(service,intent)


@pytest.mark.parametrize('field,value',[('source_revision',True),('source_revision',2**63-1),('created_at_ms',0),('classification_sha256','bad')])
def test_bypassed_dataclass_validation_is_rechecked_before_any_io(field,value):
    service,client,_,intent=setup();object.__setattr__(intent,field,value)
    with pytest.raises(ValueError):append(service,intent)
    assert client.calls==[] and client.items=={}


@pytest.mark.parametrize('bad',[0,True,-1,2**63])
def test_invalid_deadline_is_rejected_before_io(bad):
    service,client,_,intent=setup()
    with pytest.raises(ValueError):append(service,intent,deadline_ns=bad)
    assert client.calls==[]


def test_budget_preflight_and_record_bytes_deny_before_io():
    for calls,bytes in [(6,4096),(7,1)]:
        service,client,_,intent=setup(calls=calls,bytes=bytes)
        with pytest.raises(JournalHeld):append(service,intent)
        assert client.calls==[]


@pytest.mark.parametrize('ticks',[[1000],[1,0],[True]])
def test_expired_reversed_or_boolean_clock_cannot_start_storage(ticks):
    service,client,_,intent=setup();values=iter(ticks)
    with pytest.raises(JournalHeld):append(service,intent,tick=lambda:next(values))
    assert client.items=={}


@pytest.mark.parametrize('ttl',['ENABLED','ENABLING','DISABLING',None])
def test_ttl_states_hold_without_writes(ttl):
    service,client,_,intent=setup();client.ttl={'TimeToLiveDescription':{'TimeToLiveStatus':ttl}}
    with pytest.raises(JournalHeld):append(service,intent)
    assert client.items=={} and not any(n=='put_item' for n,_ in client.calls)


@pytest.mark.parametrize('malformed',[None,[],{'TableStatus':'ACTIVE'}])
def test_malformed_target_description_is_a_held_protocol(malformed):
    service,client,_,intent=setup();client.description=malformed
    with pytest.raises(JournalHeld):append(service,intent)
    assert client.items=={}


def test_primary_table_name_and_arn_aliases_are_denied():
    _,client,repo,_=setup()
    for value in ('journal-test',ARN):
        repo.tables['state']=value
        with pytest.raises(ValueError):DynamoErasureJournal(repo,journal_table='journal-test',expected_table_arn=ARN,limits=JournalLimits(4096,7))
    assert client.calls==[]


def test_configuration_swap_at_checkpoint_cannot_write():
    service,client,repo,intent=setup()
    def change():repo.tables['state']='changed-state'
    with pytest.raises(JournalHeld):append(service,intent,checkpoint=change)
    assert client.calls==[]


def test_deadline_crossed_after_put_preserves_unknown_effect_without_ack():
    service,client,_,intent=setup();clock=[1];client.after_put=lambda:clock.__setitem__(0,1000)
    with pytest.raises(JournalHeld):append(service,intent,tick=lambda:clock[0])
    assert len(client.items)==1


def test_absent_read_is_not_a_tombstone_or_cleanup_receipt():
    service,client,_,intent=setup(calls=5)
    assert read(service,intent) is None
    assert len(client.calls)==5 and client.items=={}


@pytest.mark.parametrize('calls,bytes',[(True,4096),(0,4096),(33,4096),(7,True),(7,0),(7,131073)])
def test_required_limits_are_exact_positive_and_bounded(calls,bytes):
    with pytest.raises(ValueError):JournalLimits(bytes,calls)


@pytest.mark.parametrize('fault',['retry-boolean','timeout-boolean','missing-config'])
def test_changed_sdk_configuration_is_held_before_storage(fault):
    service,client,_,intent=setup()
    if fault=='retry-boolean':client.meta.config.retries['total_max_attempts']=True
    elif fault=='timeout-boolean':client.meta.config.read_timeout=True
    else:del client.meta.config
    with pytest.raises(JournalHeld):append(service,intent)
    assert client.calls==[] and client.items=={}


@pytest.mark.parametrize('attempts',[True,2])
def test_automatic_or_boolean_sdk_retry_configuration_is_denied(attempts):
    _,client,repo,_=setup();client.meta.config.retries['total_max_attempts']=attempts
    with pytest.raises(ValueError):DynamoErasureJournal(repo,journal_table='journal-test',expected_table_arn=ARN,limits=JournalLimits(4096,7))
    assert client.calls==[]


@pytest.mark.parametrize('field,value',[('max_sdk_calls',8),('max_record_bytes',8192)])
def test_mutated_original_limit_object_is_held_before_io(field,value):
    service,client,_,intent=setup();object.__setattr__(service.limits,field,value)
    with pytest.raises(JournalHeld):append(service,intent)
    assert client.calls==[] and client.items=={}


@pytest.mark.parametrize('delta,accepted',[(0,True),(-1,False)])
def test_full_stored_record_byte_boundary_includes_keys_and_digest(delta,accepted):
    service,client,_,intent=setup();append(service,intent)
    size=len(json.dumps(next(iter(client.items.values())),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
    _,other,repo,_=setup()
    bounded=DynamoErasureJournal(repo,journal_table='journal-test',expected_table_arn=ARN,limits=JournalLimits(size+delta,7))
    if accepted:
        assert append(bounded,intent).intent==intent
        assert len(json.dumps(next(iter(other.items.values())),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())<=size+delta
    else:
        with pytest.raises(JournalHeld):append(bounded,intent)
        assert other.calls==[] and other.items=={}
