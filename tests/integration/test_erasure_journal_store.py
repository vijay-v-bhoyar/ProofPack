"""Independent owned local table; synthetic intents are not approval evidence."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from uuid import uuid4
import json

from botocore.exceptions import ReadTimeoutError
import pytest
from test_access_lifecycle import repository_factory

from proofpack.evidence.erasure_journal import DynamoErasureJournal,JournalIntent,JournalLimits,JournalHeld,JournalConflict
from proofpack.evidence.repository import Key,Write
from proofpack.evidence.resource_bindings import _payload_sha256


@pytest.fixture
def journal_case(repository_factory):
    repo=repository_factory();client=repo.client;table='proofpack-journal-'+uuid4().hex[:16]
    client.create_table(TableName=table,KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
        AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
    try:
        arn=client.describe_table(TableName=table)['Table']['TableArn']
        service=DynamoErasureJournal(repo,journal_table=table,expected_table_arn=arn,limits=JournalLimits(4096,7))
        keys=(Key('state','journal-fixture#source'),Key('events','journal-fixture#event'))
        repo.transact(tuple(Write(k,None,{'fixture':'synthetic-main-record'}) for k in keys))
        before=repo.inventory_snapshot(keys)
        source=before[keys[0]]
        intent=JournalIntent('a'*64,repo._erasure_identity(keys[0]),source.revision,_payload_sha256(source.data),'d'*64,'e'*64,100)
        yield service,client,repo,intent,keys,before
        assert repo.inventory_snapshot(keys)==before
    finally:
        client.delete_table(TableName=table)


def append(service,intent,*,tick=lambda:1):
    return service.append(intent,deadline_ns=1000,tick=tick,checkpoint=lambda:None)


def raw(client,service,intent):
    return client.get_item(TableName=service.table,Key=service._key(intent.reference_sha256,intent.resource_sha256),ConsistentRead=True).get('Item')


def test_actual_journal_is_independent_immutable_and_minimized(journal_case):
    service,client,repo,intent,keys,before=journal_case
    entry=append(service,intent);stored=raw(client,service,intent)
    assert entry.intent==intent and not entry.can_erase and not entry.restore_authorized and not entry.request_fulfilled
    assert append(service,intent)==entry and raw(client,service,intent)==stored
    assert all(k.resource not in str(stored) for k in keys)
    assert 'synthetic-main-record' not in str(stored)
    assert repo.inventory_snapshot(keys)==before


def test_actual_concurrent_exact_retry_has_one_original_record(journal_case):
    service,client,_,intent,_,_=journal_case;start=Barrier(2)
    def run():start.wait(timeout=10);return append(service,intent)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first,second=list(pool.map(lambda _:run(),range(2)))
    assert first==second and first.intent==intent
    assert raw(client,service,intent)['data']['M']['created_at_ms']=={'N':'100'}


def test_actual_conflicting_concurrent_intents_cannot_overwrite_winner(journal_case):
    service,client,_,intent,_,_=journal_case;start=Barrier(2)
    def run(candidate):
        start.wait(timeout=10)
        try:return append(service,candidate)
        except JournalConflict:return None
    candidates=[intent,replace(intent,confirmation_sha256='f'*64)]
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,candidates))
    assert sum(v is not None for v in results)==1
    winner=next(v for v in results if v is not None)
    assert raw(client,service,intent)['data']['M']['confirmation_sha256']=={'S':winner.intent.confirmation_sha256}


def test_actual_commit_then_lost_reply_is_reconciled_without_second_put(journal_case,monkeypatch):
    service,client,_,intent,_,_=journal_case;original=client.put_item;puts=[]
    def lost(**kw):
        result=original(**kw)
        if kw['TableName']==service.table:puts.append(kw);raise ReadTimeoutError(endpoint_url=client.meta.endpoint_url)
        return result
    monkeypatch.setattr(client,'put_item',lost)
    assert append(service,intent).intent==intent
    assert append(service,intent).intent==intent and len(puts)==1
    assert raw(client,service,intent)['data']['M']['source_revision']=={'N':str(intent.source_revision)}


def test_actual_late_put_retains_journal_but_returns_no_acknowledgment(journal_case,monkeypatch):
    service,client,_,intent,_,_=journal_case;original=client.put_item;clock=[1]
    def late(**kw):
        result=original(**kw)
        if kw['TableName']==service.table:clock[0]=1000
        return result
    monkeypatch.setattr(client,'put_item',late)
    with pytest.raises(JournalHeld):append(service,intent,tick=lambda:clock[0])
    assert raw(client,service,intent)['data']['M']['created_at_ms']=={'N':'100'}


def test_actual_enabled_ttl_denies_journal_append(journal_case):
    service,client,_,intent,_,_=journal_case
    client.update_time_to_live(TableName=service.table,TimeToLiveSpecification={'Enabled':True,'AttributeName':'expires_at'})
    with pytest.raises(JournalHeld):append(service,intent)
    assert raw(client,service,intent) is None


def test_actual_wrong_table_arn_denies_before_journal_write(journal_case):
    service,client,repo,intent,_,_=journal_case
    parts=service.table_arn.split(':');parts[4]='111111111111'
    wrong=DynamoErasureJournal(repo,journal_table=service.table,expected_table_arn=':'.join(parts),limits=JournalLimits(4096,7))
    with pytest.raises(JournalHeld):append(wrong,intent)
    assert raw(client,service,intent) is None


def test_actual_hidden_readback_retains_uncertainty_and_original_effect(journal_case,monkeypatch):
    service,client,_,intent,_,_=journal_case;get=client.get_item;put=client.put_item;written=[]
    def commit(**kw):
        result=put(**kw)
        if kw['TableName']==service.table:written.append(True)
        return result
    def hide(**kw):
        if written and kw['TableName']==service.table:return {}
        return get(**kw)
    monkeypatch.setattr(client,'put_item',commit);monkeypatch.setattr(client,'get_item',hide)
    with pytest.raises(JournalHeld):append(service,intent)
    stored=get(TableName=service.table,Key=service._key(intent.reference_sha256,intent.resource_sha256),ConsistentRead=True)
    assert stored['Item']['data']['M']['created_at_ms']=={'N':'100'} and len(written)==1


@pytest.mark.parametrize('delta,accepted',[(0,True),(-1,False)])
def test_actual_full_record_byte_boundary_denies_before_new_entry(journal_case,delta,accepted):
    service,client,repo,intent,_,_=journal_case;append(service,intent)
    stored=raw(client,service,intent)
    size=len(json.dumps(stored,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
    candidate=replace(intent,reference_sha256='f'*64)
    bounded=DynamoErasureJournal(repo,journal_table=service.table,expected_table_arn=service.table_arn,limits=JournalLimits(size+delta,7))
    if accepted:
        assert append(bounded,candidate).intent==candidate
        assert len(json.dumps(raw(client,service,candidate),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())<=size+delta
    else:
        with pytest.raises(JournalHeld):append(bounded,candidate)
        assert raw(client,service,candidate) is None
