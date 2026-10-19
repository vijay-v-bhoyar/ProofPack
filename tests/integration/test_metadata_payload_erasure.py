"""Owned local database only; no real personal data or erasure fulfillment claim."""
from uuid import uuid4
import pytest
from test_access_lifecycle import repository_factory
from proofpack.evidence import repository as storage
from proofpack.evidence.repository import Key,Write,Row,StoreConflict,StoreUnavailable

def erase(key,version=1,reference='a'*64):
    operation=getattr(storage,'Erase',None)
    assert operation is not None,'exact conditional metadata payload erasure is not implemented'
    return operation(key,version,reference)

def test_exact_payload_erasure_removes_data_and_preserves_only_a_minimal_marker(repository_factory):
    repo=repository_factory();key=Key('state','inspection#'+str(uuid4()))
    repo.transact((Write(key,None,{'kit_id':'NEVER_RETAIN_TEST_DATA','nested':{'name':'NEVER_RETAIN_TEST_DATA'}}),))
    repo.transact((erase(key),))
    assert repo.snapshot((key,))[key] is None
    status=repo.erasures((key,))[key]
    assert status.key==key and status.revision==2 and status.reference_sha256=='a'*64
    raw=repo.client.get_item(TableName=repo.tables['state'],Key=repo.key(key),ConsistentRead=True)['Item']
    assert set(raw)=={'pk','sk','revision','data','payload_erasure'}
    assert raw['data']=={'M':{}} and 'NEVER_RETAIN_TEST_DATA' not in str(raw)

@pytest.mark.parametrize('version',[None,1,2])
def test_ordinary_writers_cannot_recreate_an_erased_key_even_with_its_current_revision(repository_factory,version):
    repo=repository_factory();key=Key('state','observation#'+str(uuid4()))
    repo.transact((Write(key,None,{'private':'NEVER_RETAIN_TEST_DATA'}),));repo.transact((erase(key),))
    with pytest.raises(StoreConflict):repo.transact((Write(key,version,{'resurrected':True}),))
    assert repo.snapshot((key,))[key] is None

def test_erased_row_cannot_satisfy_a_condition_even_with_a_known_current_revision(repository_factory):
    repo=repository_factory();key=Key('state','human-disposition#'+str(uuid4()));other=Key('state','new#'+str(uuid4()))
    repo.transact((Write(key,None,{'private':'NEVER_RETAIN_TEST_DATA'}),));repo.transact((erase(key),))
    with pytest.raises(StoreConflict):repo.transact((Write(other,None,{}),),(Row(key,2,{}),))
    assert repo.snapshot((other,))[other] is None

def test_mixed_table_erasure_is_atomic_and_rejects_a_stale_review(repository_factory):
    repo=repository_factory();a=Key('state','inspection#'+str(uuid4()));b=Key('events','capture#'+str(uuid4()))
    repo.transact((Write(a,None,{'private':'one'}),Write(b,None,{'private':'two'})))
    with pytest.raises(StoreConflict):repo.transact((erase(a),erase(b,2)))
    assert all(repo.snapshot((a,b)).values()) and repo.erasures((a,b))=={a:None,b:None}
    repo.transact((erase(a),erase(b)))
    assert repo.snapshot((a,b))=={a:None,b:None}
    with pytest.raises(StoreConflict):repo.transact((erase(a),))
    assert repo.erasures((a,))[a].reference_sha256=='a'*64

def test_filtered_query_keeps_bounded_progress_through_empty_visible_pages(repository_factory):
    repo=repository_factory();prefix='metadata-query#'+str(uuid4())+'#';keys=[Key('state',prefix+x) for x in 'abc']
    repo.transact(tuple(Write(k,None,{'value':k.resource[-1]}) for k in keys));repo.transact((erase(keys[0]),erase(keys[1])))
    page,cursor=repo.query(prefix=prefix,limit=1)
    assert page==[] and cursor==keys[0].resource
    found=[]
    for _ in range(4):
        page,next_cursor=repo.query(prefix=prefix,limit=1,start_resource=cursor);found.extend(r.key for r in page)
        if next_cursor is None:break
        assert next_cursor!=cursor;cursor=next_cursor
    else:pytest.fail('bounded original query cursor did not finish')
    assert found==[keys[2]]

def test_payload_field_named_like_the_internal_marker_is_not_a_tombstone(repository_factory):
    repo=repository_factory();key=Key('state','ordinary#'+str(uuid4()))
    repo.transact((Write(key,None,{'payload_erasure':True}),))
    assert repo.snapshot((key,))[key].data=={'payload_erasure':True}
    assert repo.erasures((key,))[key] is None

@pytest.mark.parametrize('fault',['reference','identity','schema','payload','extra','revision','marker-type','schema-string','reference-type','revision-bool'])
def test_corrupt_markers_deny_reads_queries_and_status_without_disclosing_payload(repository_factory,fault):
    repo=repository_factory();prefix='corrupt-marker#'+str(uuid4());key=Key('state',prefix)
    repo.transact((Write(key,None,{'private':'NEVER_RETAIN_TEST_DATA'}),));repo.transact((erase(key),))
    raw=repo.client.get_item(TableName=repo.tables['state'],Key=repo.key(key),ConsistentRead=True)['Item']
    if fault=='reference':raw['payload_erasure']['M']['reference_sha256']={'S':'not-a-digest'}
    elif fault=='identity':raw['payload_erasure']['M']['resource_sha256']={'S':'f'*64}
    elif fault=='schema':raw['payload_erasure']['M']['schema_version']={'BOOL':True}
    elif fault=='payload':raw['data']={'M':{'private':{'S':'NEVER_RETAIN_TEST_DATA'}}}
    elif fault=='extra':raw['unexpected_private']={'S':'NEVER_RETAIN_TEST_DATA'}
    elif fault=='revision':raw['revision']={'N':'2.5'}
    elif fault=='marker-type':raw['payload_erasure']={'BOOL':True}
    elif fault=='schema-string':raw['payload_erasure']['M']['schema_version']={'S':'1'}
    elif fault=='reference-type':raw['payload_erasure']['M']['reference_sha256']={'BOOL':True}
    else:raw['revision']={'BOOL':True}
    repo.client.put_item(TableName=repo.tables['state'],Item=raw)
    with pytest.raises(StoreUnavailable):repo.snapshot((key,))
    with pytest.raises(StoreUnavailable):repo.query(prefix=prefix,limit=1)
    with pytest.raises(StoreUnavailable):repo.erasures((key,))

def test_full_hundred_key_snapshot_stays_one_atomic_get_after_erasure(repository_factory):
    repo=repository_factory();prefix='hundred#'+str(uuid4())+'#';keys=tuple(Key('state',prefix+str(n)) for n in range(100))
    repo.transact(tuple(Write(k,None,{'n':n}) for n,k in enumerate(keys)));repo.transact(tuple(erase(k) for k in keys[:50]))
    observed=[]
    repo.client.meta.events.register('before-parameter-build.dynamodb.TransactGetItems',lambda params,**kwargs:observed.append(len(params['TransactItems'])))
    values=repo.snapshot(keys)
    assert observed==[100] and sum(v is None for v in values.values())==50

@pytest.mark.parametrize('scope',['deployment','table','resource'])
def test_marker_cannot_be_transplanted_to_a_different_logical_scope(repository_factory,scope):
    repo=repository_factory();key=Key('state','scope#'+str(uuid4()))
    repo.transact((Write(key,None,{'private':'NEVER_RETAIN_TEST_DATA'}),));repo.transact((erase(key),))
    raw=repo.client.get_item(TableName=repo.tables['state'],Key=repo.key(key),ConsistentRead=True)['Item']
    if scope=='deployment':
        target=storage.DynamoRepository(repo.client,deployment='different-'+str(uuid4()),state_table=repo.tables['state'],events_table=repo.tables['events']);destination=key
    else:target=repo;destination=Key('events',key.resource) if scope=='table' else Key('state',key.resource+'-other')
    raw.update(target.key(destination));target.client.put_item(TableName=target.tables[destination.table],Item=raw)
    with pytest.raises(StoreUnavailable):target.snapshot((destination,))
    with pytest.raises(StoreUnavailable):target.erasures((destination,))
