import boto3
from botocore.stub import Stubber
from botocore.exceptions import EndpointConnectionError
import pytest

from proofpack.evidence.repository import DynamoRepository, Key, Row, StoreConflict, StoreUnavailable, Write


def repository():
    # Dummy credentials and Stubber prohibit network/credential-provider access.
    client=boto3.client("dynamodb",region_name="us-east-1",aws_access_key_id="test",aws_secret_access_key="test")
    return DynamoRepository(client,deployment="test",state_table="proofpack-state",events_table="proofpack-events")


def test_snapshot_is_one_transaction_not_independent_gets():
    repo=repository()
    a,b=Key("state","inspection#1"),Key("state","runtime")
    item={**repo.key(a),"revision":{"N":"3"},"data":{"M":{"state":{"S":"OBSERVING"}}}}
    with Stubber(repo.client) as stub:
        stub.add_response("transact_get_items",{"Responses":[{"Item":item},{}]},
            {"TransactItems":[{"Get":{"TableName":"proofpack-state","Key":repo.key(k)}} for k in (a,b)]})
        rows=repo.snapshot((a,b))
        assert rows[a].revision==3
        assert rows[a].data["state"]=="OBSERVING"
        assert rows[b] is None
        stub.assert_no_pending_responses()


def test_condition_is_on_write_and_event_insert_is_unique():
    repo=repository()
    i=Key("state","inspection#1")
    head=Row(Key("state","runtime"),2,{})
    event=Key("events","event#1")
    captured=[]
    def capture(params,**kwargs):
        captured.append(params)
    repo.client.meta.events.register('before-parameter-build.dynamodb.TransactWriteItems',capture)
    with Stubber(repo.client) as stub:
        stub.add_response("transact_write_items",{})
        repo.transact((Write(i,3,{"state":"PASSED_CURRENT"}),Write(event,None,{"kind":"verified"})),(head,))
        stub.assert_no_pending_responses()
    items=captured[0]["TransactItems"]
    assert items[0]["Put"]["ConditionExpression"]=="#rev = :expected AND attribute_not_exists(#erasure)"
    assert items[0]['Put']['ExpressionAttributeNames']['#erasure']=='payload_erasure'
    assert items[0]["Put"]["Item"]["revision"]=={"N":"4"}
    assert items[1]["Put"]["ConditionExpression"]=="attribute_not_exists(#pk)"
    assert items[2]["ConditionCheck"]["ExpressionAttributeValues"][":expected"]=={"N":"2"}
    assert items[2]['ConditionCheck']['ConditionExpression']=='#rev = :expected AND attribute_not_exists(#erasure)'
    with pytest.raises(ValueError,match="distinct"):
        repo.transact((Write(i,3,{}),),(Row(i,3,{}),))


def test_repository_conflict_and_outage_no_fallback():
    repo=repository()
    with Stubber(repo.client) as stub:
        stub.add_client_error("transact_write_items",service_error_code="ConditionalCheckFailedException")
        with pytest.raises(StoreConflict):
            repo.transact((Write(Key("state","i"),1,{}),))
        stub.add_client_error("transact_get_items",service_error_code="InternalServerError")
        with pytest.raises(StoreUnavailable):
            repo.snapshot((Key("state","i"),))


def test_transport_outage_denies_without_memory_fallback(monkeypatch):
    repo=repository()
    def unavailable(**kwargs):
        raise EndpointConnectionError(endpoint_url="https://dynamodb.example.invalid")
    monkeypatch.setattr(repo.client,"transact_get_items",unavailable)
    monkeypatch.setattr(repo.client,"transact_write_items",unavailable)
    with pytest.raises(StoreUnavailable):
        repo.snapshot((Key("state","i"),))
    with pytest.raises(StoreUnavailable):
        repo.transact((Write(Key("state","i"),None,{}),))


def test_erasure_status_outage_is_unknown_not_a_successful_empty_result():
    repo=repository()
    with Stubber(repo.client) as stub:
        stub.add_client_error('transact_get_items',service_error_code='InternalServerError')
        with pytest.raises(StoreUnavailable):repo.erasures((Key('state','inspection#test'),))
        stub.assert_no_pending_responses()


def test_marker_status_keeps_the_original_distinct_atomic_snapshot_bound():
    repo=repository();key=Key('state','inspection#test')
    for keys in ((),(key,key),tuple(Key('state',str(n)) for n in range(101))):
        with pytest.raises(ValueError):repo.erasures(keys)
