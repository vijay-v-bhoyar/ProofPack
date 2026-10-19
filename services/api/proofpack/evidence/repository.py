"""DynamoDB optimistic transactions with consistent multi-head snapshots.

No AWS client is created at import. Callers must supply an authorized target/client.
The adapter never falls back to process memory when AWS fails.
"""
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import re
from typing import Any

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import BotoCoreError, ClientError


class StoreConflict(ValueError):
    pass


class StoreUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Key:
    table: str
    resource: str


@dataclass(frozen=True)
class Row:
    key: Key
    revision: int
    data: dict[str, Any]


@dataclass(frozen=True)
class Write:
    key: Key
    expected_revision: int | None
    data: dict[str, Any]


@dataclass(frozen=True)
class Erase:
    """Internal exact-revision payload scrub; authorization belongs to its service."""
    key: Key
    expected_revision: int
    reference_sha256: str

    def __post_init__(self):
        if (not isinstance(self.key,Key) or not isinstance(self.key.table,str) or self.key.table not in {'state','events'}
                or not isinstance(self.key.resource,str) or not 1<=len(self.key.resource)<=256
                or type(self.expected_revision) is not int or not 1<=self.expected_revision<2**63-1
                or not isinstance(self.reference_sha256,str) or not re.fullmatch(r'[a-f0-9]{64}',self.reference_sha256)):
            raise ValueError('exact bounded payload-erasure source and opaque reference required')


@dataclass(frozen=True)
class ErasureMarker:
    key: Key
    revision: int
    reference_sha256: str
    resource_sha256: str


class DynamoRepository:
    def __init__(self, client, *, deployment: str, state_table: str, events_table: str, data_fence=None):
        if not deployment or not state_table or not events_table:
            raise ValueError("explicit deployment and table identity required")
        self.client = client
        self.deployment = deployment
        self.tables = {"state": state_table, "events": events_table}
        self.serialize = TypeSerializer()
        self.deserialize = TypeDeserializer()
        self.data_fence = data_fence
        self._data_fence_initial = data_fence
        if data_fence is not None:
            from proofpack.evidence.restore_fence import RestoreDataFence
            if type(data_fence) is not RestoreDataFence:
                raise ValueError('exact protected restore data fence required')
            data_fence.assert_repository(client, deployment, self.tables)

    def _check_data_fence(self):
        fence = self._data_fence_initial
        if self.data_fence is not fence:
            raise StoreUnavailable('original repository data fence changed')
        if fence is not None:
            fence.assert_repository(self.client, self.deployment, self.tables)
        return fence

    @property
    def snapshot_capacity(self):
        """Business keys; three protected records share a fenced transaction."""
        return 100 if self._check_data_fence() is None else 97

    def _fence_context(self):
        fence = self._check_data_fence()
        return None if fence is None else fence.begin(self._check_data_fence)

    def key(self, key: Key) -> dict:
        if key.table not in self.tables or not key.resource or len(key.resource) > 256:
            raise ValueError("unknown table or invalid resource key")
        return {"pk": {"S": f"deployment#{self.deployment}"}, "sk": {"S": key.resource}}

    def _erasure_identity(self,key):
        text=json.dumps(['metadata-payload-erasure/v1',self.deployment,key.table,key.resource],separators=(',',':'),ensure_ascii=True)
        return hashlib.sha256(text.encode()).hexdigest()

    def _decode(self,key,item):
        try:
            decoded={k:self.deserialize.deserialize(v) for k,v in item.items()}
            if decoded.get('pk')!=f'deployment#{self.deployment}' or decoded.get('sk')!=key.resource:
                raise StoreUnavailable('repository returned unexpected identity')
            revision=decoded['revision']
            if (type(revision) not in (int,Decimal)
                    or type(revision) is Decimal and (not revision.is_finite() or revision!=revision.to_integral_value())
                    or not 1<=revision<=2**63-1):
                raise StoreUnavailable('exact bounded repository revision required')
            if 'payload_erasure' not in decoded:return Row(key,int(revision),decoded['data'])
            marker=decoded['payload_erasure'];revision=decoded['revision']
            if (set(decoded)!={'pk','sk','revision','data','payload_erasure'} or decoded['data']!={}
                    or not isinstance(marker,dict) or set(marker)!={'schema_version','reference_sha256','resource_sha256'}
                    or isinstance(marker['schema_version'],bool) or marker['schema_version']!=1
                    or isinstance(revision,bool) or not isinstance(revision,(int,Decimal)) or revision!=int(revision) or not 2<=revision<=2**63-1
                    or not isinstance(marker['reference_sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',marker['reference_sha256'])
                    or marker['resource_sha256']!=self._erasure_identity(key)):
                raise StoreUnavailable('intact payload-erasure marker required')
            return ErasureMarker(key,int(revision),marker['reference_sha256'],marker['resource_sha256'])
        except (KeyError,TypeError,ValueError,ArithmeticError) as exc:
            raise StoreUnavailable('intact repository record required') from exc

    def _read(self, keys):
        if not 1 <= len(keys) <= 100 or len(set(keys)) != len(keys):
            raise ValueError("snapshot requires 1–100 distinct keys")
        if self._data_fence_initial is not None and len(keys) > 97:
            raise ValueError('fenced snapshots require at most97 business keys')
        context = self._fence_context()
        requests = [{"Get": {"TableName": self.tables[k.table], "Key": self.key(k)}} for k in keys]
        if context is not None:
            requests.extend(context.get_items())
            context.before_data_call()
        try:
            result = self.client.transact_get_items(TransactItems=requests)
        except ClientError as exc:
            raise StoreUnavailable("consistent repository snapshot unavailable") from exc
        except BotoCoreError as exc:
            raise StoreUnavailable("repository transport unavailable") from exc
        responses = result.get('Responses', [])
        if len(responses) != len(requests):
            raise StoreUnavailable("incomplete repository snapshot")
        if context is not None:
            context.validate(responses[-3:])
            responses = responses[:-3]
        rows = {}
        for key, response in zip(keys, responses, strict=True):
            item = response.get("Item")
            if not item:
                rows[key] = None
                continue
            rows[key]=self._decode(key,item)
        if context is not None:
            context.finish()
        return rows

    def snapshot(self, keys: tuple[Key, ...]) -> dict[Key, Row | None]:
        return {key:value if isinstance(value,Row) else None for key,value in self._read(keys).items()}

    def erasures(self, keys: tuple[Key, ...]) -> dict[Key, ErasureMarker | None]:
        """Internal reconciliation only; absence is not proof of payload removal."""
        return {key:value if isinstance(value,ErasureMarker) else None for key,value in self._read(keys).items()}

    def inventory_snapshot(self, keys: tuple[Key, ...]) -> dict[Key, Row | ErasureMarker | None]:
        """Private inventory reconciliation; no caller authorization or removal grant."""
        if (type(keys) is not tuple or not 1 <= len(keys) <= 100
                or any(not isinstance(key, Key) or type(key.table) is not str
                       or key.table not in {'state', 'events'} or type(key.resource) is not str
                       or not 1 <= len(key.resource) <= 256 for key in keys)
                or len(set(keys)) != len(keys)):
            raise ValueError('1–100 distinct typed inventory keys required')
        return self._read(keys)

    def query(self,*,prefix: str,limit: int=100,start_resource: str | None=None,table: str='state'):
        """Bounded same-deployment prefix query; service signs any client cursor."""
        if (table not in self.tables or not isinstance(prefix,str) or not 1<=len(prefix)<=128
                or type(limit) is not int or not 1<=limit<=100
                or (start_resource is not None and not start_resource.startswith(prefix))):
            raise ValueError('bounded deployment query required')
        parameters={'TableName':self.tables[table],'ConsistentRead':True,'Limit':limit,
            'KeyConditionExpression':'#pk = :deployment AND begins_with(#sk, :prefix)',
            'ExpressionAttributeNames':{'#pk':'pk','#sk':'sk'},
            'ExpressionAttributeValues':{':deployment':{'S':f'deployment#{self.deployment}'},':prefix':{'S':prefix}}}
        if start_resource is not None:parameters['ExclusiveStartKey']=self.key(Key(table,start_resource))
        context = self._fence_context()
        if context is not None:context.before_data_call()
        try:response=self.client.query(**parameters)
        except (ClientError,BotoCoreError) as exc:raise StoreUnavailable('repository query unavailable') from exc
        rows=[]
        for raw in response.get('Items',[]):
            resource=raw.get('sk',{}).get('S')
            if not isinstance(resource,str) or not resource.startswith(prefix):
                raise StoreUnavailable('unexpected query identity')
            decoded=self._decode(Key(table,resource),raw)
            if isinstance(decoded,Row):rows.append(decoded)
        last=response.get('LastEvaluatedKey')
        if last and (last.get('pk')!={'S':f'deployment#{self.deployment}'} or not last.get('sk',{}).get('S','').startswith(prefix)):
            raise StoreUnavailable('unexpected query cursor')
        if context is not None:context.recheck()
        return rows,None if not last else last['sk']['S']

    def partition_page(self, *, limit: int = 100, start_resource: str | None = None, table: str = 'state'):
        """Internal inventory only; pages are not an atomic or authorized closure."""
        if (type(table) is not str or table not in self.tables or type(limit) is not int or not 1 <= limit <= 100
                or (start_resource is not None and (type(start_resource) is not str or not 1 <= len(start_resource) <= 256))):
            raise ValueError('bounded exact deployment partition request required')
        parameters = {'TableName': self.tables[table], 'ConsistentRead': True, 'Limit': limit,
            'KeyConditionExpression': '#pk = :deployment', 'ExpressionAttributeNames': {'#pk': 'pk'},
            'ExpressionAttributeValues': {':deployment': {'S': f'deployment#{self.deployment}'}}}
        if start_resource is not None:
            parameters['ExclusiveStartKey'] = self.key(Key(table, start_resource))
        context = self._fence_context()
        if context is not None:context.before_data_call()
        try:
            response = self.client.query(**parameters)
        except (ClientError, BotoCoreError) as exc:
            raise StoreUnavailable('repository partition unavailable') from exc
        try:
            if type(response) is not dict:
                raise ValueError()
            items = response.get('Items', [])
            if type(items) is not list or len(items) > limit:
                raise ValueError()
            for name in ('Count', 'ScannedCount'):
                # This query has neither a filter nor a projection.
                if name in response and (type(response[name]) is not int or response[name] != len(items)):
                    raise ValueError()
            rows = []; previous = start_resource
            for raw in items:
                if type(raw) is not dict:
                    raise ValueError()
                resource = raw.get('sk', {}).get('S')
                if type(resource) is not str or not 1 <= len(resource) <= 256 or (previous is not None and resource <= previous):
                    raise ValueError()
                key = Key(table, resource)
                if raw.get('pk') != self.key(key)['pk'] or raw.get('sk') != {'S': resource}:
                    raise ValueError()
                expected = {'pk', 'sk', 'revision', 'data'} | ({'payload_erasure'} if 'payload_erasure' in raw else set())
                if set(raw) != expected:
                    raise ValueError()
                number = self.deserialize.deserialize(raw['revision'])
                if (type(number) is not Decimal or not number.is_finite() or number != number.to_integral_value()
                        or not 1 <= number <= 2**63-1):
                    raise ValueError()
                decoded = self._decode(key, raw)
                if isinstance(decoded, Row) and type(decoded.data) is not dict:
                    raise ValueError()
                rows.append(decoded); previous = resource
            last = response.get('LastEvaluatedKey')
            if last is not None and not (type(last) is dict and not last):
                if type(last) is not dict:
                    raise ValueError()
                cursor = last.get('sk', {}).get('S')
                if (type(cursor) is not str or not 1 <= len(cursor) <= 256
                        or last != self.key(Key(table, cursor))
                        or (start_resource is not None and cursor <= start_resource)
                        or (previous is not None and cursor < previous)):
                    raise ValueError()
            else:
                cursor = None
        except (KeyError, TypeError, ValueError, ArithmeticError, AttributeError) as exc:
            raise StoreUnavailable('intact progressing partition page required') from exc
        if context is not None:context.recheck()
        return rows, cursor

    def transact(self, writes: tuple[Write | Erase, ...], checks: tuple[Row, ...] = ()) -> None:
        """A write includes its condition; a row cannot also be a ConditionCheck."""
        if any(not isinstance(w,(Write,Erase)) for w in writes) or any(not isinstance(r,Row) for r in checks):
            raise ValueError('typed repository operations required')
        keys = [w.key for w in writes] + [r.key for r in checks]
        if not writes or len(keys) > 100 or len(set(keys)) != len(keys):
            raise ValueError("bounded distinct transactional items required")
        if self._data_fence_initial is not None and len(keys) > 97:
            raise ValueError('fenced transactions require at most97 business items')
        items = []
        for write in writes:
            if write.expected_revision is not None and write.expected_revision < 1:
                raise ValueError("invalid expected revision")
            revision = 1 if write.expected_revision is None else write.expected_revision + 1
            item = {**self.key(write.key), "revision": {"N": str(revision)},
                    "data": self.serialize.serialize({} if isinstance(write,Erase) else write.data)}
            if isinstance(write,Erase):
                item['payload_erasure']=self.serialize.serialize({'schema_version':1,'reference_sha256':write.reference_sha256,'resource_sha256':self._erasure_identity(write.key)})
            operation = {"TableName": self.tables[write.key.table], "Item": item,
                         "ConditionExpression": "attribute_not_exists(#pk)" if write.expected_revision is None else "#rev = :expected AND attribute_not_exists(#erasure)",
                         "ExpressionAttributeNames": {"#pk":"pk"} if write.expected_revision is None else {"#rev":"revision","#erasure":"payload_erasure"}}
            if write.expected_revision is not None:
                operation["ExpressionAttributeValues"] = {":expected":{"N":str(write.expected_revision)}}
            items.append({"Put":operation})
        for row in checks:
            if row.revision < 1:
                raise ValueError("invalid check revision")
            items.append({"ConditionCheck": {"TableName": self.tables[row.key.table], "Key":self.key(row.key),
                "ConditionExpression":"#rev = :expected AND attribute_not_exists(#erasure)", "ExpressionAttributeNames":{"#rev":"revision","#erasure":"payload_erasure"},
                "ExpressionAttributeValues":{":expected":{"N":str(row.revision)}}}})
        context = self._fence_context()
        if context is not None:
            items.extend(context.condition_items())
            context.before_data_call()
        try:
            self.client.transact_write_items(TransactItems=items)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            reasons = exc.response.get("CancellationReasons", [])
            if code == "ConditionalCheckFailedException" or (code == "TransactionCanceledException"
                    and any(r.get("Code") == "ConditionalCheckFailed" for r in reasons)):
                raise StoreConflict("repository changed; refetch before deciding") from exc
            raise StoreUnavailable("repository transaction unavailable") from exc
        except BotoCoreError as exc:
            raise StoreUnavailable("repository transport unavailable") from exc
        if context is not None:context.finish()
