"""Internal historical links; neither deletion authority nor public evidence."""
from copy import deepcopy
from decimal import Decimal
import hashlib
import json

from boto3.dynamodb.types import TypeSerializer

from proofpack.evidence.repository import Key, Row, Write, StoreConflict


def _key(key):
    if (not isinstance(key, Key) or not isinstance(key.table, str) or key.table not in {'state', 'events'}
            or not isinstance(key.resource, str) or not 1 <= len(key.resource) <= 256):
        raise ValueError('bounded typed resource identity required')
    return key.table, key.resource


def _version(value, *, previous=False):
    if previous and value is None:
        return None
    if type(value) is not int or not 1 <= value <= (2**63 - 2 if previous else 2**63 - 1):
        raise ValueError('exact bounded resource revision required')
    return value


def _payload_sha256(data):
    if not isinstance(data, dict):
        raise ValueError('structured record payload required')
    # Preserve the project's canonical JSON convention without importing the
    # calibration layer, which depends on AccessService itself.
    def number(value):
        if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
            return int(value)
        raise ValueError('canonical structured record value required')
    try:
        TypeSerializer().serialize(data)
        encoded = json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False, default=number).encode()
    except (TypeError, ArithmeticError) as exc:
        raise ValueError('canonical storable record payload required') from exc
    return hashlib.sha256(encoded).hexdigest()


def _limit(deployment,operation,reserved_items):
    if (not isinstance(deployment, str) or not 1 <= len(deployment) <= 256
            or not isinstance(operation, str) or not 1 <= len(operation) <= 512):
        raise ValueError('bounded deployment and operation required')
    if type(reserved_items) is not int or not 1 <= reserved_items <= 99:
        raise ValueError('exact bounded linked output count required')
    return 100-reserved_items


def _envelope(deployment,operation,written,checked,maximum):
    if len(set(written)|set(checked))>maximum:raise ValueError('shared transaction resource bound exceeded')
    if not written and not checked:raise ValueError('business effect or checked acknowledgment required')
    for identity in written.keys() & checked.keys():
        if written[identity][0].expected_revision != checked[identity][0].revision:
            raise StoreConflict('written resource must bind its checked prior revision')
    envelope = {'schema_version': 1, 'deployment': deployment, 'operation': operation,
        'writes': [{'table': table, 'resource': resource, 'previous_revision': value.expected_revision,
            'revision': 1 if value.expected_revision is None else value.expected_revision + 1, 'sha256': digest}
            for (table, resource), (value, digest) in sorted(written.items())],
        'checks': [{'table': table, 'resource': resource, 'revision': value.revision, 'sha256': digest}
            for (table, resource), (value, digest) in sorted(checked.items())]}
    if len(json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode()) > 131072:
        raise ValueError('resource binding envelope exceeds bound')
    return envelope


def prepare(deployment, operation, writes, checks, *, reserved_items=2):
    """Freeze inputs; reserve outputs without adding database requests or authority."""
    maximum=_limit(deployment,operation,reserved_items)
    written = {}
    checked = {}
    for write in writes:
        if not isinstance(write, Write):
            raise ValueError('typed ordinary business write required')
        identity = _key(write.key)
        if identity in written:
            raise ValueError('distinct business writes required')
        _version(write.expected_revision, previous=True)
        frozen = Write(write.key, write.expected_revision, deepcopy(write.data))
        written[identity] = (frozen, _payload_sha256(frozen.data))
        if len(written) > maximum:
            raise ValueError('shared transaction resource bound exceeded')
    for row in checks:
        if not isinstance(row, Row):
            raise ValueError('typed checked record required')
        identity = _key(row.key)
        _version(row.revision)
        frozen = Row(row.key, row.revision, deepcopy(row.data))
        value = (frozen, _payload_sha256(frozen.data))
        if identity in checked and checked[identity] != value:
            raise StoreConflict('conflicting checked resource bindings')
        checked[identity] = value
        if len(set(written) | set(checked)) > maximum:
            raise ValueError('shared transaction resource bound exceeded')
    envelope=_envelope(deployment,operation,written,checked,maximum)
    return tuple(value for value, _ in written.values()), tuple(value for value, _ in checked.values()), envelope


def prepare_linked(deployment, operation, writes, checks):
    """Freeze a transaction and link every audit/replay output, without self-links."""
    values={};outputs=set();frozen_checks={}
    for write in writes:
        if not isinstance(write,Write):raise ValueError('typed linked transaction write required')
        identity=_key(write.key)
        if identity in values:raise ValueError('distinct linked transaction writes required')
        _version(write.expected_revision,previous=True)
        frozen=Write(write.key,write.expected_revision,deepcopy(write.data))
        payload_hash=_payload_sha256(frozen.data)
        audit=write.key.table=='events';replay=write.key.table=='state' and write.key.resource.startswith('idempotency#')
        if audit:
            if write.expected_revision is not None or 'resource_bindings' in frozen.data:
                raise ValueError('new unbound immutable audit output required')
        if audit or replay:outputs.add(identity)
        values[identity]=(frozen,payload_hash)
        if len(values)>100:raise ValueError('linked transaction item bound exceeded')
    if not outputs:raise ValueError('explicit event or idempotency output required')
    for row in checks:
        if not isinstance(row,Row):raise ValueError('typed linked transaction check required')
        identity=_key(row.key);_version(row.revision)
        value=Row(row.key,row.revision,deepcopy(row.data));value_hash=_payload_sha256(value.data)
        if identity in frozen_checks and frozen_checks[identity][1]!=value_hash:
            raise StoreConflict('conflicting linked transaction check payload')
        if identity in frozen_checks and frozen_checks[identity][0].revision!=value.revision:
            raise StoreConflict('conflicting linked transaction check version')
        frozen_checks[identity]=(value,value_hash)
        if identity in outputs and values[identity][0].expected_revision!=value.revision:
            raise StoreConflict('linked output must bind its checked prior revision')
        if len(set(values)|set(frozen_checks))>100:raise ValueError('linked transaction item bound exceeded')
    business={identity:value for identity,value in values.items() if identity not in outputs}
    dependencies={identity:value for identity,value in frozen_checks.items() if identity not in outputs}
    binding=_envelope(deployment,operation,business,dependencies,_limit(deployment,operation,len(outputs)))
    result=[]
    for identity,(value,_) in values.items():
        if identity in outputs:
            result.append(Write(value.key,value.expected_revision,{**value.data,'resource_bindings':deepcopy(binding)}))
        else:result.append(value)
    return tuple(result),tuple(row for row,_ in frozen_checks.values())
