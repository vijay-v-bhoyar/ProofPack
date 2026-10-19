"""Decode historical private provenance, without ownership or removal authority."""
from dataclasses import asdict, dataclass
from decimal import Decimal
import json
import re

from proofpack.evidence.repository import Key, Row


class MissingResourceBindings(ValueError):
    """Legacy or unlinked output; a family policy must resolve this explicitly."""


class InvalidResourceBindings(ValueError):
    """Unsupported, corrupt or foreign provenance; never a partial discovery."""


@dataclass(frozen=True)
class CheckedResource:
    table: str
    resource: str
    revision: int
    sha256: str

    @property
    def key(self):
        return Key(self.table, self.resource)


@dataclass(frozen=True)
class WrittenResource(CheckedResource):
    previous_revision: int | None


@dataclass(frozen=True)
class ResourceBindings:
    deployment: str
    operation: str
    writes: tuple[WrittenResource, ...]
    checks: tuple[CheckedResource, ...]


def _fail():
    raise InvalidResourceBindings('intact supported historical resource bindings required')


def _integer(value, *, maximum=2**63-1):
    if type(value) is not int and type(value) is not Decimal:
        _fail()
    if isinstance(value, Decimal) and (not value.is_finite() or value != value.to_integral_value()):
        _fail()
    if not 1 <= value <= maximum:
        _fail()
    return int(value)


def _identity(table, resource):
    if (type(table) is not str or table not in {'state', 'events'}
            or type(resource) is not str or not 1 <= len(resource) <= 256):
        _fail()
    return table, resource


def _references(values, *, written, output):
    if type(values) is not list or len(values) > 99:
        _fail()
    result = []
    identities = []
    fields = {'table', 'resource', 'revision', 'sha256'} | ({'previous_revision'} if written else set())
    for value in values:
        if type(value) is not dict or set(value) != fields:
            _fail()
        identity = _identity(value['table'], value['resource'])
        if identity == output or (written and (identity[0] == 'events' or identity[1].startswith('idempotency#'))):
            _fail()
        revision = _integer(value['revision'])
        digest = value['sha256']
        if type(digest) is not str or re.fullmatch('[a-f0-9]{64}', digest) is None:
            _fail()
        if written:
            previous = value['previous_revision']
            if previous is not None:
                previous = _integer(previous, maximum=2**63-2)
            if revision != (1 if previous is None else previous + 1):
                _fail()
            result.append(WrittenResource(*identity, revision, digest, previous))
        else:
            result.append(CheckedResource(*identity, revision, digest))
        identities.append(identity)
    if identities != sorted(set(identities)):
        _fail()
    return tuple(result)


def decode(row, *, deployment):
    """Read exact stored schema; callers must still validate family and scope."""
    if not isinstance(row, Row) or not isinstance(row.key, Key) or type(row.data) is not dict:
        _fail()
    output = _identity(row.key.table, row.key.resource)
    _integer(row.revision)
    if (output[0] != 'events' and not output[1].startswith('idempotency#')) or (output[0] == 'events' and row.revision != 1):
        _fail()
    if type(deployment) is not str or not 1 <= len(deployment) <= 256:
        _fail()
    if 'resource_bindings' not in row.data:
        raise MissingResourceBindings('explicit legacy resource binding policy required')
    value = row.data['resource_bindings']
    if type(value) is not dict or set(value) != {'schema_version', 'deployment', 'operation', 'writes', 'checks'}:
        _fail()
    if _integer(value['schema_version'], maximum=1) != 1 or value['deployment'] != deployment:
        _fail()
    if type(value['deployment']) is not str or type(value['operation']) is not str or not 1 <= len(value['operation']) <= 512:
        _fail()
    writes = _references(value['writes'], written=True, output=output)
    checks = _references(value['checks'], written=False, output=output)
    written = {r.key: r for r in writes}
    checked = {r.key: r for r in checks}
    if not written and not checked or len(written.keys() | checked.keys()) > 99:
        _fail()
    if any(written[key].previous_revision != checked[key].revision for key in written.keys() & checked.keys()):
        _fail()
    canonical = {'schema_version': 1, 'deployment': deployment, 'operation': value['operation'],
                 'writes': [asdict(r) for r in writes], 'checks': [asdict(r) for r in checks]}
    if len(json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()) > 131072:
        _fail()
    return ResourceBindings(deployment, value['operation'], writes, checks)
