"""Canonical bounded inspection selector shared by requests and held readers."""
from dataclasses import dataclass
import re
from proofpack.calibrations.dependencies import digest
from proofpack.runtime.control import uuid

MAXIMUM = 2**63-1
POLICY = 'read-only-family-selection-v3'

@dataclass(frozen=True)
class InspectionScope:
    schema_version: int
    kind: str
    deployment: str
    inspection_ids: tuple[str, ...]
    selector_policy: str


def inspection_scope(deployment, inspection_ids, *, max_inspections):
    if (type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or type(inspection_ids) is not tuple or not inspection_ids
            or type(max_inspections) is not int or not 1 <= max_inspections <= MAXIMUM):
        raise ValueError('exact deployment and bounded inspection scope required')
    if len(inspection_ids) > max_inspections:
        raise ValueError('inspection scope bound exhausted')
    if (any(type(value) is not str for value in inspection_ids)
            or tuple(sorted(set(inspection_ids))) != inspection_ids):
        raise ValueError('ordered unique inspection UUIDs required')
    for ident in inspection_ids: uuid(ident)
    return InspectionScope(1, 'inspection_metadata', deployment, inspection_ids, POLICY)


def scope_sha256(scope):
    if type(scope) is not InspectionScope: raise ValueError('typed private inspection scope required')
    return digest({'schema_version': scope.schema_version, 'kind': scope.kind,
        'deployment': scope.deployment, 'inspection_ids': list(scope.inspection_ids),
        'selector_policy': scope.selector_policy})


