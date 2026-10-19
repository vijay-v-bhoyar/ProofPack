"""Genuine request writers and the shared current-schema contract; no SDK."""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal

import pytest

from test_owner_metadata import world, create, cancel, no_sdk
from proofpack.evidence.metadata_request_contract import validate_request, request_key
from proofpack.evidence.inspection_scope import InspectionScope, inspection_scope, scope_sha256
from proofpack.evidence.privacy_admission import AdmissionHeld
from proofpack.evidence.repository import Row


def validate(service, row, rows, **changes):
    def snapshot(keys):
        return {key: rows.get(key) for key in keys}
    return validate_request(row, **(dict(deployment=service.repository.deployment,
        configuration_sha256=service._configuration, max_inspections=service.limits.max_inspections,
        now=service.access.now, snapshot=snapshot) | changes))


@pytest.mark.parametrize('cancelled', [False, True])
def test_shared_validator_reads_original_writer_rows_without_mutation_or_live_store(cancelled):
    service, actor, repo, _, owner, _ = world()
    result = create(service, actor)
    if cancelled:
        cancel(service, actor, result)
    rows = deepcopy(repo.rows)
    row = rows[request_key(result['id'])]
    before = deepcopy(rows)
    value, dependencies = validate(service, row, rows)
    assert value == row.data
    assert len(dependencies) == (2 if cancelled else 1)
    assert all(type(item) is Row and item.revision == 1 for item in dependencies)
    assert [d.data['resource_bindings']['operation'] for d in dependencies] == (
        ['owner-metadata-create', 'owner-metadata-cancel'] if cancelled else ['owner-metadata-create'])
    assert rows == before and repo.rows == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('field,bad', [
    ('schema_version', True), ('status', 'fulfilled'), ('kind', 'cleanup_approved'),
    ('owner_access_version', True), ('initial_gate_revision', 0),
    ('owner_user_id', 'not-a-uuid'), ('scope_sha256', '0' * 64),
    ('original_request_sha256', '1' * 64), ('configuration_sha256', '2' * 64),
    ('created_at_ms', Decimal('NaN')), ('created_at_ms', 2**63),
    ('creation_operation_resource', 'foreign'),
])
def test_malformed_root_holds_before_any_write(field, bad):
    service, actor, repo, _, owner, _ = world()
    result = create(service, actor)
    before = deepcopy(repo.rows)
    original = before[request_key(result['id'])]
    row = replace(original, data={**original.data, field: bad})
    with pytest.raises(AdmissionHeld):
        validate(service, row, before)
    assert repo.rows == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('cancelled', [False, True])
@pytest.mark.parametrize('fault', ['missing', 'result', 'revision', 'binding'])
def test_missing_or_corrupt_original_creation_and_cancellation_provenance_holds(cancelled, fault):
    service, actor, repo, _, owner, _ = world()
    result = create(service, actor)
    if cancelled:
        cancel(service, actor, result)
    original = deepcopy(repo.rows)
    rows = deepcopy(original)
    row = rows[request_key(result['id'])]
    field = 'cancellation_operation_resource' if cancelled else 'creation_operation_resource'
    key = next(k for k in rows if k.resource == row.data[field])
    operation = rows[key]
    if fault == 'missing':
        del rows[key]
    elif fault == 'revision':
        rows[key] = replace(operation, revision=2)
    elif fault == 'result':
        rows[key] = replace(operation, data={**operation.data, 'result': {}})
    else:
        rows[key] = replace(operation, data={k: v for k, v in operation.data.items() if k != 'resource_bindings'})
    with pytest.raises(AdmissionHeld):
        validate(service, row, rows)
    assert repo.rows == original and owner.wait_for_drain(0)


def test_owner_actual_get_delegates_to_shared_validator_inside_original_lifetime(monkeypatch):
    from proofpack.evidence import owner_metadata
    service, actor, repo, _, owner, _ = world()
    result = create(service, actor)
    calls = []
    original = owner_metadata.validate_request
    def observed(row, **kwargs):
        service._check()
        calls.append(row.key)
        return original(row, **kwargs)
    monkeypatch.setattr(owner_metadata, 'validate_request', observed)
    before = deepcopy(repo.rows)
    readback = service.get(actor, result['id'])
    assert readback['id'] == result['id'] and readback['status'] == 'held'
    assert not readback['can_confirm_cleanup'] and not readback['request_fulfilled']
    assert calls == [request_key(result['id'])]
    assert repo.rows == before and owner.wait_for_drain(0)


def test_scope_public_imports_retain_one_type_and_identical_digest():
    from proofpack.evidence import held_corpus
    from test_privacy_admission import ident
    assert held_corpus.InspectionScope is InspectionScope
    assert held_corpus.inspection_scope is inspection_scope
    assert held_corpus.scope_sha256 is scope_sha256
    scope = inspection_scope('deployment', (ident(1),), max_inspections=1)
    assert type(scope) is InspectionScope and held_corpus.scope_sha256(scope) == scope_sha256(scope)


def test_decimal_native_storage_numbers_preserve_canonical_request_and_bindings():
    service, actor, repo, _, owner, _ = world()
    result = create(service, actor)
    def native(value):
        if type(value) is int:
            return Decimal(value)
        if type(value) is dict:
            return {k: native(v) for k, v in value.items()}
        if type(value) is list:
            return [native(v) for v in value]
        return value
    rows = {k: replace(v, data=native(v.data)) for k, v in repo.rows.items()}
    value, dependencies = validate(service, rows[request_key(result['id'])], rows)
    assert value['id'] == result['id'] and len(dependencies) == 1 and owner.wait_for_drain(0)
