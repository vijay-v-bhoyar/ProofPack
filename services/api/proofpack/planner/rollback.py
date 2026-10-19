"""Exact server-verified rollback intent; never a generic stale-revision override."""
from pydantic import Field
from proofpack.recipes.models import Contract
from proofpack.review.labels import UUIDText
from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.repository import Key, StoreConflict, StoreUnavailable
from proofpack.runtime.control import integer, sha, uuid
from proofpack.stations.service import POLICY


class RollbackTarget(Contract):
    active_version: int = Field(ge=1, le=9007199254740991)
    activation_id: UUIDText
    predecessor_activation_id: UUIDText


def _event_key(ident):
    return Key('state', 'policy-activation#' + ident)


def intact_policy_provenance(policies, row, kind):
    from proofpack.planner.candidates import PolicyDraft
    try:
        value = row.data
        if (integer(value['schema_version']) != 1 or value['kind'] != kind
                or digest({k: v for k, v in value.items() if k != 'sha256'}) != value['sha256']
                or (kind == 'policy_activation' and row.revision != 1)):
            raise ValueError()
        spec = PolicyDraft.model_validate_json(canonical(value['definition']))
        if digest({'algorithm': spec.algorithm, 'priority': [x.value for x in spec.priority]}) != value['behavior_sha256']:
            raise ValueError()
        uuid(value['policy_id']); uuid(value['activation_id'])
        sha(value['policy_revision_sha256'])
        if 'policy_state_version' in value and not 1 <= integer(value['policy_state_version']) <= 9007199254740991:
            raise ValueError()
        runtime = policies.runtime
        if (value['environment'] != runtime.environment or value['artifact_sha256'] != runtime.artifact_sha256
                or value['controls_sha256'] != runtime.controls_sha256 or value['installed_sha256'] != policies.installed_sha256
                or (kind == 'active_policy' and (value['status'] != 'approved' or value['mode'] != 'deterministic_policy'))):
            raise ValueError()
        return row
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise StoreUnavailable('intact compatible active policy provenance required') from exc


def rollback_checks(policies, request, *, consumed=None):
    try:
        return _rollback_checks(policies, request, consumed=consumed)
    except StoreConflict:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise StoreUnavailable('complete exact rollback provenance required') from exc


def _rollback_checks(policies, request, *, consumed=None):
    repository = policies.repository
    target = request.rollback_target
    if target is None:
        return {}
    if type(target) is not RollbackTarget:
        raise ValueError('strict exact rollback target required')
    keys = (_event_key(target.activation_id), _event_key(target.predecessor_activation_id))
    rows = repository.snapshot(keys)
    anchor, predecessor = (rows[key] for key in keys)
    intact_policy_provenance(policies, anchor, 'policy_activation')
    intact_policy_provenance(policies, predecessor, 'policy_activation')
    if consumed is None:
        head = repository.snapshot((POLICY,))[POLICY]
        intact_policy_provenance(policies, head, 'active_policy')
        if (head.revision != target.active_version or head.data['activation_id'] != target.activation_id
                or head.data['activation_sha256'] != anchor.data['sha256']
                or any(anchor.data[k] != v for k, v in head.data.items()
                    if k not in {'kind', 'status', 'mode', 'activation_sha256', 'sha256'})):
            raise StoreConflict('exact current rollback anchor required')
        rows[head.key] = head
    else:
        from proofpack.planner.consumption import consumption
        context = consumption(consumed)
        event = context.event
        if (event.data['operation'] != 'rollback'
                or integer(event.data['previous_active_version']) != target.active_version
                or event.data['predecessor_activation_id'] != target.activation_id
                or event.data['policy_id'] != request.policy_id
                or integer(event.data['policy_revision']) != request.policy_revision
                or event.data['policy_revision_sha256'] != request.policy_revision_sha256):
            raise StoreConflict('exact consumed rollback anchor required')
        rows.update({context.policy.key: context.policy, event.key: event})
    if (anchor.data['predecessor_activation_id'] != target.predecessor_activation_id
            or integer(anchor.data['previous_active_version']) + 1 != target.active_version
            or predecessor.data['policy_id'] != request.policy_id
            or integer(predecessor.data['policy_revision']) != request.policy_revision
            or predecessor.data['policy_revision_sha256'] != request.policy_revision_sha256):
        raise StoreConflict('selected candidate differs from exact rollback predecessor')
    return rows
