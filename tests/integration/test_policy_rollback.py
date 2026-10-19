"""Fresh exact-predecessor rollback using actual local qualification, not physical truth."""
import pytest
from test_policy_qualification import qualification, finish, policies, world, repository_factory
from test_policy_candidates import draft
from proofpack.auth.service import RUNTIME
from proofpack.planner.activation import PolicyActivations, ActivationConfig, ActivationRequest
from proofpack.planner.active import ActivePolicies
from proofpack.evidence.repository import StoreConflict


def activate(world, service, candidate, job, operation, key, predecessor=None):
    from proofpack.stations.service import POLICY
    roots = world[1].snapshot((RUNTIME, POLICY))
    request = ActivationRequest(operation=operation, policy_id=candidate['id'],
        policy_revision=candidate['revision'], policy_state_version=candidate['state_version'],
        policy_revision_sha256=candidate['revision_sha256'], qualification_id=job['id'],
        qualification_report_sha256=job['report_sha256'],
        expected_active_version=0 if roots[POLICY] is None else roots[POLICY].revision,
        expected_control_version=int(roots[RUNTIME].data['control_version']),
        predecessor_activation_id=predecessor, invalidation_acknowledged=True)
    return service.transition(world[5], request=request, idempotency_key=key)


def test_same_id_older_revision_can_be_freshly_qualified_for_exact_rollback(world, qualification):
    writer, actor, original, first = qualification
    activation = PolicyActivations(writer.policies, ActivationConfig(20, 120, 60000, 80, writer.registry_sha), writer)
    a = activate(world, activation, first, finish(qualification, 'first'), 'bootstrap', 'activate-first')
    second = writer.policies.write(actor, request=draft('Second default'), ident=first['id'],
        expected_version=first['state_version'], idempotency_key='second-revision')
    second_request = original.model_copy(update={'policy_revision': second['revision'],
        'policy_state_version': second['state_version'], 'policy_revision_sha256': second['revision_sha256']})
    b = activate(world, activation, second, finish((writer, actor, second_request), 'second'), 'promote', 'activate-second')
    old_current = original.model_copy(update={'policy_state_version': second['state_version']})
    # Ordinary non-latest proposals remain forbidden; fresh rollback is a distinct intent.
    with pytest.raises(StoreConflict, match='exact current qualification candidate'):
        writer.create(actor, request=old_current, idempotency_key='ordinary-old')
    target = {'active_version': b['active_version'], 'activation_id': b['transition_id'],
        'predecessor_activation_id': a['transition_id']}
    request = type(original).model_validate({**old_current.model_dump(), 'rollback_target': target})
    job = finish((writer, actor, request), 'fresh-rollback')
    report = writer.read_current(job['id']).qualification.data
    assert report['rollback_target'] == target and report['completed_case_count'] == 182
    old = {**first, 'state_version': second['state_version']}
    with pytest.raises(StoreConflict):
        activate(world, activation, old, job, 'promote', 'cannot-promote-rollback-only')
    rolled = activate(world, activation, old, job, 'rollback', 'exact-rollback', a['transition_id'])
    current = ActivePolicies(activation).read_current()
    assert rolled['active_version'] == 3 and current.policy.data['policy_revision'] == 1
    assert current.policy.data['policy_id'] == first['id']
    assert world[1].snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
