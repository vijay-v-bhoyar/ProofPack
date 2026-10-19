"""Internal current-policy reader. A live snapshot is never promotion authority."""
from dataclasses import asdict,dataclass
from typing import Callable
from proofpack.auth.policy import Role
from proofpack.auth.service import HEAD,RUNTIME,user_key
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.job_authority import resolve
from proofpack.evidence.repository import Row,StoreConflict,StoreUnavailable
from proofpack.planner.activation import PolicyActivations,activation_key,qualification_key
from proofpack.planner.candidates import PolicyDraft,revision_key
from proofpack.planner.consumption import PolicyConsumption
from proofpack.runtime.control import DATA,integer
from proofpack.stations.service import POLICY


@dataclass(frozen=True)
class ActivePolicySnapshot:
    policy:Row
    definition:PolicyDraft
    dependencies:tuple[Row,...]
    expires_at_ms:int
    final_guard:Callable[[],None]


class ActivePolicies:
    def __init__(self,activations):
        from proofpack.review.policy_qualification import PolicyQualifications
        if not isinstance(activations,PolicyActivations) or type(activations.reader) is not PolicyQualifications:
            raise ValueError('genuine shared qualification and activation services required')
        self.activations=activations;self.reader=activations.reader;self.policies=activations.policies
        self.access=activations.access;self.runtime=activations.runtime;self.repository=activations.repository

    def _binding(self):
        a=self.activations
        if (a.reader is not self.reader or a.policies is not self.policies or a.runtime is not self.runtime or a.access is not self.access
                or a.repository is not self.repository or self.reader.policies is not self.policies or self.reader.runtime is not self.runtime
                or self.reader.repository is not self.repository or self.reader.access is not self.access
                or digest(asdict(a.config))!=a.configuration or a.config.qualification_registry_sha256!=self.reader.registry_sha
                or self.reader._configuration()!=self.reader.configuration or self.runtime.handle is None):
            raise StoreUnavailable('unchanged active-policy services and registry required')
        return digest({'activation':asdict(a.config),'qualification':self.reader.configuration,
            'policy':self.policies._binding(),'runtime':asdict(self.runtime.handle),'golden':self.reader.plan.sha256,
            'registry':self.reader.registry_sha,'software':self.reader.software_implementation})

    def _snapshot(self):
        a=self.activations;binding=self._binding()
        roots=self.repository.snapshot((POLICY,RUNTIME,DATA));policy,runtime,data=(roots[k] for k in (POLICY,RUNTIME,DATA))
        a._intact(policy,'active_policy')
        if not self.runtime.matches(runtime) or data is None:raise StoreUnavailable('current active-policy runtime and DATA required')
        keys=(activation_key(policy.data['activation_id']),qualification_key(policy.data['qualification_id']))
        records=self.repository.snapshot(keys);event,report=(records[k] for k in keys);a._intact(event,'policy_activation')
        if policy.data['activation_configuration_sha256']!=a.configuration:raise StoreConflict('active transition configuration changed')
        job=self.reader._row(policy.data['qualification_id'])
        context=PolicyConsumption(policy,event,report,job,runtime,data)
        ownerkey=user_key(event.data['owner_id']);owners=self.repository.snapshot((HEAD,ownerkey));head=self.access._head(owners[HEAD]);owner=owners[ownerkey]
        if (owner is None or owner.data.get('enabled') is not True or owner.data.get('invited') is not True
                or owner.data['id']!=event.data['owner_id'] or owner.data['id'] not in head['enabled_user_ids'] or owner.data['id'] not in head['owner_ids']
                or Role.OWNER.value not in owner.data['roles'] or integer(owner.data['access_version'])!=integer(event.data['owner_access_version'])):
            raise StoreConflict('current approving-owner membership and exact access grant required')
        actor=resolve(self.access,job.data);checks,sealed=self.reader._sealed(actor,job,consumed=context)
        if sealed!=report:raise StoreConflict('consumed qualification changed during validation')
        record=checks[revision_key(policy.data['policy_id'],integer(policy.data['policy_revision']))]
        if record.data['spec']!=policy.data['definition'] or record.data['behavior_sha256']!=policy.data['behavior_sha256']:
            raise StoreConflict('active definition differs from its immutable qualified revision')
        deadline=min(integer(policy.data['expires_at_ms']),integer(report.data['expires_at_ms']))
        if not integer(event.data['issued_at_ms'])<=self.access.now()<deadline:raise StoreUnavailable('original active-policy lifetime expired')
        frozen=a._merge((*roots.values(),*records.values(),*owners.values(),*checks.values()))
        if len(frozen)>90:raise StoreUnavailable('complete active-policy dependencies exceed capacity')
        fresh=self.access._fresh(actor,Role.REVIEWER)
        a._merge((*frozen.values(),*fresh.rows))
        current=self.repository.snapshot(tuple(frozen))
        if any(current[k]!=v for k,v in frozen.items()):raise StoreConflict('active policy changed during source validation')
        if self._binding()!=binding:raise StoreConflict('active-policy configuration changed during delivery')
        if self.access.now()>=deadline:raise StoreUnavailable('active-policy delivery expired')
        return policy,PolicyDraft.model_validate_json(canonical(policy.data['definition'])),frozen,deadline

    def read_current(self):
        policy,spec,checks,deadline=self._snapshot()
        def final_guard():
            current,current_spec,values,expiry=self._snapshot()
            if current!=policy or current_spec!=spec or values!=checks or expiry!=deadline:
                raise StoreConflict('active-policy snapshot changed before use')
        final_guard()
        return ActivePolicySnapshot(policy,spec,tuple(checks.values()),deadline,final_guard)
