"""Exact consumed-transition facts for internal source revalidation, never promotion."""
from dataclasses import dataclass
import json
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Row,StoreConflict,StoreUnavailable
from proofpack.runtime.control import integer


@dataclass(frozen=True)
class PolicyConsumption:
    policy:Row
    event:Row
    qualification:Row
    job:Row
    runtime:Row
    data:Row

    def __post_init__(self):
        try:
            p,e,q,j,r,d=(v.data for v in (self.policy,self.event,self.qualification,self.job,self.runtime,self.data))
            for row in (self.policy,self.event,self.qualification):
                if digest({k:v for k,v in row.data.items() if k!='sha256'})!=row.data['sha256']:raise ValueError()
            if (self.event.revision!=1 or self.qualification.revision!=1 or p['kind']!='active_policy' or e['kind']!='policy_activation'
                    or p['activation_sha256']!=e['sha256'] or p['status']!='approved' or p['mode']!='deterministic_policy'
                    or any(e[k]!=v for k,v in p.items() if k not in {'kind','status','mode','activation_sha256','sha256'})
                    or q['id']!=p['qualification_id'] or q['sha256']!=p['qualification_report_sha256']
                    or j['id']!=q['id'] or j['kind']!='policy_qualification' or j['status']!='completed' or j['report_sha256']!=q['sha256']
                    or integer(q['schema_version'])!=1 or q['runner']!='policy_qualification_v1'
                    or q['scope']!='synthetic_demo_only' or q['status']!='qualified' or q['environment']!='synthetic_demo'
                    or any(q[k] is not False for k in ('physical_truth_verified','independent_benchmark_qualified','operator_effort_measured','beta_eligible'))
                    or not 0<integer(q['required_case_count'])==integer(q['completed_case_count'])==integer(q['passed_case_count'])
                    or integer(q['failed_case_count'])!=0 or integer(q['unknown_case_count'])!=0
                    or integer(q['control_version'])!=integer(e['previous_control_version'])
                    or integer(e['control_version'])!=integer(e['previous_control_version'])+1
                    or integer(r['control_version'])<integer(e['control_version']) or integer(d['epoch'])!=integer(e['data_epoch'])
                    or integer(p['expires_at_ms'])>integer(q['expires_at_ms']) or integer(e['issued_at_ms'])<integer(q['issued_at_ms'])
                    or any(q[k]!=e[k] for k in ('policy_id','policy_revision','policy_revision_sha256','behavior_sha256','registry_sha256',
                        'installed_sha256','environment','artifact_sha256','controls_sha256','runtime_epoch','data_epoch'))
                    or any(r[k]!=e[k] for k in ('environment','artifact_sha256','controls_sha256','runtime_epoch'))):raise ValueError()
        except (KeyError,TypeError,ValueError,AttributeError) as exc:
            raise StoreUnavailable('exact current consumed activation and genuine qualification required') from exc

    def candidate(self,request,head,record):
        """Only a later draft head may differ; qualified revision and binding do not."""
        e=self.event.data
        if (request.policy_id!=e['policy_id'] or request.policy_revision!=integer(e['policy_revision'])
                or request.policy_revision_sha256!=e['policy_revision_sha256'] or record.data['sha256']!=e['policy_revision_sha256']
                or not request.policy_state_version<=head.revision or integer(head.data['latest_revision'])<request.policy_revision):
            raise StoreConflict('consumed policy must retain its exact qualified revision')

    def execution_control(self,row,runtime):
        """Only this qualification and its exact preparation consumed the old control."""
        original=json.loads(self.job.data['request_json'])
        expected=self.job.data['id'] if row.data['kind']=='policy_qualification' else original.get('preparation_id') if row.data['kind']=='policy_qualification_preparation' else None
        if (expected is None or row.data['id']!=expected or runtime!=self.runtime
                or integer(row.data['control_version'])!=integer(self.event.data['previous_control_version'])):
            raise StoreConflict('exact consumed job and original execution control required')
        return integer(self.event.data['previous_control_version'])


def consumption(value):
    if type(value) is not PolicyConsumption:raise ValueError('server-bound consumption context required')
    return value
