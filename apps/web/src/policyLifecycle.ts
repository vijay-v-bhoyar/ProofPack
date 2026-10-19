import { positive, sha, uuid } from './workbench';

export const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
export type RollbackTarget = { active_version: number; activation_id: string; predecessor_activation_id: string };
export function target(v: unknown): v is RollbackTarget {
  const x = v as RollbackTarget;
  return !!x && Object.keys(x).length === 3 && positive(x.active_version) && uuid.test(x.activation_id) && uuid.test(x.predecessor_activation_id);
}
export const sameTarget = (a: RollbackTarget | null, b: RollbackTarget | null) => a === null ? b === null : b !== null
  && a.active_version === b.active_version && a.activation_id === b.activation_id && a.predecessor_activation_id === b.predecessor_activation_id;
export type Candidate = { id: string; revision: number; state_version: number; latest_revision: number; revision_sha256: string; binding_current: true; spec: { name: string; algorithm: string; priority: string[] }; promotion_available: false; evaluation_status: string; status: string };
export function candidate(x: Candidate): Candidate {
  if (!x || !uuid.test(x.id) || !positive(x.revision) || x.revision > 1000 || !positive(x.state_version) || !positive(x.latest_revision)
    || x.latest_revision < x.revision || x.latest_revision > 1000 || !sha.test(x.revision_sha256) || x.status !== 'draft' || x.evaluation_status !== 'NOT_VERIFIED'
    || x.promotion_available !== false || x.binding_current !== true || !x.spec || typeof x.spec.name !== 'string' || !x.spec.name.trim() || x.spec.name.length > 80 || x.spec.algorithm !== 'reason_priority_v1'
    || !Array.isArray(x.spec.priority) || x.spec.priority.length !== 3 || new Set(x.spec.priority).size !== 3 || x.spec.priority.some(v => !['SEPARATE_REGION', 'PLACE_FLAT', 'RECAPTURE'].includes(v)))
    throw new Error('Exact candidate metadata is unavailable.');
  return x;
}
export type Options = { software_cases: number; golden_cases: number; registry_sha256: string; max_reserved_cases: number; max_steps: number; lifetime_ms: number; lease_ms: number; page_size: 20; synthetic_demo_only: true };
export function options(x: Options): Options {
  if (!x || !positive(x.software_cases) || x.software_cases > 256 || x.golden_cases !== 12 || !sha.test(x.registry_sha256)
    || !positive(x.max_reserved_cases) || x.max_reserved_cases > 1000000 || !positive(x.max_steps) || x.max_steps > 10000
    || !positive(x.lifetime_ms) || x.lifetime_ms > 3600000 || !positive(x.lease_ms) || x.lease_ms > 60000 || x.page_size !== 20 || x.synthetic_demo_only !== true || !flags(x))
    throw new Error('Installed synthetic qualification bounds are unavailable.');
  return x;
}
export function flags(x: unknown): boolean {
  const v = x as Record<string, unknown>;
  return !!v && ['physical_truth_verified', 'independent_benchmark_qualified', 'operator_effort_measured', 'beta_eligible', 'inspection_enablement_granted'].every(k => v[k] === false);
}
export type Decision = { policy_id: string; policy_revision: number; policy_state_version: number; policy_revision_sha256: string; mode: 'installed_default' | 'candidate';
  preparation_id: string | null; preparation_state_version: number | null; preparation_report_sha256: string | null; rollback_target: RollbackTarget | null; source_examples: number; registry_sha256: string };
export type QJob = Decision & { id: string; kind: string; state_version: number; status: string; current: boolean; report_current: boolean;
  steps_prepared: number; planned_steps: number; steps_reserved: number; cases_reserved: number; required_cases: number;
  report_sha256: string | null; qualification_status: string; counts: { passed: number; failed: number; unknown: number } | null;
  remaining_ms: number; lease_remaining_ms: number; can_advance: boolean; can_cancel: boolean; can_retire: boolean; can_read_request: boolean; can_read_details: boolean; failure_reason: string | null };
export function decision(x: Decision): Decision {
  if (!x || !uuid.test(x.policy_id) || !positive(x.policy_revision) || x.policy_revision > 1000 || !positive(x.policy_state_version) || !sha.test(x.policy_revision_sha256)
    || !sha.test(x.registry_sha256) || !integer(x.source_examples) || x.source_examples > 1000 || (x.rollback_target !== null && !target(x.rollback_target))
    || (x.mode === 'installed_default' ? x.source_examples !== 0 || x.preparation_id !== null || x.preparation_state_version !== null || x.preparation_report_sha256 !== null
      : x.mode !== 'candidate' || !x.source_examples || !uuid.test(x.preparation_id ?? '') || !positive(x.preparation_state_version) || !sha.test(x.preparation_report_sha256 ?? '')))
    throw new Error('Qualification candidate, source or purpose binding is unavailable.');
  return x;
}
export function qjob(x: QJob, installed?: Options): QJob {
  decision(x);
  if (!uuid.test(x.id) || x.kind !== 'policy_qualification' || !positive(x.state_version) || !['queued', 'processing', 'completed', 'failed', 'cancelled', 'retired'].includes(x.status) || !flags(x)
    || !positive(x.planned_steps) || x.planned_steps > 1256 || !integer(x.steps_prepared) || x.steps_prepared > x.planned_steps
    || !integer(x.steps_reserved) || x.steps_reserved < x.steps_prepared || x.steps_reserved > 10000 || !integer(x.cases_reserved) || x.cases_reserved > 1000000
    || !positive(x.required_cases) || x.required_cases > 1268 || !integer(x.remaining_ms) || x.remaining_ms > 3600000 || !integer(x.lease_remaining_ms) || x.lease_remaining_ms > 60000
    || [x.current, x.report_current, x.can_advance, x.can_cancel, x.can_retire, x.can_read_request, x.can_read_details].some(v => typeof v !== 'boolean')
    || (x.can_read_details && (!x.report_current || !x.can_read_request))
    || (x.failure_reason !== null && (typeof x.failure_reason !== 'string' || x.failure_reason.length > 128))
    || (x.can_advance && (!x.can_read_request || !x.current || !x.remaining_ms || x.lease_remaining_ms || !['queued', 'processing'].includes(x.status)))
    || (x.can_cancel && !['queued', 'processing', 'failed'].includes(x.status)) || (x.can_retire && x.status !== 'completed')) throw new Error('Qualification state or budget is inconsistent.');
  if (x.report_current) {
    const c = x.counts;
    if (!x.current || x.status !== 'completed' || !x.remaining_ms || !sha.test(x.report_sha256 ?? '') || x.steps_prepared !== x.planned_steps || x.cases_reserved < x.required_cases
      || !c || !integer(c.passed) || !integer(c.failed) || !integer(c.unknown) || c.passed + c.failed + c.unknown !== x.required_cases
      || x.qualification_status !== (c.failed + c.unknown === 0 ? 'qualified' : 'rejected')) throw new Error('Qualification report does not reconcile.');
  } else if (x.counts !== null || x.report_sha256 !== null || x.qualification_status !== 'not_qualified') throw new Error('Held metadata cannot claim a current report.');
  if (installed && x.current && (x.registry_sha256 !== installed.registry_sha256 || x.required_cases !== installed.software_cases + installed.golden_cases + x.source_examples
    || x.planned_steps !== (x.mode === 'installed_default' ? 1 : Math.ceil((installed.software_cases + x.source_examples) / 20) + x.source_examples) + installed.golden_cases)) throw new Error('Qualification differs from the installed complete plan.');
  return x;
}
export type Active = { policy: { id: string; revision: number; revision_sha256: string; name: string; mode: string } | null; active_version: number; current: boolean; current_qualification_verified: boolean;
  remaining_ms: number; historical_head: boolean; inspection_enablement_granted: false; scope: string; control_version?: number; inspection_enabled?: boolean; activation_id?: string | null; predecessor_activation_id?: string | null };
export function active(x: Active, owner = false): Active {
  if (!x || !integer(x.active_version) || !integer(x.remaining_ms) || x.remaining_ms > 60000 || typeof x.current !== 'boolean' || x.current_qualification_verified !== x.current
    || x.historical_head !== (x.policy !== null) || x.inspection_enablement_granted !== false || x.scope !== (owner ? 'owner' : 'summary')
    || (x.policy === null ? x.active_version !== 0 || x.current : !positive(x.active_version) || !uuid.test(x.policy.id) || !positive(x.policy.revision) || !sha.test(x.policy.revision_sha256)
      || x.policy.mode !== 'deterministic_policy' || typeof x.policy.name !== 'string' || x.policy.name.length > 80)
    || (x.current && !x.remaining_ms) || (owner && (!positive(x.control_version) || typeof x.inspection_enabled !== 'boolean'
      || (x.policy === null ? x.activation_id !== null || x.predecessor_activation_id !== null : !uuid.test(x.activation_id ?? '') || (x.predecessor_activation_id !== null && !uuid.test(x.predecessor_activation_id ?? '')))))) throw new Error('Current policy context is unavailable.');
  return x;
}
export type Receipt = { transition_id: string; operation: string; policy_id: string; policy_revision: number; policy_revision_sha256: string; policy_state_version: number | null;
  qualification_id: string; qualification_report_sha256: string; active_version: number; previous_active_version: number; previous_control_version: number; control_version: number; activation_sha256: string;
  historical_receipt: true; current_qualification_verified: false; inspection_enablement_granted: false; predecessor_activation_id: string | null };
export function receipt(x: Receipt): Receipt {
  if (!x || !uuid.test(x.transition_id) || !['bootstrap', 'promote', 'rollback'].includes(x.operation) || !uuid.test(x.policy_id) || !positive(x.policy_revision) || x.policy_revision > 1000
    || !sha.test(x.policy_revision_sha256) || (x.policy_state_version !== null && !positive(x.policy_state_version)) || !uuid.test(x.qualification_id) || !sha.test(x.qualification_report_sha256)
    || !integer(x.previous_active_version) || !positive(x.active_version) || x.active_version !== x.previous_active_version + 1 || !positive(x.previous_control_version) || !positive(x.control_version) || x.control_version !== x.previous_control_version + 1
    || !sha.test(x.activation_sha256) || x.historical_receipt !== true || x.current_qualification_verified !== false || x.inspection_enablement_granted !== false
    || (x.operation === 'bootstrap' ? x.previous_active_version !== 0 || x.predecessor_activation_id !== null : !positive(x.previous_active_version) || !uuid.test(x.predecessor_activation_id ?? '')))
    throw new Error('Historical activation receipt is incomplete.');
  return x;
}
