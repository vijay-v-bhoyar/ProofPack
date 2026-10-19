// Historical minimized proposal only; never an executable scope or cleanup capability.
import type {ReviewBinding} from './ownerMetadataReview';
export type OwnerCollateralScope = ReviewBinding & {
  proposal_policy: 'whole-artifact-collateral-proposal-v1';
  original_inspection_ids: string[]; proposed_inspection_ids: string[]; additional_inspection_ids: string[];
  implicated_records: number; unresolved_records: number; total_records: number;
  historical: true; read_only: true; scope_changed: false; can_confirm_cleanup: false; erasure_complete: false; request_fulfilled: false;
};
const bindingFields = 'id scope_sha256 request_version gate_version control_version';
const fields = bindingFields + ' proposal_policy original_inspection_ids proposed_inspection_ids additional_inspection_ids implicated_records unresolved_records total_records historical read_only scope_changed can_confirm_cleanup erasure_complete request_fulfilled';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const safe = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
function closed(v: unknown, names: string): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(' ') === names.split(' ').sort().join(' ');
}
function scope(v: unknown, max: number, empty = false): v is string[] {
  return Array.isArray(v) && (empty || v.length > 0) && v.length <= max
    && v.every(id => typeof id === 'string' && uuid.test(id)) && v.join(',') === [...new Set(v)].sort().join(',');
}
const invalid = (): never => { throw new Error('Historical collateral scope is unrecognized or stale. Read fresh owner context and request status. No scope change, cleanup or fulfillment is confirmed.'); };
export function ownerCollateralScope(value: unknown, expected: ReviewBinding, original: readonly string[], max: number): OwnerCollateralScope {
  if (!safe(max) || max < 1 || max > 64 || !closed(expected, bindingFields) || typeof expected.id !== 'string' || !uuid.test(expected.id)
    || typeof expected.scope_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expected.scope_sha256)
    || ![expected.request_version, expected.gate_version, expected.control_version].every(v => safe(v) && v > 0)
    || !scope(original, max) || !closed(value, fields) || Object.entries(expected).some(([key, wanted]) => value[key] !== wanted)
    || value.proposal_policy !== 'whole-artifact-collateral-proposal-v1'
    || !scope(value.original_inspection_ids, max) || value.original_inspection_ids.join(',') !== original.join(',')
    || !scope(value.proposed_inspection_ids, max) || !scope(value.additional_inspection_ids, max, true)
    || original.some(id => !(value.proposed_inspection_ids as string[]).includes(id))) return invalid();
  const difference = value.proposed_inspection_ids.filter(id => !original.includes(id));
  if (difference.join(',') !== value.additional_inspection_ids.join(',')
    || !safe(value.implicated_records) || !safe(value.unresolved_records) || !safe(value.total_records)
    || !Number.isSafeInteger(value.implicated_records + value.unresolved_records)
    || value.implicated_records + value.unresolved_records > value.total_records
    || value.historical !== true || value.read_only !== true || value.scope_changed !== false
    || value.can_confirm_cleanup !== false || value.erasure_complete !== false || value.request_fulfilled !== false) return invalid();
  return value as unknown as OwnerCollateralScope;
}
