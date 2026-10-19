import type { ReviewBinding } from './ownerMetadataReview';
export const authCategories = ['access-head','bootstrap','user','identity','session','cookie','invitation','owner-transfer','access-replay','oauth-flow','oauth-quota'] as const;
export type AuthCategory = typeof authCategories[number];
export const metadataCategories = ['metadata-request','metadata-operation','metadata-event','metadata-quota'] as const;
export type MetadataCategory = typeof metadataCategories[number];
type PolicyVersion = {policy: 'auth-policy-obligations-v1'; accounting_policy: 'conservative-family-accounting-v5'}
  | {policy: 'privacy-policy-obligations-v2'; accounting_policy: 'conservative-family-accounting-v6';
      metadata_family_counts: Record<MetadataCategory,number>; validated_metadata_records: number;
      metadata_historical_dependencies_unavailable: number; metadata_history_policy_resolved: false;
      historical_metadata_authority_proven: false};
export type OwnerPolicyObligations = ReviewBinding & PolicyVersion & {
  family_counts: Record<AuthCategory, number>; validated_auth_records: number; source_records: number;
  historical_dependencies_unavailable: number; next_step: 'OWNER_D11_POLICY_DECISION_REQUIRED';
  historical: true; read_only: true; auth_history_policy_resolved: false; historical_auth_authority_proven: false;
  can_confirm_cleanup: false; erasure_complete: false; request_fulfilled: false;
};
const bindingKeys = 'id scope_sha256 request_version gate_version control_version';
function closed(v: unknown, names: string): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    && Object.keys(v).sort().join(' ') === names.split(' ').sort().join(' ');
}
const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const invalid = (): never => { throw new Error('Privacy decision explanation is unrecognized or stale. Read fresh request status. No policy, cleanup or fulfillment is confirmed.'); };
export function ownerPolicyObligations(value: unknown, expected: ReviewBinding): OwnerPolicyObligations {
  if (!closed(expected,bindingKeys) || typeof expected.id !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(expected.id)
    || typeof expected.scope_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expected.scope_sha256)
    || ![expected.request_version,expected.gate_version,expected.control_version].every(v => count(v) && v > 0)) return invalid();
  const metadata = value !== null && typeof value === 'object' && 'policy' in value && value.policy === 'privacy-policy-obligations-v2';
  const extra = metadata ? ' metadata_family_counts validated_metadata_records metadata_historical_dependencies_unavailable metadata_history_policy_resolved historical_metadata_authority_proven' : '';
  if (!closed(value,bindingKeys+' policy accounting_policy family_counts validated_auth_records source_records historical_dependencies_unavailable next_step historical read_only auth_history_policy_resolved historical_auth_authority_proven can_confirm_cleanup erasure_complete request_fulfilled'+extra)
    || Object.entries(expected).some(([key,wanted]) => value[key] !== wanted)
    || (metadata ? value.accounting_policy !== 'conservative-family-accounting-v6'
      : value.policy !== 'auth-policy-obligations-v1' || value.accounting_policy !== 'conservative-family-accounting-v5')
    || value.next_step !== 'OWNER_D11_POLICY_DECISION_REQUIRED' || value.historical !== true || value.read_only !== true
    || ['auth_history_policy_resolved','historical_auth_authority_proven','can_confirm_cleanup','erasure_complete','request_fulfilled'].some(key => value[key] !== false)
    || !count(value.validated_auth_records) || !count(value.source_records) || !count(value.historical_dependencies_unavailable)
    || value.validated_auth_records > value.source_records || !closed(value.family_counts,authCategories.join(' '))) return invalid();
  let total = 0;
  for (const name of authCategories) {
    const n = value.family_counts[name]; if (!count(n)) return invalid();
    total += n; if (!Number.isSafeInteger(total)) return invalid();
  }
  if (total !== value.validated_auth_records) return invalid();
  if (metadata) {
    if (!closed(value.metadata_family_counts,metadataCategories.join(' ')) || !count(value.validated_metadata_records)
      || !count(value.metadata_historical_dependencies_unavailable) || value.metadata_history_policy_resolved !== false
      || value.historical_metadata_authority_proven !== false) return invalid();
    let metadataTotal = 0;
    for (const name of metadataCategories) {
      const n = value.metadata_family_counts[name]; if (!count(n)) return invalid();
      metadataTotal += n; if (!Number.isSafeInteger(metadataTotal)) return invalid();
    }
    const combined = value.validated_auth_records + value.validated_metadata_records;
    if (metadataTotal !== value.validated_metadata_records || !Number.isSafeInteger(combined) || combined > value.source_records) return invalid();
  }
  return value as unknown as OwnerPolicyObligations;
}
