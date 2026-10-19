// Historical accounting hints only; this response cannot authorize cleanup or resumption.
export type ReviewBinding = { id: string; scope_sha256: string; request_version: number; gate_version: number; control_version: number };
type AccountingPolicy = { accounting_policy: 'conservative-family-accounting-v1' }
  | { accounting_policy: 'conservative-family-accounting-v5'; auth_history_policy_resolved: false; historical_auth_authority_proven: false }
  | { accounting_policy: 'conservative-family-accounting-v6'; auth_history_policy_resolved: false; historical_auth_authority_proven: false;
      metadata_history_policy_resolved: false; historical_metadata_authority_proven: false };
export type OwnerMetadataReview = ReviewBinding & AccountingPolicy & {
  counts: Record<'AFFECTED' | 'SHARED' | 'CONTEXT' | 'UNRELATED' | 'UNRESOLVED', number>; total_records: number;
  historical: true; read_only: true; can_confirm_cleanup: false; erasure_complete: false; request_fulfilled: false };
const bindingKeys = 'id scope_sha256 request_version gate_version control_version';
const categories = ['AFFECTED', 'SHARED', 'CONTEXT', 'UNRELATED', 'UNRESOLVED'] as const;
function closed(value: unknown, names: string): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(' ') === names.split(' ').sort().join(' ');
}
const positive = (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const nonnegative = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const invalid = (): never => { throw new Error('Historical accounting is unrecognized or does not match this request. Read fresh status. No cleanup, fulfillment or resumption is confirmed.'); };
export function ownerMetadataReview(value: unknown, expected: ReviewBinding): OwnerMetadataReview {
  if (!closed(expected, bindingKeys) || typeof expected.id !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(expected.id)
    || typeof expected.scope_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expected.scope_sha256)
    || !positive(expected.request_version) || !positive(expected.gate_version) || !positive(expected.control_version)) return invalid();
  const metadata = value !== null && typeof value === 'object' && 'accounting_policy' in value
    && value.accounting_policy === 'conservative-family-accounting-v6';
  const auth = metadata || (value !== null && typeof value === 'object' && 'accounting_policy' in value
    && value.accounting_policy === 'conservative-family-accounting-v5');
  const authKeys = auth ? ' auth_history_policy_resolved historical_auth_authority_proven' : '';
  const metadataKeys = metadata ? ' metadata_history_policy_resolved historical_metadata_authority_proven' : '';
  if (!closed(value, bindingKeys + ' accounting_policy counts total_records historical read_only can_confirm_cleanup erasure_complete request_fulfilled' + authKeys + metadataKeys)
    || Object.entries(expected).some(([key, wanted]) => value[key] !== wanted)
    || (!auth && value.accounting_policy !== 'conservative-family-accounting-v1')
    || (auth && (value.auth_history_policy_resolved !== false || value.historical_auth_authority_proven !== false))
    || (metadata && (value.metadata_history_policy_resolved !== false || value.historical_metadata_authority_proven !== false))
    || value.historical !== true || value.read_only !== true || value.can_confirm_cleanup !== false
    || value.erasure_complete !== false || value.request_fulfilled !== false
    || !closed(value.counts, categories.join(' ')) || !nonnegative(value.total_records)) return invalid();
  let total = 0;
  for (const category of categories) {
    const count = value.counts[category];
    if (!nonnegative(count)) return invalid();
    total += count;
    if (!Number.isSafeInteger(total)) return invalid();
  }
  if (total !== value.total_records) return invalid();
  return value as unknown as OwnerMetadataReview;
}
