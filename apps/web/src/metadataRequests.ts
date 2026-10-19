// Closed owner-control response and recovery-intent contracts; no authorization is granted here.
export const metadataBase = '/privacy/metadata-requests';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const sha = /^[0-9a-f]{64}$/;
const positive = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) > 0;
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= 64;
const flag = (v: unknown) => typeof v === 'boolean';
const invalid = (): never => { throw new Error('Owner maintenance metadata is unrecognized. Refresh authorized status; no erasure or resumption is confirmed.'); };
function keys(value: unknown, names: string): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(' ') === names.split(' ').sort().join(' ');
}
export function inspectionIds(text: string, max = 64): string[] {
  const ids = text.trim().split(/[\s,]+/).filter(Boolean);
  if (!positive(max) || max > 64 || !ids.length || ids.length > max || ids.some(id => !uuid.test(id)) || new Set(ids).size !== ids.length)
    throw new Error('Enter unique lowercase inspection IDs within the displayed limit. Only existing closed inspections can be selected.');
  return ids.sort();
}
export type MetadataContext = { gate_version: number; gate_phase: 'OPEN' | 'HELD'; gate_epoch: number; control_version: number;
  inspection_enabled: boolean; active_count: number; foreign_active: boolean; max_inspections: number; can_create: boolean;
  can_confirm_cleanup: false; erasure_complete: false; collateral_review_available?: boolean };
export function metadataContext(value: unknown): MetadataContext {
  const fields = 'gate_version gate_phase gate_epoch control_version inspection_enabled active_count foreign_active max_inspections can_create can_confirm_cleanup erasure_complete';
  if (!keys(value, fields) && !keys(value, fields + ' collateral_review_available')) return invalid();
  if ('collateral_review_available' in value && !flag(value.collateral_review_available)) return invalid();
  if (!positive(value.gate_version) || !positive(value.gate_epoch) || !positive(value.control_version) || !['OPEN', 'HELD'].includes(String(value.gate_phase))
    || !flag(value.inspection_enabled) || !count(value.active_count) || !flag(value.foreign_active) || (value.foreign_active && !value.active_count)
    || !positive(value.max_inspections) || value.max_inspections > 64 || value.can_create !== (value.gate_phase === 'OPEN' && value.inspection_enabled === false)
    || value.can_confirm_cleanup !== false || value.erasure_complete !== false) return invalid();
  return value as MetadataContext;
}
export type MetadataRequest = { id: string; state_version: number; status: 'held' | 'cancelled'; scope_sha256: string; inspection_ids: string[];
  selector_policy: 'read-only-family-selection-v3'; created_at_ms: number; original_owner_session: boolean; current_hold: boolean;
  gate_version: number; gate_epoch: number; gate_phase: 'OPEN' | 'HELD'; control_version: number; inspection_enabled: boolean;
  active_count: number; foreign_active: boolean; drain_status: 'not_current' | 'blocked_runtime' | 'waiting' | 'empty'; can_cancel: boolean;
  can_confirm_cleanup: false; erasure_complete: false; request_fulfilled: false; replayed?: boolean; original_operation?: 'held' | 'cancelled' };
const requestFields = 'id state_version status scope_sha256 inspection_ids selector_policy created_at_ms original_owner_session current_hold gate_version gate_epoch gate_phase control_version inspection_enabled active_count foreign_active drain_status can_cancel can_confirm_cleanup erasure_complete request_fulfilled';
export function metadataRequest(value: unknown, expectedId?: string, operation?: 'held' | 'cancelled'): MetadataRequest {
  if (!keys(value, requestFields + (operation ? ' replayed original_operation' : ''))) return invalid();
  const v = value as unknown as MetadataRequest;
  if (!uuid.test(v.id) || (expectedId !== undefined && v.id !== expectedId) || !sha.test(v.scope_sha256) || !['held', 'cancelled'].includes(v.status)
    || v.state_version !== (v.status === 'held' ? 1 : 2) || v.selector_policy !== 'read-only-family-selection-v3'
    || !Array.isArray(v.inspection_ids) || !v.inspection_ids.length || v.inspection_ids.length > 64 || v.inspection_ids.some(id => typeof id !== 'string' || !uuid.test(id))
    || v.inspection_ids.join(',') !== [...new Set(v.inspection_ids)].sort().join(',') || !Number.isSafeInteger(v.created_at_ms) || v.created_at_ms < 0
    || !positive(v.gate_version) || !positive(v.gate_epoch) || !positive(v.control_version) || !['OPEN', 'HELD'].includes(v.gate_phase)
    || !count(v.active_count) || !flag(v.foreign_active) || (v.foreign_active && !v.active_count) || !flag(v.inspection_enabled)
    || !flag(v.original_owner_session) || !flag(v.current_hold) || (v.current_hold && (v.gate_phase !== 'HELD' || v.status !== 'held'))
    || v.drain_status !== (!v.current_hold ? 'not_current' : v.inspection_enabled ? 'blocked_runtime' : v.active_count ? 'waiting' : 'empty')
    || v.can_cancel !== (v.status === 'held' && v.current_hold && !v.inspection_enabled && v.active_count === 0)
    || v.can_confirm_cleanup !== false || v.erasure_complete !== false || v.request_fulfilled !== false
    || (operation && (typeof v.replayed !== 'boolean' || v.original_operation !== operation))) return invalid();
  return v;
}
export function metadataOutcome(value: MetadataRequest): string {
  return 'Original request status: ' + value.status + '. No erasure or request fulfillment is confirmed. Inspections at this read: ' + (value.inspection_enabled ? 'enabled under separate authority' : 'disabled') + '. This status cannot authorize resumption; retain pending obligations with the accepting owner.';
}
export type MetadataCurrent = { status: 'open' | 'held'; request: MetadataRequest | null;
  unknown_writes_reconciled: false; inspection_resumption_authorized: false; can_confirm_cleanup: false;
  erasure_complete: false; request_fulfilled: false };
export function metadataCurrent(value: unknown): MetadataCurrent {
  if (!keys(value, 'status request unknown_writes_reconciled inspection_resumption_authorized can_confirm_cleanup erasure_complete request_fulfilled')) return invalid();
  const v = value as unknown as MetadataCurrent;
  if (!['open', 'held'].includes(v.status) || v.unknown_writes_reconciled !== false || v.inspection_resumption_authorized !== false
    || v.can_confirm_cleanup !== false || v.erasure_complete !== false || v.request_fulfilled !== false) return invalid();
  if (v.status === 'open') {
    if (v.request !== null) return invalid();
    return v;
  }
  const current = metadataRequest(v.request);
  if (current.current_hold !== true || current.status !== 'held' || current.gate_phase !== 'HELD') return invalid();
  return { ...v, request: current };
}
export type CreateMetadata = { inspection_ids: string[]; expected_gate_version: number; expected_control_version: number; interruption_acknowledged: true };
export type CancelMetadata = { confirmed_scope_sha256: string; expected_request_version: number; expected_gate_version: number; expected_control_version: number; no_erasure_acknowledged: true };
export type MetadataIntent = { schema_version: 1; user_id: string; key: string; kind: 'create' | 'cancel'; path: string; body: CreateMetadata | CancelMetadata };
export function metadataIntent(value: unknown, userId: string): MetadataIntent {
  if (!uuid.test(userId) || !keys(value, 'schema_version user_id key kind path body')) return invalid();
  const v = value as unknown as MetadataIntent;
  if (v.schema_version !== 1 || v.user_id !== userId || !uuid.test(v.key)) return invalid();
  const b = v.body as unknown as Record<string, unknown>;
  if (v.kind === 'create') {
    if (v.path !== metadataBase || !keys(b, 'inspection_ids expected_gate_version expected_control_version interruption_acknowledged') || b.interruption_acknowledged !== true
      || !Array.isArray(b.inspection_ids) || b.inspection_ids.some(x => typeof x !== 'string')
      || inspectionIds(b.inspection_ids.join(',')).join(',') !== b.inspection_ids.join(',')) return invalid();
  } else if (v.kind === 'cancel') {
    if (typeof v.path !== 'string' || !v.path.startsWith(metadataBase + '/') || !v.path.endsWith('/cancel') || !uuid.test(v.path.slice(metadataBase.length + 1, -7))
      || !keys(b, 'confirmed_scope_sha256 expected_request_version expected_gate_version expected_control_version no_erasure_acknowledged')
      || typeof b.confirmed_scope_sha256 !== 'string' || !sha.test(b.confirmed_scope_sha256) || !positive(b.expected_request_version) || b.no_erasure_acknowledged !== true) return invalid();
  } else return invalid();
  if (!positive(b.expected_gate_version) || !positive(b.expected_control_version)) return invalid();
  return v;
}
export const metadataStorage = 'proofpack.metadata.original-intent.v1';
export function parseMetadataIntent(raw: string, userId: string): MetadataIntent {
  if (typeof raw !== 'string' || raw.length > 8192) return invalid();
  return metadataIntent(JSON.parse(raw), userId);
}

export const metadataOperationMs = 7000;
export const metadataReadAttempts = 3;
export const metadataReadDelayMs = 100;
const interrupted = () => new DOMException('Maintenance review interrupted. Read fresh owner status; original write outcomes remain unconfirmed.', 'AbortError');
function pauseMetadataRead(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); signal.removeEventListener('abort', abort); reject(interrupted()); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, metadataReadDelayMs);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
}
// Caller supplies only a safe GET; this function never repeats identity flows or writes.
export async function metadataRead(fetchRead: (signal: AbortSignal) => Promise<unknown>, busy: (error: unknown) => boolean, signal: AbortSignal): Promise<unknown> {
  for (let attempt = 0; attempt < metadataReadAttempts; attempt++) {
    if (signal.aborted) throw interrupted();
    try {
      const value = await fetchRead(signal);
      if (signal.aborted) throw interrupted();
      return value;
    } catch (error) {
      if (signal.aborted) throw interrupted();
      if (attempt + 1 === metadataReadAttempts || !busy(error)) throw error;
      await pauseMetadataRead(signal);
    }
  }
  throw interrupted();
}
