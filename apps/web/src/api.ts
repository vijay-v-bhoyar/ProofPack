import { metadataStorage } from './metadataRequests';
export type User = { id: string; display_name: string; roles: string[]; csrf_token: string; session_id: string };
export type Station = { id: string; name: string; state_version: number; epoch: number; owner_session_id: string | null;
  active_inspection_id: string | null; owned_by_current_session: boolean; calibration_profile_id: string };
export type Status = { id: string; station_id: string; state_version: number; effective_state: string; remaining_lease_ms: number;
  last_observed_at: number | null; action?: { id: string; kind: string; message: string; observation_id?: string; correction_reference_available?: boolean } | null };
export type Context = { context_version: number; capture_transform: string; inspection_id: string; recipe_name: string;
  recipe_revision: number; data_origin: string; policy_mode: string; camera_label: string; frame_width: number; frame_height: number;
  work_polygon: number[][]; constraints: { constraint_id: string; part_class_id: string; expected_count: number }[]; remaining_context_ms: number;
  original_capture_retention_allowed?: boolean; original_capture_remaining_attempts?: number };

export class ApiError extends Error {
  constructor(public status: number) {
    super(status === 401 ? 'Sign in again with your invited account.' : status === 403 ? 'Your current session cannot perform this action. Ask the owner or supervisor.' :
      status === 409 ? 'State changed or work is still pending. Refresh status before continuing; do not restart the kit.' :
      status === 429 ? 'The service is busy. Stop and refresh status before trying again.' : status === 503 ? 'This workflow is unavailable. Use the ordinary manual check and ask the owner.' :
      'The request could not be completed. Stop and refresh status before continuing.');
  }
}

export async function api<T>(path: string, options: { user?: Pick<User, 'csrf_token'>; body?: object | FormData; method?: string; version?: number; signal?: AbortSignal; idempotencyKey?: string } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  const method = options.method ?? 'GET';
  if (method !== 'GET') {
    if (!options.user) throw new Error('An invited session is required.');
    headers['X-CSRF-Token'] = options.user.csrf_token;
    headers['Idempotency-Key'] = options.idempotencyKey ?? crypto.randomUUID();
    if (options.version !== undefined) headers['If-Match'] = String(options.version);
  }
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = window.setTimeout(abort, 7000);
  try {
    const response = await fetch('/api/v1' + path, { method, headers, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
      body: options.body instanceof FormData ? options.body : options.body ? JSON.stringify(options.body) : undefined });
    if (!response.ok) throw new ApiError(response.status);
    if (path === '/auth/logout' && method === 'POST') { try { sessionStorage.removeItem(metadataStorage); sessionStorage.removeItem('proofpack.maintenance.entry'); } catch { /* A confirmed logout must not be reinterpreted as a failed network operation. */ } }
    return response.status === 204 ? undefined as T : await response.json() as T;
  } catch (error) {
    if (error instanceof TypeError) throw new Error('Connection unavailable. The operation outcome is unconfirmed. Review current state before retrying; use manual checking for interrupted inspections.');
    if (error instanceof SyntaxError) throw new Error('Unrecognized service response. Stop checking and ask the owner.');
    throw error;
  } finally { window.clearTimeout(timer); options.signal?.removeEventListener('abort', abort); }
}

export function statusValue(value: Status): Status {
  if (!value || !['CREATED', 'OBSERVING', 'ACTION_REQUIRED', 'REVIEW_REQUIRED', 'PASSED_CURRENT', 'INVALIDATED', 'CLOSED'].includes(value.effective_state)
    || !Number.isSafeInteger(value.state_version) || value.state_version < 1 || !Number.isFinite(value.remaining_lease_ms)
    || value.remaining_lease_ms < 0 || value.remaining_lease_ms > 1000) throw new Error('Unrecognized status. Stop and ask the supervisor.');
  if (value.action && (!['RECAPTURE', 'PLACE_FLAT', 'SEPARATE_REGION', 'REVIEW'].includes(value.action.kind) || typeof value.action.message !== 'string'
    || value.action.message.length > 300)) throw new Error('Unrecognized correction. Ask for manual review.');
  if (value.action?.correction_reference_available !== undefined && (typeof value.action.correction_reference_available !== 'boolean'
    || (value.action.correction_reference_available && (!['PLACE_FLAT', 'SEPARATE_REGION'].includes(value.action.kind) || value.effective_state !== 'ACTION_REQUIRED'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.action.observation_id ?? ''))))) throw new Error('Correction source is unavailable. Stop and request fresh status.');
  return value;
}

export function contextValue(value: Context): Context {
  if (!value || value.context_version !== 1 || value.capture_transform !== 'center_crop_resize_no_upscale'
    || !Number.isSafeInteger(value.frame_width) || !Number.isSafeInteger(value.frame_height)
    || Math.min(value.frame_width, value.frame_height) < 16 || Math.max(value.frame_width, value.frame_height) > 2000
    || value.frame_width * value.frame_height > 2000000 || !Array.isArray(value.work_polygon) || value.work_polygon.length !== 4
    || value.work_polygon.some(point => point.length !== 2 || point.some(v => !Number.isFinite(v) || v < 0 || v > 1))
    || !Array.isArray(value.constraints) || value.constraints.length < 1 || value.constraints.length > 4
    || value.constraints.some(item => !Number.isSafeInteger(item.expected_count) || item.expected_count < 0 || item.expected_count > 30 || typeof item.part_class_id !== 'string')
    || !['synthetic','printable','physical'].includes(value.data_origin) || value.policy_mode !== 'deterministic_policy'
    || !Number.isFinite(value.remaining_context_ms) || value.remaining_context_ms <= 0
    || ((value.original_capture_retention_allowed !== undefined || value.original_capture_remaining_attempts !== undefined)
      && (typeof value.original_capture_retention_allowed !== 'boolean' || !Number.isSafeInteger(value.original_capture_remaining_attempts)
        || value.original_capture_remaining_attempts! < 0 || value.original_capture_remaining_attempts! > 3))) throw new Error('Approved camera geometry is unavailable. Ask the owner.');
  return value;
}
