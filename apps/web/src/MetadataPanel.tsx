import { useEffect, useRef, useState } from 'react';
import { ownerMetadataReview, type OwnerMetadataReview } from './ownerMetadataReview';
import { ownerPolicyObligations, type OwnerPolicyObligations, type AuthCategory } from './ownerPolicyObligations';
import { ownerCollateralScope, type OwnerCollateralScope } from './ownerCollateralScope';
import { api, ApiError, type User } from './api';
import { member } from './workbench';
import { metadataBase, metadataContext, metadataRequest, metadataCurrent, metadataIntent, metadataOutcome, metadataStorage, parseMetadataIntent, inspectionIds, metadataRead, metadataOperationMs,
  type MetadataContext, type MetadataRequest, type MetadataIntent } from './metadataRequests';

export function MetadataPanel({ onBack }: { onBack: () => void }) {
  const [user, setUser] = useState<User | null>(null), [context, setContext] = useState<MetadataContext | null>(null);
  const [record, setRecord] = useState<MetadataRequest | null>(null), [pending, setPending] = useState<MetadataIntent | null>(null);
  const [review, setReview] = useState<OwnerMetadataReview | null>(null);
  const [policy, setPolicy] = useState<OwnerPolicyObligations | null>(null);
  const [collateral, setCollateral] = useState<OwnerCollateralScope | null>(null);
  const [capability, setCapability] = useState<{enabled: boolean; max: number} | null>(null), [proposalEligible, setProposalEligible] = useState(false);
  const [selection, setSelection] = useState(''), [requestId, setRequestId] = useState('');
  const [holdAck, setHoldAck] = useState(false), [cancelAck, setCancelAck] = useState(false), [leaveAck, setLeaveAck] = useState(false);
  const [storageBlocked, setStorageBlocked] = useState(() => { try { return sessionStorage.getItem(metadataStorage) !== null; } catch { return true; } }), [busy, setBusy] = useState(false);
  const [message, say] = useState('Read your owner status or sign in with recent MFA. No inspection or cleanup starts here.');
  const lock = useRef(false), heading = useRef<HTMLHeadingElement>(null), active = useRef(true), operation = useRef<AbortController | null>(null);
  function clearHistory() { setReview(null); setPolicy(null); setCollateral(null); setProposalEligible(false); }
  function clearViews() { clearHistory(); setContext(null); setRecord(null); setHoldAck(false); setCancelAck(false); }
  function current(signal: AbortSignal) {
    if (signal.aborted || !active.current || document.visibilityState !== 'visible') throw new DOMException('Maintenance review interrupted. Read fresh owner status; original write outcomes remain unconfirmed.', 'AbortError');
  }
  useEffect(() => {
    active.current = true; heading.current?.focus();
    const hidden = () => { if (document.visibilityState !== 'visible') { operation.current?.abort(); clearViews(); setCapability(null); setUser(null); } };
    const offline = () => { operation.current?.abort('metadata-offline'); clearViews(); setCapability(null); setUser(null); say('Connection unavailable. Original server outcomes remain unconfirmed. Read owner status after recovery.'); };
    document.addEventListener('visibilitychange', hidden); window.addEventListener('offline', offline);
    return () => { active.current = false; operation.current?.abort(); document.removeEventListener('visibilitychange', hidden); window.removeEventListener('offline', offline); };
  }, []);
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    if (pending || storageBlocked) window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [pending, storageBlocked]);
  async function run(action: (signal: AbortSignal) => Promise<void>) {
    if (lock.current || !active.current) return;
    const controller = new AbortController(); operation.current = controller;
    const timer = window.setTimeout(() => controller.abort(), metadataOperationMs);
    lock.current = true; setBusy(true); clearHistory();
    try { current(controller.signal); await action(controller.signal); }
    catch (error) {
      if (active.current) {
        clearViews(); setCapability(null);
        if (error instanceof ApiError && [401, 403].includes(error.status)) setUser(null);
        const detail = controller.signal.reason === 'metadata-offline'
          ? 'Connection unavailable. Original server outcomes remain unconfirmed. Read owner status after recovery.'
          : error instanceof Error ? error.message : 'The outcome is unconfirmed.';
        say(detail + ' Keep the original intent for readback; no erasure, fulfillment or inspection resumption is confirmed.');
      }
    } finally { window.clearTimeout(timer); if (operation.current === controller) operation.current = null; lock.current = false; if (active.current) setBusy(false); }
  }
  const readOnly = (path: string, signal: AbortSignal) => metadataRead(next => api(path, { signal: next }), error => error instanceof ApiError && error.status === 503, signal);
  async function load(signal: AbortSignal) {
    clearViews(); setCapability(null); setUser(null);
    const owner = member(await readOnly('/me', signal) as User); current(signal);
    if (!owner.roles.includes('owner')) throw new Error('Only a currently authorized owner can review these requests.');
    setUser(owner);
    try {
      const raw = sessionStorage.getItem(metadataStorage);
      setPending(raw === null ? null : parseMetadataIntent(raw, owner.id)); setStorageBlocked(false);
    } catch { setPending(null); setStorageBlocked(true); throw new Error('Stored retry details are unavailable, malformed or belong to another owner. No new request can be sent until an acknowledged local closeout.'); }
    const context = metadataContext(await readOnly(metadataBase + '/context', signal)); current(signal); setContext(context);
    setCapability({enabled: context.collateral_review_available === true, max: context.max_inspections});
    say('Owner snapshot read. Refresh after changes. A held request is pending; cancellation erases nothing and leaves inspections disabled.');
  }
  function save(intent: MetadataIntent) {
    const raw = JSON.stringify(metadataIntent(intent, user!.id));
    if (raw.length > 8192) throw new Error('The original intent exceeds the recovery limit.');
    try { sessionStorage.setItem(metadataStorage, raw); if (sessionStorage.getItem(metadataStorage) !== raw) throw new Error(); }
    catch { setStorageBlocked(true); throw new Error('Tab recovery storage is unavailable. No request was sent.'); }
    setPending(intent); setLeaveAck(false);
  }
  async function send(intent: MetadataIntent, signal: AbortSignal) {
    current(signal);
    if (!user) throw new Error('Read current owner status before retrying.');
    clearViews();
    const value = metadataRequest(await api(intent.path, { user, method: 'POST', body: intent.body, idempotencyKey: intent.key, signal }),
      intent.kind === 'cancel' ? intent.path.slice(metadataBase.length + 1, -7) : undefined, intent.kind === 'create' ? 'held' : 'cancelled');
    current(signal);
    if (intent.kind === 'create') {
      if (!('inspection_ids' in intent.body) || value.inspection_ids.join(',') !== intent.body.inspection_ids.join(',')) throw new Error('Original request scope does not match.');
    } else if (!('confirmed_scope_sha256' in intent.body) || value.scope_sha256 !== intent.body.confirmed_scope_sha256 || value.status !== 'cancelled') throw new Error('Original cancellation scope does not match.');
    setRecord(value); setRequestId(value.id);
    try { sessionStorage.removeItem(metadataStorage); if (sessionStorage.getItem(metadataStorage) !== null) throw new Error(); }
    catch { setStorageBlocked(true); say('Server status read, but local retry cleanup is unconfirmed. Preserve the request reference; do not start a separate intent.'); return; }
    setPending(null); setStorageBlocked(false); setLeaveAck(false);
    say(metadataOutcome(value));
  }
  async function create(signal: AbortSignal) {
    current(signal);
    if (!user || !context?.can_create || !holdAck || pending || storageBlocked) throw new Error('Refresh the exact owner context and acknowledge interruption.');
    const intent: MetadataIntent = { schema_version: 1, user_id: user.id, key: crypto.randomUUID(), kind: 'create', path: metadataBase,
      body: { inspection_ids: inspectionIds(selection, context.max_inspections), expected_gate_version: context.gate_version,
        expected_control_version: context.control_version, interruption_acknowledged: true } };
    save(intent); await send(intent, signal);
  }
  async function cancel(signal: AbortSignal) {
    current(signal);
    if (!user || !record?.can_cancel || !cancelAck || pending || storageBlocked) throw new Error('Read the exact request and acknowledge that cancellation erases nothing.');
    const intent: MetadataIntent = { schema_version: 1, user_id: user.id, key: crypto.randomUUID(), kind: 'cancel', path: metadataBase + '/' + record.id + '/cancel',
      body: { confirmed_scope_sha256: record.scope_sha256, expected_request_version: record.state_version, expected_gate_version: record.gate_version,
        expected_control_version: record.control_version, no_erasure_acknowledged: true } };
    save(intent); await send(intent, signal);
  }
  async function read(signal: AbortSignal) {
    clearViews(); const id = inspectionIds(requestId, 1)[0];
    const value = metadataRequest(await readOnly(metadataBase + '/' + id, signal), id); current(signal); setRecord(value); setProposalEligible(true);
    say('Request snapshot read. This read alone does not reconcile an unknown write; retry its exact original intent.');
  }
  async function recoverCurrent(signal: AbortSignal) {
    clearViews(); setContext(null);
    const value = metadataCurrent(await readOnly(metadataBase + '/current', signal)); current(signal);
    if (value.request === null) {
      say('No current held request at this read. Preserve any uncertain original intent and outstanding duties; this is not a history or fulfillment result.');
      return;
    }
    setRecord(value.request); setRequestId(value.request.id); setProposalEligible(true);
    say('Current held request recovered as a snapshot. Preserve any uncertain original intent for separate reconciliation; no erasure, fulfillment or inspection resumption is confirmed.');
  }
  async function reviewRequest(signal: AbortSignal) {
    current(signal);
    if (!user || !record?.can_cancel || pending || storageBlocked || record.inspection_enabled || record.drain_status !== 'empty')
      throw new Error('Read the exact held request after confirmed drain before requesting historical accounting.');
    const binding = { id: record.id, scope_sha256: record.scope_sha256, request_version: record.state_version,
      gate_version: record.gate_version, control_version: record.control_version };
    const value = ownerMetadataReview(await api(metadataBase + '/' + record.id + '/review', { user, method: 'POST',
      body: { expected_request_version: binding.request_version, expected_gate_version: binding.gate_version,
        expected_control_version: binding.control_version }, signal }), binding);
    current(signal); setReview(value);
    say('Historical accounting read. These counts grant no cleanup, fulfillment or inspection resumption. Read fresh request status before another review.');
  }
  async function reviewPolicy(signal: AbortSignal) {
    current(signal);
    if (!user || !record?.can_cancel || (review?.accounting_policy !== 'conservative-family-accounting-v5' && review?.accounting_policy !== 'conservative-family-accounting-v6')
      || pending || storageBlocked || record.inspection_enabled || record.drain_status !== 'empty')
      throw new Error('Read fresh held request status and configured authentication accounting before reviewing missing privacy decisions.');
    const binding = {id: record.id, scope_sha256: record.scope_sha256, request_version: record.state_version,
      gate_version: record.gate_version, control_version: record.control_version};
    const result = ownerPolicyObligations(await api(metadataBase + '/' + record.id + '/policy-obligations', {user,method:'POST',
      body:{expected_request_version:binding.request_version,expected_gate_version:binding.gate_version,
        expected_control_version:binding.control_version},signal}),binding);
    current(signal); setPolicy(result);
    say('Missing privacy decisions reviewed as a snapshot. The business owner and privacy steward must agree the operating policy; no cleanup or fulfillment is approved.');
  }
  async function reviewCollateral(signal: AbortSignal) {
    current(signal);
    if (!user || !capability?.enabled || !proposalEligible || !record?.can_cancel || pending || storageBlocked || record.inspection_enabled || record.drain_status !== 'empty')
      throw new Error('Read fresh owner context and exact held request status after confirmed drain before a collateral proposal.');
    const binding = {id: record.id, scope_sha256: record.scope_sha256, request_version: record.state_version,
      gate_version: record.gate_version, control_version: record.control_version};
    const value = ownerCollateralScope(await api(metadataBase + '/' + record.id + '/collateral-scope-proposal', {user, method: 'POST',
      body: {expected_request_version: binding.request_version, expected_gate_version: binding.gate_version,
        expected_control_version: binding.control_version}, signal}), binding, record.inspection_ids, capability.max);
    current(signal); setCollateral(value);
    say('Historical collateral proposal read. No scope changed. Read fresh request status before another explicit proposal; unresolved duties remain pending.');
  }
  async function logout(signal: AbortSignal) {
    if (!user || ((pending || storageBlocked) && !leaveAck)) return;
    try { await api('/auth/logout', { user, method: 'POST', signal }); }
    finally { if (active.current) { setUser(null); setCapability(null); clearViews(); } }
    current(signal);
    sessionStorage.removeItem(metadataStorage); sessionStorage.removeItem('proofpack.maintenance.entry');
    setUser(null); setPending(null); setStorageBlocked(false); clearViews();
    say('Signed out. Local retry details cleared; any pending server request still needs its accepting owner and original reference.');
  }
  const leaveAllowed = !busy && (!(pending || storageBlocked) || leaveAck);
  return <section className="workbench metadata-maintenance" aria-labelledby="metadata-title" aria-busy={busy}>
    <h2 id="metadata-title" tabIndex={-1} ref={heading}>Owner maintenance</h2>
    <p>Review a bounded metadata request while ordinary work is held. This screen cannot classify or delete data, fulfill a request, or enable inspections.</p>
    <p role="status" aria-live="polite">{message}</p>
    <button disabled={busy} onClick={() => void run(load)}>Read owner status</button>
    <a href="/api/v1/auth/login?mfa=required" onClick={() => { try { sessionStorage.setItem('proofpack.maintenance.entry', 'v1'); } catch { /* Return through Owner maintenance if storage is unavailable. */ } }}>Sign in or refresh MFA</a>
    {user && <p>Signed in as {user.display_name}. Explicit owner authority is rechecked by the service for every request.</p>}
    {context && <div className="private-record"><h3>Owner snapshot</h3><p>Admission: {context.gate_phase}. Inspections: {context.inspection_enabled ? 'enabled; disable through approved runtime controls before requesting a hold' : 'disabled'}.</p>
      <p>{context.active_count} other registered work item(s). {context.foreign_active ? 'Previous-runtime work needs confirmed completion.' : 'Expiry never proves completion.'}</p></div>}
    {user && <>
      <fieldset disabled={busy || !!pending || storageBlocked || !context?.can_create}><legend>Create a request and hold</legend>
        <p>Use existing closed inspection IDs, up to {context?.max_inspections ?? 64}. The original scope is sorted; selection alone proves no ownership or completed erasure.</p>
        <label>Inspection IDs<textarea value={selection} onChange={event => { setSelection(event.target.value); clearHistory(); setHoldAck(false); }}/></label>
        <label className="check"><input type="checkbox" checked={holdAck} onChange={event => setHoldAck(event.target.checked)}/>I acknowledge interruption of ordinary work; this hold erases nothing.</label>
        <button disabled={!holdAck} onClick={() => void run(create)}>Create request and hold</button>
      </fieldset>
      <fieldset disabled={busy}><legend>Read an existing request</legend>
        <p>Recover a lost request ID from the current hold. Keep any uncertain original retry for separate readback.</p>
        <button onClick={() => void run(recoverCurrent)}>Recover current held request</button>
        <label>Metadata request ID<input value={requestId} onChange={event => { setRequestId(event.target.value); clearHistory(); setRecord(null); setCancelAck(false); }}/></label>
        <button onClick={() => void run(read)}>Read request status</button></fieldset>
    </>}
    {user && record && <div className="private-record"><h3>Request {record.id}</h3><p>Status: {record.status}. Drain: {record.drain_status}. This is a snapshot, not a cleanup receipt.</p>
      <p>Scope: {record.inspection_ids.join(', ')}. Scope digest: {record.scope_sha256}.</p><p>{record.original_owner_session ? 'Original creator session.' : 'Historical creator session; current authority is separate.'}</p>
      <p>Erasure complete: no. Request fulfilled: no. Inspections at this read: {record.inspection_enabled ? 'enabled under separate authority' : 'disabled'}. Cancellation grants no authority to resume; keep pending obligations with the accepting owner.</p>
      <button disabled={busy || !record.can_cancel || !!pending || storageBlocked || !!review} onClick={() => void run(reviewRequest)}>Read historical accounting</button>
      {review && <section aria-labelledby="metadata-review-title"><h4 id="metadata-review-title">Historical accounting hints</h4>
        <p>Accounting policy: {review.accounting_policy}.</p>
        {(review.accounting_policy === 'conservative-family-accounting-v5' || review.accounting_policy === 'conservative-family-accounting-v6') && <><p>Supported authentication history was inspected. Operational authentication policy remains unresolved; historical authentication authority is not proven. This is not a cleanup preview or permission to delete records.</p>
          {review.accounting_policy === 'conservative-family-accounting-v6' && <p>Supported privacy-request history was also inspected. Retention policy remains unresolved; past authorization is not proven. Shared action receipts and write allowances are not inspection contents or permission to erase them.</p>}
          <button disabled={busy || !!pending || storageBlocked} onClick={() => void run(reviewPolicy)}>Explain missing privacy decisions</button></>}
        <p>Conservative historical counts for this exact request. They do not confirm ownership, authorize deletion or fulfill a request. Zero unresolved hints does not approve cleanup.</p>
        <table><caption>Historical record counts; no cleanup authority</caption><thead><tr><th scope="col">Accounting hint</th><th scope="col">Records</th></tr></thead>
          <tbody>{Object.entries(review.counts).map(([name, count]) => <tr key={name}><th scope="row">{name}</th><td>{count}</td></tr>)}
            <tr><th scope="row">Total records</th><td>{review.total_records}</td></tr></tbody></table>
        <p>Read only: yes. Erasure complete: no. Request fulfilled: no. Inspections cannot resume from this snapshot.</p>
      </section>}
      {policy && <section aria-labelledby="metadata-policy-title"><h4 id="metadata-policy-title">Missing privacy decisions</h4>
        <p>Business owner and privacy steward: agree the business purpose, retention period, applicable requester rights and approver in the private operating policy. No retention period is selected here.</p>
        <p>These are reviewed deployment authentication records. The categories do not establish inspection ownership, historical authority or permission to delete.</p>
        <table><caption>Reviewed authentication categories requiring an operating policy</caption><thead><tr><th scope="col">Category</th><th scope="col">Records</th></tr></thead>
          <tbody>{Object.entries(policy.family_counts).map(([name,n]) => <tr key={name}><th scope="row">{({
            'access-head':'Current access control',bootstrap:'Initial owner setup',user:'Account records',identity:'Sign-in identities',
            session:'Sessions',cookie:'Session references',invitation:'Invitations','owner-transfer':'Ownership transfers',
            'access-replay':'Access action receipts','oauth-flow':'Sign-in flows','oauth-quota':'Sign-in allowances'
          } satisfies Record<AuthCategory,string>)[name as AuthCategory]}</th><td>{n}</td></tr>)}</tbody></table>
        <p>Reviewed authentication records: {policy.validated_auth_records}. Source inventory records: {policy.source_records}. Earlier source references unavailable: {policy.historical_dependencies_unavailable}.</p>
        {policy.policy === 'privacy-policy-obligations-v2' && <>
          <table><caption>Reviewed privacy-request categories requiring an operating policy</caption><thead><tr><th scope="col">Category</th><th scope="col">Records</th></tr></thead>
            <tbody>{Object.entries(policy.metadata_family_counts).map(([name,n]) => <tr key={name}><th scope="row">{({
              'metadata-request':'Privacy requests','metadata-operation':'Action receipts','metadata-event':'Audit history','metadata-quota':'Shared write allowances'
            } as Record<string,string>)[name]}</th><td>{n}</td></tr>)}</tbody></table>
          <p>Reviewed privacy-request records: {policy.validated_metadata_records}. Earlier privacy-request references unavailable: {policy.metadata_historical_dependencies_unavailable}.</p>
          <p>These categories do not prove who may erase records. Shared write allowances must not be reset or refunded by this review.</p>
        </>}
        <p>Policy remains unresolved even if a count is zero. Read only: yes. Cleanup authorized: no. Request fulfilled: no. Inspections cannot resume from this snapshot.</p>
      </section>}
      {capability?.enabled && <>
        <p>Collateral review is available for this configured service. Read fresh request status before each explicit proposal. Scope limit: {capability.max} inspections.</p>
        <button disabled={busy || !proposalEligible || !record.can_cancel || !!pending || storageBlocked} onClick={() => void run(reviewCollateral)}>Read collateral scope proposal</button>
      </>}
      {collateral && <section aria-labelledby="metadata-collateral-title"><h4 id="metadata-collateral-title">Historical collateral scope proposal</h4>
        <p>No scope changed. This is not a cleanup preview, complete classification or authorization. Other inspections may contain unrelated business records.</p>
        <p>Original inspection references: {collateral.original_inspection_ids.join(', ')}.</p>
        <p>Proposed inspection references: {collateral.proposed_inspection_ids.join(', ')}.</p>
        <p>Additional inspection references: {collateral.additional_inspection_ids.join(', ') || 'none'}.</p>
        <p>Implicated records: {collateral.implicated_records}. Unresolved records: {collateral.unresolved_records}. Total inventory records: {collateral.total_records}.</p>
        <p>Unknown obligations remain pending even when no additional inspections are listed. No erasure, request fulfillment or inspection resumption is confirmed.</p>
        <p>Keep the original request reference with the accepting steward. Broader scope requires a separate decision: any acknowledged pre-cleanup cancellation erases nothing and leaves inspections disabled; then read fresh owner context, review each selected inspection and create a new ordinary request. If capacity or policy is insufficient, stop for accountable investigation.</p>
      </section>}
      <label className="check"><input type="checkbox" disabled={busy || !record.can_cancel || !!pending || storageBlocked} checked={cancelAck} onChange={event => setCancelAck(event.target.checked)}/>I acknowledge cancellation performs no erasure and leaves inspections disabled.</label>
      <button disabled={busy || !record.can_cancel || !cancelAck || !!pending || storageBlocked} onClick={() => void run(cancel)}>Cancel this request before cleanup</button>
    </div>}
    {pending && <div className="private-record"><h3>Original outcome unconfirmed</h3><p>No new intent is available until the original is reconciled. A timeout or denied response does not prove that nothing committed.</p>
      {user?.id === pending.user_id && <><p>Keep these opaque recovery details privately; they grant no access.</p><pre className="notice-text">{JSON.stringify(pending, null, 2)}</pre>
        <button disabled={busy || storageBlocked} onClick={() => void run(signal => send(pending, signal))}>Retry original {pending.kind}</button></>}
    </div>}
    {(pending || storageBlocked) && <label className="check"><input type="checkbox" checked={leaveAck} onChange={event => setLeaveAck(event.target.checked)}/>I have kept the original recovery reference privately and accepted follow-up. Leaving or signing out cannot cancel or fulfill server work; sign-out discards local retry details.</label>}
    {storageBlocked && <button disabled={busy || !leaveAck} onClick={() => { try { sessionStorage.removeItem(metadataStorage); setStorageBlocked(false); setPending(null); clearViews(); say('Local retry details cleared only. Investigate the original server outcome before any separate request.'); } catch { say('Local recovery storage could not be cleared. Stop and use the agreed procedure.'); } }}>Clear acknowledged local retry details</button>}
    <button disabled={!leaveAllowed} onClick={onBack}>Back to workspace</button>
    {user && <button disabled={!leaveAllowed} onClick={() => void run(logout)}>Sign out of maintenance</button>}
  </section>;
}
