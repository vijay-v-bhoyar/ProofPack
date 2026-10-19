import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, contextValue, statusValue } from './api';
import { EvidencePanel } from './EvidencePanel';
import type { Context, Station, Status, User } from './api';
import { drawCapture, imageBlob, nextFrame, requestCamera, startPlayback } from './camera';

type HumanDecision = { id: string; inspection_id: string; disposition: string; reason: string; human_check_confirmed: boolean; machine_approval: false; independent_truth_verified: false; sha256: string };
type DecisionIntent = { inspection: string; version: number; key: string; body: { expected_epoch: number; disposition: string; reason: string; human_check_confirmed: boolean } };
type Recipe = { id: string; name: string };
const explanation = (error: unknown) => error instanceof Error && error.name !== 'AbortError' ? error.message : 'Connection interrupted. Refresh status; do not start a replacement inspection.';

export function OperatorWorkspace({ onWorkbench, onInvitation, onEvidence, onSupport }: { onWorkbench: () => void; onInvitation: () => void; onEvidence: (id: string) => void; onSupport: (id: string) => void }) {
  const [user, setUser] = useState<User | null>(null), [message, setMessage] = useState('Loading invited account…');
  const [busy, setBusy] = useState(false), [uncertainLogout, setUncertainLogout] = useState(false);
  const [stations, setStations] = useState<Station[]>([]), [recipes, setRecipes] = useState<Recipe[]>([]);
  const [stationCursor, setStationCursor] = useState<string | null>(null), [recipeCursor, setRecipeCursor] = useState<string | null>(null);
  const [stationId, setStationId] = useState(''), [recipeId, setRecipeId] = useState(''), [kit, setKit] = useState('');
  const [context, setContext] = useState<Context | null>(null), [status, setStatus] = useState<Status | null>(null);
  const [findings, setFindings] = useState<string[]>([]);
  const [correctionOpen, setCorrectionOpen] = useState(false);
  const [cameraOn, setCameraOn] = useState(false), [running, setRunning] = useState(false), [confirmed, setConfirmed] = useState(false);
  const [retainOriginal, setRetainOriginal] = useState(false), [originalsRemaining, setOriginalsRemaining] = useState(0);
  const originalChoice = useRef(false), originalBudget = useRef(0);
  const [devices, setDevices] = useState<MediaDeviceInfo[]>([]), [device, setDevice] = useState('');
  const [takeover, setTakeover] = useState(false), [disposition, setDisposition] = useState(''), [reason, setReason] = useState('');
  const [, repaint] = useState(0);
  const video = useRef<HTMLVideoElement>(null), canvas = useRef<HTMLCanvasElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const stream = useRef<MediaStream | null>(null), controller = useRef(new AbortController());
  const generation = useRef(0), work = useRef(''), revision = useRef(1), run = useRef(false), mounted = useRef(true);
  const lease = useRef(0), contextUntil = useRef(0), lastFrame = useRef(0), scene = useRef(0), pixels = useRef<Uint8ClampedArray | null>(null);
  const mutation = useRef(false);
  const decisionIntent = useRef<DecisionIntent | null>(null);
  const [decisionPending, setDecisionPending] = useState(false), [humanCheck, setHumanCheck] = useState(false), [decisionNotice, setDecisionNotice] = useState('');

  const stop = useCallback((text?: string) => {
    generation.current++; run.current = false; lease.current = 0; controller.current.abort();
    originalChoice.current = false;
    stream.current?.getTracks().forEach(track => track.stop()); stream.current = null; pixels.current = null;
    if (video.current) video.current.srcObject = null;
    if (canvas.current) { canvas.current.width = 0; canvas.current.height = 0; }
    if (mounted.current) { setCameraOn(false); setRunning(false); setConfirmed(false); setRetainOriginal(false); setCorrectionOpen(false); if (text) setMessage(text); }
  }, []);

  useEffect(() => {
    mounted.current = true;
    title.current?.focus();
    let active = true;
    void api<User>('/me').then(me => {
      if (!active) return;
      if (!Array.isArray(me.roles) || typeof me.csrf_token !== 'string' || typeof me.session_id !== 'string') throw new Error('Invited account information is unavailable.');
      setUser(me); setMessage(me.roles.includes('operator') ? 'Select a station. Capture starts only after your explicit action.' : 'This account has no operator grant. Ask the owner for the role required for your work.');
    }).catch(async error => {
      if (!active) return;
      if (error instanceof ApiError && error.status === 403) {
        try { const session = await api<{ status: string }>('/auth/session'); if (active && session.status === 'invitation_pending') { onInvitation(); return; } }
        catch { /* Keep the original denial; no membership is inferred from a failed read. */ }
      }
      if (active) setMessage(explanation(error));
    });
    const visibility = () => { if (document.visibilityState !== 'visible') stop('Page hidden. Restore the camera and obtain fresh observations.'); };
    const offline = () => stop('Connection unavailable. Use the manual check; server status is unconfirmed.');
    window.addEventListener('offline', offline); window.addEventListener('pagehide', offline); document.addEventListener('visibilitychange', visibility);
    const tick = window.setInterval(() => { if (lease.current && performance.now() - lastFrame.current > 750) lease.current = 0; repaint(v => v + 1); }, 100);
    return () => { active = false; mounted.current = false; stop(); window.clearInterval(tick);
      window.removeEventListener('offline', offline); window.removeEventListener('pagehide', offline); document.removeEventListener('visibilitychange', visibility); };
  }, [stop]);

  const operator = !!user?.roles.includes('operator') && !uncertainLogout;
  const selected = stations.find(item => item.id === stationId);
  async function perform(task: () => Promise<void>) {
    if (mutation.current) return;
    mutation.current = true; setBusy(true); lease.current = 0;
    try { await task(); } catch (error) { if (mounted.current) stop(explanation(error)); }
    finally { mutation.current = false; if (mounted.current) setBusy(false); }
  }
  async function loadLists(moreStations = false, moreRecipes = false) {
    if (!user) return;
    const [ss, rr] = await Promise.all([
      !moreRecipes ? api<{ stations: Station[]; next_cursor: string | null }>('/stations' + (moreStations && stationCursor ? '?cursor=' + encodeURIComponent(stationCursor) : '')) : Promise.resolve(null),
      !moreStations ? api<{ recipes: Recipe[]; next_cursor: string | null }>('/recipes' + (moreRecipes && recipeCursor ? '?cursor=' + encodeURIComponent(recipeCursor) : '')) : Promise.resolve(null),
    ]);
    if (ss) { setStations(old => moreStations ? [...old.filter(row => !ss.stations.some(s => s.id === row.id)), ...ss.stations] : ss.stations); setStationCursor(ss.next_cursor); }
    if (rr) { setRecipes(old => moreRecipes ? [...old.filter(row => !rr.recipes.some(r => r.id === row.id)), ...rr.recipes] : rr.recipes); setRecipeCursor(rr.next_cursor); }
    if (!moreStations && !moreRecipes) { setStationId(''); setRecipeId(''); }
    setMessage('Choose the approved station and recipe for this kit.');
  }
  async function freshStation(): Promise<Station> {
    const value = await api<Station>('/stations/' + stationId);
    setStations(old => old.map(s => s.id === value.id ? value : s)); return value;
  }
  function adopt(value: Status, started: number, allowPass = false, capturedScene = scene.current) {
    const current = statusValue(value);
    if (current.id !== work.current) throw new Error('Inspection changed. Stop and refresh.');
    revision.current = current.state_version; setStatus(current);
    lease.current = allowPass && run.current && stream.current && scene.current === capturedScene && document.visibilityState === 'visible'
      && navigator.onLine && performance.now() - lastFrame.current < 750 && current.effective_state === 'PASSED_CURRENT'
      ? Math.min(started + current.remaining_lease_ms, performance.now() + current.remaining_lease_ms) : 0;
    if (['ACTION_REQUIRED', 'REVIEW_REQUIRED', 'CLOSED', 'INVALIDATED'].includes(current.effective_state)) { run.current = false; setRunning(false); }
  }
  async function attach(ident: string) {
    stop(); work.current = ident; setStatus(null); setContext(null); setFindings([]);
    decisionIntent.current = null; setDecisionPending(false); setDecisionNotice(''); setHumanCheck(false);
    const began = performance.now();
    const state = await api<Status>('/inspections/' + ident); adopt(state, began);
    const geometry = await api<Context>('/inspections/' + ident + '/capture-context');
    const checked = contextValue(geometry);
    if (checked.inspection_id !== ident) throw new Error('Capture geometry does not match this inspection.');
    contextUntil.current = began + checked.remaining_context_ms; setContext(checked); adopt(state, began);
    originalBudget.current = checked.original_capture_remaining_attempts ?? 0; setOriginalsRemaining(originalBudget.current);
    setMessage('Review expected contents and the camera explanation. Keep the same inspection through corrections.');
  }
  async function acquire() {
    if (!user) return;
    const ss = await freshStation();
    const result = await api<{ current: Station }>('/stations/' + ss.id + '/acquire', { user, method: 'POST', version: ss.state_version,
      body: { expected_epoch: ss.epoch, expected_owner_session_id: ss.owner_session_id, takeover_ack: takeover,
        reason: takeover ? reason : null, disposition: disposition || null } });
    setStations(old => old.map(s => s.id === ss.id ? result.current : s)); setTakeover(false); setMessage('Station acquired. Start a new kit or resume your existing inspection.');
  }
  async function startKit() {
    if (!user) return;
    const ss = await freshStation();
    const created = await api<{ inspection_id: string }>('/inspections', { user, method: 'POST', body: {
      station_id: ss.id, expected_version: ss.state_version, expected_epoch: ss.epoch, recipe_id: recipeId, kit_id: kit,
    } });
    await freshStation(); await attach(created.inspection_id);
  }
  async function startCamera() {
    if (!context || !work.current || !operator) return;
    stop(); setHumanCheck(false); const stamp = generation.current;
    if (performance.now() >= contextUntil.current || document.visibilityState !== 'visible' || !navigator.onLine) throw new Error('Refresh inspection context before starting the camera.');
    if (!navigator.mediaDevices?.getUserMedia || !video.current || typeof video.current.requestVideoFrameCallback !== 'function') throw new Error('Use a supported desktop browser with camera access.');
    controller.current = new AbortController();
    setMessage('Starting camera preview. Stop camera and checks cancels this attempt.');
    const live = await api<User>('/me', { signal: controller.current.signal });
    if (!Array.isArray(live.roles) || !live.roles.includes('operator') || live.session_id !== user?.session_id) throw new Error('Your operator session changed. Sign in again and ask the owner.');
    const checkedAt = performance.now();
    const geometry = contextValue(await api<Context>('/inspections/' + work.current + '/capture-context', { signal: controller.current.signal }));
    if (geometry.inspection_id !== work.current) throw new Error('Capture context changed. Stop and refresh status.');
    if (stamp !== generation.current || !mounted.current || document.visibilityState !== 'visible') return;
    contextUntil.current = checkedAt + geometry.remaining_context_ms; setContext(geometry);
    originalBudget.current = geometry.original_capture_remaining_attempts ?? 0; setOriginalsRemaining(originalBudget.current);
    let media: MediaStream;
    try { media = await requestCamera({ audio: false, video: { width: { ideal: geometry.frame_width }, height: { ideal: geometry.frame_height }, ...(device ? { deviceId: { exact: device } } : {}) } }, controller.current.signal); }
    catch (error) { if (stamp !== generation.current) return; throw new Error(error instanceof DOMException && error.name === 'NotAllowedError' ? 'Camera permission denied. Enable camera access for this site, then start preview explicitly.' : 'Camera unavailable. Check the selected device and ask the supervisor.'); }
    if (stamp !== generation.current || !mounted.current || document.visibilityState !== 'visible') { media.getTracks().forEach(track => track.stop()); return; }
    stream.current = media;
    media.getVideoTracks().forEach(track => { track.addEventListener('ended', () => { if (stamp === generation.current) stop('Camera ended. Recheck required.'); });
      track.addEventListener('mute', () => { if (stamp === generation.current) stop('Camera interrupted. Recheck required.'); }); });
    video.current!.srcObject = media;
    try {
      await startPlayback(video.current!, controller.current.signal); await nextFrame(video.current!, controller.current.signal);
      drawCapture(video.current!, canvas.current!, geometry); lastFrame.current = performance.now();
      setCameraOn(true); setMessage('Preview only: the full rectangle includes mat markers. No image has been uploaded.');
      setDevices((await navigator.mediaDevices.enumerateDevices()).filter(item => item.kind === 'videoinput'));
    } catch (error) { if (stamp !== generation.current) return; stop(); throw error; }
    void (async () => {
      try {
        while (stamp === generation.current && stream.current) {
          await nextFrame(video.current!, controller.current.signal);
          if (stamp !== generation.current) break;
          lastFrame.current = performance.now();
          const drawing = drawCapture(video.current!, canvas.current!, geometry);
          const current = drawing.getImageData(0, 0, geometry.frame_width, geometry.frame_height).data;
          const before = pixels.current;
          if (before && before.length === current.length && current.some((v, i) => i % 4 !== 3 && Math.abs(v - before[i]) > 12)) { scene.current++; lease.current = 0; repaint(v => v + 1); }
          pixels.current = current;
        }
      } catch (error) { if (stamp === generation.current) stop(explanation(error)); }
    })();
  }
  async function checkLoop() {
    if (!user || !context || !stream.current || !confirmed || run.current) return;
    const stamp = generation.current, ident = work.current; lease.current = 0;
    await api('/inspections/' + ident + '/prepare-capture', { user, method: 'POST', version: revision.current, body: {}, signal: controller.current.signal });
    if (stamp !== generation.current) return;
    run.current = true; setRunning(true); setMessage('Checking fresh observations. Manually double-check the entire kit before packing.');
    void (async () => {
      try {
        while (run.current && stamp === generation.current) {
          const cycle = performance.now();
          if (cycle >= contextUntil.current) throw new Error('Capture context expired. Refresh status and ask the owner if needed.');
          const retainThisFrame = originalChoice.current;
          originalChoice.current = false; setRetainOriginal(false);
          if (retainThisFrame && (context.original_capture_retention_allowed !== true || originalBudget.current < 1)) throw new Error('Original retention is unavailable. Refresh context or continue without it.');
          const permit = await api<{ permit_id: string; nonce: string | null; sequence: number; inspection_state_version: number; usable: boolean; retain_original_frame?: boolean }>('/inspections/' + ident + '/capture-permits', {
            user, method: 'POST', version: revision.current, body: { expected_epoch: selected!.epoch, ...(retainThisFrame ? { retain_original_frame: true } : {}) }, signal: controller.current.signal });
          if (retainThisFrame) {
            if (permit.retain_original_frame !== true) throw new Error('Original retention was not confirmed. Stop and refresh status.');
            originalBudget.current = Math.max(0, originalBudget.current - 1); setOriginalsRemaining(originalBudget.current);
          } else if (permit.retain_original_frame === true) throw new Error('Unexpected original retention. Stop and ask the owner.');
          if (stamp !== generation.current || !permit.usable || !permit.nonce) throw new Error('Capture permit is unavailable. Refresh status.');
          revision.current = permit.inspection_state_version;
          await nextFrame(video.current!, controller.current.signal);
          if (stamp !== generation.current) return;
          drawCapture(video.current!, canvas.current!, context); lastFrame.current = performance.now();
          const capturedScene = scene.current, image = await imageBlob(canvas.current!);
          if (stamp !== generation.current) return;
          const form = new FormData(); form.set('permit_id', permit.permit_id); form.set('nonce', permit.nonce); form.set('sequence', String(permit.sequence)); form.set('image', image, 'capture.jpg');
          const sent = performance.now();
          const result = await api<{ status: Status; measurement?: { findings: string[] } | null }>('/inspections/' + ident + '/observations', { user, method: 'POST', version: revision.current, body: form, signal: controller.current.signal });
          if (stamp !== generation.current) return;
          if (result.measurement) {
            const values = result.measurement.findings;
            if (!Array.isArray(values) || values.length !== context.constraints.length || values.some(v => !['SATISFIED','VIOLATED','UNOBSERVABLE'].includes(v))) throw new Error('Findings are incomplete. Ask for manual review.');
            setFindings(values);
          }
          adopt(result.status, sent, true, capturedScene);
          if (run.current) await new Promise(resolve => window.setTimeout(resolve, Math.max(0, 500 - (performance.now() - cycle))));
        }
      } catch (error) { if (stamp === generation.current) stop(explanation(error)); }
    })();
  }
  async function refresh() {
    if (!work.current) return;
    stop(); await freshStation(); await attach(work.current);
  }
  async function acknowledge() {
    setCorrectionOpen(false);
    if (!user || !status?.action) return;
    const began = performance.now();
    adopt(await api<Status>('/inspections/' + work.current + '/actions/' + status.action.id + '/complete', { user, method: 'POST', body: {}, version: revision.current }), began);
    setMessage('Acknowledgment recorded. Obtain fresh observations; it is not a pass.');
  }
  function checkedDecision(value: HumanDecision, inspection: string): HumanDecision {
    if (!value || value.inspection_id !== inspection || !/^[0-9a-f-]{36}$/.test(value.id) || !/^[0-9a-f]{64}$/.test(value.sha256)
      || !['rework', 'reject', 'cancelled', 'human_accepted'].includes(value.disposition) || typeof value.reason !== 'string'
      || value.reason.length < 1 || value.reason.length > 120 || typeof value.human_check_confirmed !== 'boolean'
      || (value.disposition === 'human_accepted' && !value.human_check_confirmed)
      || value.machine_approval !== false || value.independent_truth_verified !== false) throw new Error('Human decision readback is unrecognized. Ask the supervisor; no machine approval was granted.');
    return value;
  }
  async function recordDecision() {
    if (!user || !work.current || !selected) return;
    if (!decisionIntent.current) {
      if (!disposition || !reason.trim() || (disposition === 'human_accepted' && !humanCheck)) throw new Error('Choose your actual human decision, give a reason and confirm any complete manual check.');
      decisionIntent.current = { inspection: work.current, version: revision.current, key: crypto.randomUUID(),
        body: { expected_epoch: selected.epoch, disposition, reason, human_check_confirmed: humanCheck } };
      setDecisionPending(true);
    }
    const intent = decisionIntent.current;
    stop('Recording a separate human decision. Current camera approval cleared.');
    try {
      const result = await api<{ id: string; inspection_id: string; inspection_state_version: number; decision: HumanDecision }>(
        '/inspections/' + intent.inspection + '/dispositions', { user, method: 'POST', version: intent.version, idempotencyKey: intent.key, body: intent.body });
      const decision = checkedDecision(result.decision, intent.inspection);
      if (result.id !== decision.id || result.inspection_id !== intent.inspection || result.inspection_state_version !== intent.version + 1
        || decision.disposition !== intent.body.disposition || decision.reason !== intent.body.reason || decision.human_check_confirmed !== intent.body.human_check_confirmed
        || work.current !== intent.inspection) throw new Error('Human decision confirmation is unrecognized. Retry the unchanged request or ask the supervisor.');
      revision.current = Math.max(revision.current, result.inspection_state_version);
      setStatus(previous => previous ? { ...previous, state_version: Math.max(previous.state_version, result.inspection_state_version), remaining_lease_ms: 0 } : previous);
      setDecisionNotice('Recorded historical human decision: ' + decision.disposition.replaceAll('_', ' ') + '. Record ' + decision.id + '. Reason: ' + decision.reason);
      decisionIntent.current = null; setDecisionPending(false); setHumanCheck(false);
      setMessage('Human decision recorded separately. It grants no machine pass or shipment approval.');
    } catch (error) {
      if (error instanceof ApiError && error.status < 500) { decisionIntent.current = null; setDecisionPending(false); }
      else setDecisionNotice('Human decision outcome is unconfirmed. Retry the unchanged request. Reload or sign-out cannot undo a committed decision; read latest history before another write.');
      throw error;
    }
  }
  async function readDecision() {
    if (!work.current) return;
    const ident = work.current;
    const result = await api<{ inspection_id: string; decision: HumanDecision | null; historical: boolean; machine_approval: boolean; current_disposition: string | null }>('/inspections/' + ident + '/dispositions/latest');
    if (work.current !== ident || result.inspection_id !== ident || result.historical !== true || result.machine_approval !== false) throw new Error('Historical decision unavailable. Ask the supervisor.');
    const decision = result.decision === null ? null : checkedDecision(result.decision, ident);
    setDecisionNotice(decision ? 'Latest separately recorded historical decision: ' + decision.disposition.replaceAll('_', ' ') + '. Record ' + decision.id + '. Reason: ' + decision.reason
      : 'No separate human-decision record. Close or takeover decisions may still exist.');
    setMessage('Historical human handling only. Readback does not restore camera approval or undo an uncertain write.');
  }
  async function closeKit() {
    if (!user) return;
    stop(); const ss = await freshStation();
    const latest = statusValue(await api<Status>('/inspections/' + work.current)); revision.current = latest.state_version; setStatus(latest);
    await api('/inspections/' + work.current + '/close', { user, method: 'POST', version: revision.current, body: { expected_epoch: ss.epoch, reason, disposition: disposition || null } });
    work.current = ''; setStatus(null); setContext(null); setKit(''); await freshStation(); setMessage('Inspection closed. Its result is historical. Start a distinct kit when ready.');
  }
  async function release() {
    if (!user) return;
    stop(); const ss = await freshStation();
    await api('/stations/' + ss.id + '/release', { user, method: 'POST', version: ss.state_version, body: { expected_epoch: ss.epoch, disposition: disposition || null } });
    work.current = ''; setStatus(null); setContext(null); await freshStation(); setMessage('Station released; prior observations are historical.');
  }
  async function logout() {
    if (!user) return;
    stop();
    try { await api('/auth/logout', { user, method: 'POST' }); setUser(null); setStations([]); setRecipes([]); setContext(null); setStatus(null); work.current = ''; setUncertainLogout(false); setMessage('Signed out of ProofPack.'); }
    catch { setUncertainLogout(true); setMessage('Camera stopped. Server sign-out is unconfirmed. Retry sign-out or ask the owner to revoke your session.'); }
  }
  const currentPass = cameraOn && running && lease.current > performance.now();
  const stateText = currentPass ? 'Visible checks passed — current observation' : status?.effective_state === 'ACTION_REQUIRED' ? 'Action required' : status?.effective_state === 'REVIEW_REQUIRED' ? 'Review required — stop and ask the supervisor' : status?.effective_state === 'CLOSED' ? 'Closed / historical' : 'Recheck required — no current approval';

  const resultPanel = (status && <section className={'inspection-status ' + (currentPass ? 'current' : '')} aria-label="Inspection result"><h3>{stateText}</h3><p>Observation: {status.last_observed_at ? new Date(status.last_observed_at).toLocaleString() : 'No verified observation yet'}.</p>{currentPass && <p>Remaining current lease: {Math.max(0, Math.floor(lease.current - performance.now()))} ms. This does not authorize shipment.</p>}
          {findings.length > 0 && <><h4>Last observation findings</h4><p>Historical unless the observation is shown as current.</p><ul>{findings.map((finding, i) => <li key={i}>{context?.constraints[i]?.part_class_id.replaceAll('_', ' ')}: {finding.toLowerCase()}</li>)}</ul></>}
          {status.action && <><p>{status.action.message}</p>
            {status.action.correction_reference_available ? <><p>Numbered targets are available on the measured retained crop. They do not describe the live camera scene.</p>
              <button disabled={busy || running || decisionPending || !operator || status.effective_state !== 'ACTION_REQUIRED'} onClick={() => { stop('Camera stopped. Inspect the historical correction reference, make the correction and acknowledge; then start fresh capture.'); setCorrectionOpen(true); }}>Open measured correction reference (stops camera)</button>
            </> : <p>Correction area: the outlined retained work area. Part-specific localization is unavailable.</p>}
            <button disabled={busy || running || decisionPending || status.effective_state !== 'ACTION_REQUIRED'} onClick={() => void perform(acknowledge)}>Acknowledge correction completed</button>
            {correctionOpen && user && status.action.observation_id && status.action.correction_reference_available && <EvidencePanel key={[status.id, status.action.id, status.action.observation_id, status.action.kind].join(':')} user={user} seedInspection={status.id}
              correction={{ inspection_id: status.id, observation_id: status.action.observation_id, action_id: status.action.id, kind: status.action.kind }}/>}</>}
          <button disabled={busy || running} onClick={() => void perform(refresh)}>Refresh inspection status</button></section>);

  return <section className="operator" aria-labelledby="operator-title">
    <h2 id="operator-title" ref={title} tabIndex={-1}>Operator workspace</h2>
    <p role="status" aria-label="Workspace message">{message}</p>
    {!user && <a href="/api/v1/auth/login">Sign in with your invited account</a>}
    {user && <><div className="toolbar"><span>Signed in: {user.display_name} · {user.roles.join(', ')}</span><button disabled={busy} onClick={() => void perform(logout)}>{uncertainLogout ? 'Retry sign out' : 'Sign out'}</button></div>
      <button disabled={busy || uncertainLogout || decisionPending} onClick={() => { stop('Camera stopped for review. Any open inspection remains on the server.'); onWorkbench(); }}>Review and administration</button>
      {work.current && <button disabled={busy || uncertainLogout || decisionPending} onClick={() => { const id = work.current; stop('Capture stopped for historical evidence review.'); onEvidence(id); }}>Review latest retained evidence</button>}
      {operator && work.current && <button disabled={busy || uncertainLogout || decisionPending} onClick={() => { const id=work.current; stop('Capture stopped for designated review support. No request has been sent.'); onSupport(id); }}>Request support for this inspection</button>}
      {operator && <><button disabled={busy || cameraOn || !!work.current} onClick={() => void perform(() => loadLists())}>Load stations and recipes</button>
        <div className="form-grid"><label>Station<select value={stationId} disabled={busy || cameraOn || !!work.current} onChange={e => setStationId(e.target.value)}><option value="">Choose station</option>{stations.map(ss => <option key={ss.id} value={ss.id}>{ss.name}{ss.active_inspection_id ? ' · active inspection' : ''}</option>)}</select></label>
          <label>Approved recipe<select value={recipeId} disabled={busy || !!work.current} onChange={e => setRecipeId(e.target.value)}><option value="">Choose recipe</option>{recipes.map(rr => <option key={rr.id} value={rr.id}>{rr.name}</option>)}</select></label>
          <label>Opaque kit reference<input value={kit} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,63}" disabled={busy || !!work.current} onChange={e => setKit(e.target.value)} placeholder="No names or shipping details"/></label></div>
        <div className="toolbar">{stationCursor && <button disabled={busy || !!work.current} onClick={() => void perform(() => loadLists(true, false))}>More stations</button>}{recipeCursor && <button disabled={busy || !!work.current} onClick={() => void perform(() => loadLists(false, true))}>More recipes</button>}
          <button disabled={busy || !selected || !!work.current || (!!selected.owner_session_id && !selected.owned_by_current_session && (!takeover || !reason.trim()))} onClick={() => void perform(acquire)}>Acquire station</button>
          <button disabled={busy || !selected?.owned_by_current_session || !!selected.active_inspection_id || !recipeId || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(kit)} onClick={() => void perform(startKit)}>Start kit inspection</button>
          {selected?.owned_by_current_session && selected.active_inspection_id && !work.current && <button disabled={busy} onClick={() => void perform(() => attach(selected.active_inspection_id!))}>Resume my inspection</button>}
        </div>
        {selected?.owner_session_id && !selected.owned_by_current_session && <label className="check"><input type="checkbox" checked={takeover} onChange={e => setTakeover(e.target.checked)}/>I have arranged this station handoff. Takeover will fence prior work; provide a reason and any required disposition below.</label>}
        {context && <><h3>{context.recipe_name} · revision {context.recipe_revision}</h3><p>Scene origin: <strong>{context.data_origin}</strong> · correction method: fixed rules. Camera profile: {context.camera_label}. Synthetic/printable scenes do not qualify physical kits.</p>
          <ul>{context.constraints.map(item => <li key={item.constraint_id}>{item.part_class_id.replaceAll('_', ' ')}: expected {item.expected_count}</li>)}</ul>
          <p>Complete supervised practice with the owner before live use. Hidden properties and shipment decisions require another method. Keep faces and paperwork outside the entire preview.</p>
          <div className="camera-result-grid"><div className="capture-view" style={{ aspectRatio: `${context.frame_width}/${context.frame_height}` }}><video ref={video} muted playsInline aria-label="Exact transmitted capture rectangle"/><canvas ref={canvas} aria-hidden="true"/>{cameraOn && <svg viewBox="0 0 1 1" preserveAspectRatio="none" aria-hidden="true"><polygon points={context.work_polygon.map(point => point.join(',')).join(' ')} /></svg>}{!cameraOn && <span>Camera stopped. No capture preview.</span>}</div>
          {resultPanel}</div>
          <p>Whole preview: transmitted capture rectangle including mat markers. Outlined polygon: smaller retained work area. Preview alone uploads nothing.</p>
          {context.original_capture_retention_allowed === true && <><label className="check"><input type="checkbox" checked={retainOriginal} disabled={busy || running || !cameraOn || originalsRemaining < 1}
            onChange={event => { originalChoice.current = event.target.checked; setRetainOriginal(event.target.checked); }}/>Retain the next original transmitted image once for operational review</label>
            <p>Original attempts remaining: {originalsRemaining} of at most 3 per inspection. Issued attempts are not refunded after interruption or failure. The entire preview, including markers, is retained until purpose expiry or seven days, whichever is earlier. This permits no improvement use or publicity. Ordinary checks do not require originals.</p></>}
          <label>Camera<select value={device} disabled={busy || running} onChange={e => setDevice(e.target.value)}><option value="">Default camera</option>{devices.map(item => <option key={item.deviceId} value={item.deviceId}>{item.label || 'Available camera'}</option>)}</select></label>
          <div className="toolbar"><button disabled={busy || running || decisionPending} onClick={() => void perform(startCamera)}>{cameraOn ? 'Use selected camera' : 'Start camera preview'}</button><button onClick={() => stop('Camera stopped. Current approval cleared; inspection remains open.')}>Stop camera and checks</button></div>
          <label className="check"><input type="checkbox" checked={confirmed} disabled={!cameraOn || running} onChange={e => setConfirmed(e.target.checked)}/>I checked the full transmitted area and will manually verify the entire kit before packing.</label>
          <button disabled={busy || decisionPending || !cameraOn || !confirmed || running || ['ACTION_REQUIRED','REVIEW_REQUIRED','CLOSED'].includes(status?.effective_state ?? '')} onClick={() => void perform(checkLoop)}>Start fresh checks</button>
        </>}
        {!context && resultPanel}
        {!!work.current && !status && <button disabled={busy} onClick={() => void perform(refresh)}>Refresh inspection status</button>}
        <div className="form-grid"><label>Human disposition (separate from machine result)<select value={disposition} disabled={busy || running || decisionPending} onChange={e => { setDisposition(e.target.value); setHumanCheck(false); }}><option value="">No disposition selected</option><option value="rework">Rework</option><option value="reject">Reject</option><option value="cancelled">Cancelled</option><option value="human_accepted">Accepted after human check</option></select></label><label>Handoff / close reason<input value={reason} maxLength={120} disabled={busy || running || decisionPending} onChange={e => { setReason(e.target.value); setHumanCheck(false); }} placeholder="No personal or shipping information"/></label></div>
        {work.current && <section aria-label="Separate human decision"><h3>Manual handling and historical decision</h3>
          <p>This records your decision separately. It never clears a machine finding, resets corrective requests or authorizes shipment. Corrections append another record.</p>
          <label className="check"><input type="checkbox" checked={humanCheck} disabled={busy || running || decisionPending} onChange={event => setHumanCheck(event.target.checked)}/>I completed a manual check of the entire kit. This is my declaration, not independent proof.</label>
          <div className="toolbar"><button disabled={busy || running || (!decisionPending && (!disposition || !reason.trim() || (disposition === 'human_accepted' && !humanCheck)))} onClick={() => void perform(recordDecision)}>{decisionPending ? 'Retry unchanged human decision' : 'Record separate human decision'}</button>
            <button disabled={busy || running} onClick={() => void perform(readDecision)}>Read latest human decision</button></div>
          {decisionNotice && <p role="status" aria-label="Human decision history">{decisionNotice}</p>}
          {decisionPending && <p>Keep this inspection open and retry the frozen request. Leaving or signing out does not cancel a server commit. After a reload, read latest history and ask the supervisor if the outcome remains uncertain.</p>}
        </section>}
        <div className="toolbar"><button disabled={busy || running || decisionPending || !work.current || !reason.trim()} onClick={() => void perform(closeKit)}>Close kit inspection</button><button disabled={busy || running || decisionPending || !selected?.owned_by_current_session} onClick={() => void perform(release)}>Release station</button></div>
        <p>For unresolved checks, account problems or unavailable support, stop and ask the owner or supervisor. Use the ordinary manual check. Starting a replacement inspection does not resolve uncertainty.</p>
      </>}
    </>}
  </section>;
}
