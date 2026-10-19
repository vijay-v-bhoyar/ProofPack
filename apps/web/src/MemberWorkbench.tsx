import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from 'react';
import type { User } from './api';
import { member, useTasks, WorkbenchBusy, WorkbenchUnconfirmed } from './workbench';
import { AccountsPanel } from './AccountsPanel';
import { RuntimePanel, TransferPanel } from './AuthorityPanels';
import { RecipePanel } from './RecipePanel';
import { ReferencePanel } from './ReferencePanel';
import { CalibrationPanel } from './CalibrationPanel';
import { LabelPanel } from './LabelPanel';
import { EvidencePanel } from './EvidencePanel';
import { ErasurePanel } from './ErasurePanel';
import { ExportPanel } from './ExportPanel';
import { ImprovementPanel } from './ImprovementPanel';
import { DatasetPanel } from './DatasetPanel';
import { PolicyPanel } from './PolicyPanel';
import { EvaluationPanel } from './EvaluationPanel';
import { PreparationPanel } from './PreparationPanel';
import { QualificationPanel } from './QualificationPanel';
import { ActivationPanel } from './ActivationPanel';
import { ApprovedPolicyPanel } from './ApprovedPolicyPanel';
import { SupportPanel } from './SupportPanel';

export function MemberWorkbench({ onBack, seedInspection = '', seedSupport = false }: { onBack: () => void; seedInspection?: string; seedSupport?: boolean }) {
  const { busy, message, call, perform, say } = useTasks('Loading your current account…');
  const [user, setUser] = useState<User | null>(null), [panel, setPanel] = useState('handoff'), [transferId, setTransferId] = useState(''), [uncertain, setUncertain] = useState(false);
  const [panelBusy, setPanelBusy] = useState(false);
  const [calibrationSeed, setCalibrationSeed] = useState('');
  const [preparationSeed, setPreparationSeed] = useState(''), [qualificationSeed, setQualificationSeed] = useState(''), [activationSeed, setActivationSeed] = useState('');
  const unresolved = useRef(new Set<symbol>()), trigger = useRef<HTMLElement | null>(null), decision = useRef<HTMLDivElement>(null);
  const [unresolvedCount, setUnresolvedCount] = useState(0), [leave, setLeave] = useState<{ run: () => void } | null>(null), [leaveAck, setLeaveAck] = useState(false);
  const reportUnconfirmed = useCallback((token: symbol, value: boolean) => {
    const before = unresolved.current.size;
    if (value) unresolved.current.add(token); else unresolved.current.delete(token);
    if (before !== unresolved.current.size) setUnresolvedCount(unresolved.current.size);
  }, []);
  function requestLeave(run: () => void) {
    if (!unresolved.current.size) { run(); return; }
    trigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setLeaveAck(false); setLeave({ run });
  }
  function requestPanel(next: string) { if (next !== panel) requestLeave(() => setPanel(next)); }
  function stay() {
    setLeave(null); setLeaveAck(false);
    requestAnimationFrame(() => { if (trigger.current?.isConnected) trigger.current.focus(); });
  }
  function decisionKey(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') { event.preventDefault(); stay(); }
    if (event.key === 'Tab') {
      const items = [...(decision.current?.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled])') ?? [])];
      if (!items.length) return;
      const index = items.indexOf(document.activeElement as HTMLElement);
      event.preventDefault(); items[index < 0 ? event.shiftKey ? items.length - 1 : 0 : (index + (event.shiftKey ? -1 : 1) + items.length) % items.length].focus();
    }
  }
  useEffect(() => { if (leave) decision.current?.focus(); }, [leave]);

  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    let active = true; heading.current?.focus();
    void call<User>('/me').then(value => {
      const current = member(value);
      if (active) { setUser(current); setPanel(seedSupport && (current.roles.includes('operator') || current.roles.includes('reviewer')) ? 'support' : seedInspection ? 'evidence' : current.roles.includes('owner') ? 'accounts' : current.roles.includes('reviewer') ? 'recipes' : 'handoff'); say('Your explicit grants determine the available actions.'); }
    }).catch(error => { if (active) say(error instanceof Error ? error.message : 'Account unavailable.'); });
    return () => { active = false; };
  }, []);
  const ended = () => { setUser(null); setTransferId(''); setUncertain(false); setLeave(null); say('Account authority changed. Sign in afresh before continuing.' + (unresolved.current.size ? ' Any unconfirmed server operation must be investigated before another intent.' : '')); };
  async function logout() {
    if (!user) return;
    setUncertain(true);
    try { await call('/auth/logout', { user, method: 'POST' }); setUser(null); setTransferId(''); setUncertain(false); say('Signed out of ProofPack.'); }
    catch { say('Server sign-out is unconfirmed. Retry sign-out or ask the owner to revoke this session.'); }
  }
  const owner = !!user?.roles.includes('owner'), reviewer = !!user?.roles.includes('reviewer');
  return <section className="operator workbench" aria-labelledby="workbench-title"><h2 id="workbench-title" ref={heading} tabIndex={-1}>Review and administration</h2><p role="status">{message}</p>
    <p>Leaving inspections stops camera capture. Any open inspection stays on the server; return to its station and resume the same kit.</p>
    {user && <><div className="toolbar"><span>{user.display_name} · {user.roles.join(', ')}</span><button disabled={busy || panelBusy || !!leave} onClick={() => requestLeave(() => void perform(logout))}>{uncertain ? 'Retry sign out' : 'Sign out'}</button></div>
      {!uncertain && <WorkbenchBusy.Provider value={setPanelBusy}><WorkbenchUnconfirmed.Provider value={reportUnconfirmed}><nav className="toolbar" aria-label="Workbench sections">
        <button disabled={panelBusy || !!leave} aria-pressed={panel === 'evidence'} onClick={() => requestPanel('evidence')}>Retained evidence</button>
        {(reviewer || user.roles.includes('operator')) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'support'} onClick={() => requestPanel('support')}>Support handoff</button>}
        {owner && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'accounts'} onClick={() => requestPanel('accounts')}>Accounts</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'recipes'} onClick={() => requestPanel('recipes')}>Recipes and qualification</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'references'} onClick={() => requestPanel('references')}>Reference media</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'calibration'} onClick={() => requestPanel('calibration')}>Camera calibration</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'labels'} onClick={() => requestPanel('labels')}>Outcome labels</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'improvement'} onClick={() => requestPanel('improvement')}>Optional improvement permissions</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'datasets'} onClick={() => requestPanel('datasets')}>Dataset manifests</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'policies'} onClick={() => requestPanel('policies')}>Policy candidates</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'evaluations'} onClick={() => requestPanel('evaluations')}>Historical comparisons</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'preparations'} onClick={() => requestPanel('preparations')}>Qualification preparation</button>}
        {(owner || reviewer) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'qualifications'} onClick={() => requestPanel('qualifications')}>Policy qualification</button>}
        {owner && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'activations'} onClick={() => requestPanel('activations')}>Policy activation</button>}
        {owner && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'runtime'} onClick={() => requestPanel('runtime')}>Runtime controls</button>}
        {owner && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'cleanup'} onClick={() => requestPanel('cleanup')}>Selected asset cleanup</button>}
        {(reviewer || user.roles.includes('operator')) && <button disabled={panelBusy || !!leave} aria-pressed={panel === 'exports'} onClick={() => requestPanel('exports')}>Historical exports</button>}
        <button disabled={panelBusy || !!leave} aria-pressed={panel === 'handoff'} onClick={() => requestPanel('handoff')}>Ownership handoff</button>
        <button disabled={panelBusy || !!leave} aria-pressed={panel === 'approved-policy'} onClick={() => requestPanel('approved-policy')}>Approved policy</button>
      </nav>
        {panel === 'evidence' && <EvidencePanel user={user} seedInspection={seedInspection}/>}
        {(reviewer || user.roles.includes('operator')) && panel === 'support' && <SupportPanel user={user} seedInspection={seedInspection}/>}
        {panel === 'approved-policy' && <ApprovedPolicyPanel user={user}/>}
        {owner && panel === 'accounts' && <AccountsPanel user={user} onSessionEnded={ended} onTransfer={id => setTransferId(id)}/>}
        {(owner || reviewer) && panel === 'recipes' && <RecipePanel user={user}/>}
        {(owner || reviewer) && panel === 'references' && <ReferencePanel user={user} onEnroll={id => requestLeave(() => { setCalibrationSeed(id); setPanel('calibration'); })}/>}
        {(owner || reviewer) && panel === 'calibration' && <CalibrationPanel user={user} seedReference={calibrationSeed}/>}
        {(owner || reviewer) && panel === 'labels' && <LabelPanel user={user}/>}
        {(owner || reviewer) && panel === 'improvement' && <ImprovementPanel user={user}/>}
        {(owner || reviewer) && panel === 'datasets' && <DatasetPanel user={user}/>}
        {(owner || reviewer) && panel === 'policies' && <PolicyPanel user={user}/>}
        {(owner || reviewer) && panel === 'evaluations' && <EvaluationPanel user={user} onPrepare={id => requestLeave(() => { setPreparationSeed(id); setPanel('preparations'); })}/>}
        {(owner || reviewer) && panel === 'preparations' && <PreparationPanel user={user} seedEvaluation={preparationSeed} onQualify={id => requestLeave(() => { setQualificationSeed(id); setPanel('qualifications'); })}/>}
        {(owner || reviewer) && panel === 'qualifications' && <QualificationPanel user={user} seedPreparation={qualificationSeed} onActivate={id => requestLeave(() => { setActivationSeed(id); setPanel('activations'); })}/>}
        {owner && panel === 'activations' && <ActivationPanel user={user} seedQualification={activationSeed}/>}
        {owner && panel === 'runtime' && <RuntimePanel user={user}/>}
        {owner && panel === 'cleanup' && <ErasurePanel user={user}/>}
        {(reviewer || user.roles.includes('operator')) && panel === 'exports' && <ExportPanel user={user}/>}
        {panel === 'handoff' && <TransferPanel user={user} transferId={transferId} onSessionEnded={ended}/>}
        {transferId && panel !== 'handoff' && <p>Ownership handoff ID: {transferId}. Open Ownership handoff to review. No delivery or acceptance has occurred.</p>}
      </WorkbenchUnconfirmed.Provider></WorkbenchBusy.Provider>}
    </>}
    <div className="toolbar">{!busy && !panelBusy && <a href="/api/v1/auth/login?mfa=required" onClick={event => { if (unresolved.current.size) { event.preventDefault(); requestLeave(() => window.location.assign('/api/v1/auth/login?mfa=required')); } }}>Sign in with recent MFA</a>}{!user && <a href="/api/v1/auth/login">Sign in with your invited account</a>}<button disabled={busy || panelBusy || !!leave} onClick={() => requestLeave(onBack)}>Return to inspections</button></div>
    {leave && <div className="workbench-guard-backdrop"><div className="workbench-guard" role="alertdialog" aria-modal="true" aria-labelledby="leave-title" aria-describedby="leave-explanation" ref={decision} tabIndex={-1} onKeyDown={decisionKey}>
      <h3 id="leave-title">Leave unconfirmed work?</h3><p id="leave-explanation">An operation may already exist on the server. Leaving discards local retry details; it does not cancel, undo or determine the outcome. Keep working here to retry the exact original request. Investigate the original records with the owner before a separate intent.</p>
      <p>{unresolvedCount} unresolved local request scope(s). No new write will be sent by this decision.</p>
      <button onClick={stay}>Keep working here</button>
      <label><input type="checkbox" checked={leaveAck} onChange={event => setLeaveAck(event.target.checked)}/>I understand only local retry details will be discarded and the server outcome must still be investigated.</label>
      <button disabled={!leaveAck} onClick={() => { if (leaveAck) { const chosen = leave.run; setLeave(null); setLeaveAck(false); chosen(); } }}>Leave and investigate</button>
    </div></div>}
  </section>;
}
