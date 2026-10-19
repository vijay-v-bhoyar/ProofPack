import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { OperatorWorkspace } from './OperatorWorkspace';
import { InvitationPanel } from './InvitationPanel';
import { MemberWorkbench } from './MemberWorkbench';
import { MetadataPanel } from './MetadataPanel';
import { metadataStorage } from './metadataRequests';

function maintenanceEntry() { try { return window.location.hash === '#maintenance' || sessionStorage.getItem('proofpack.maintenance.entry') === 'v1' || sessionStorage.getItem(metadataStorage) !== null; } catch { return window.location.hash === '#maintenance'; } }

type Connection = 'checking' | 'unavailable' | 'not_ready' | 'ready';

function App() {
  const [connection, setConnection] = useState<Connection>('checking');
  const [attempt, setAttempt] = useState(0);
  const [workspace, setWorkspace] = useState(maintenanceEntry);
  const [view, setView] = useState(() => maintenanceEntry() ? 'maintenance' : 'operator');
  const [evidenceInspection, setEvidenceInspection] = useState('');
  const [supportSeed, setSupportSeed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timer = window.setTimeout(() => controller.abort(), 5000);
    setConnection('checking');
    void fetch('/health/ready', { credentials: 'same-origin', cache: 'no-store', signal: controller.signal })
      .then(async response => {
        const body: unknown = await response.json();
        const status = typeof body === 'object' && body !== null && 'status' in body ? body.status : null;
        if (active) setConnection(response.ok && status === 'ready' ? 'ready' : 'not_ready');
      })
      .catch(() => { if (active) setConnection('unavailable'); })
      .finally(() => { window.clearTimeout(timer); });
    return () => { active = false; window.clearTimeout(timer); controller.abort(); };
  }, [attempt]);

  return <>
    <a className="skip" href="#main">Skip to main content</a>
    <header><a href="/" className="brand" aria-label="ProofPack home"><span className="mark" aria-hidden="true">P</span>ProofPack</a><span className="context">Invited workspace</span></header>
    <main id="main" tabIndex={-1} className={workspace ? 'workspace-active' : undefined}>
      <div className="eyebrow">Visible kit checks · human decisions</div>
      {!workspace && <>
      <h1>A clear check.<br/>An honest next step.</h1>
      <p className="intro">Check configured visible parts against an approved recipe. When the view is uncertain, resolve it or ask for a manual review.</p>
      <section className="workspace" aria-labelledby="workspace-title">
        <div><span className="eyebrow">Your workspace</span><h2 id="workspace-title">Before you begin</h2></div>
        <div className="status" role="status" aria-live="polite">
          <strong>{connection === 'checking' ? 'Checking availability…' : connection === 'unavailable' ? 'Connection unavailable' : connection === 'ready' ? 'Service available' : 'Inspections are not available yet'}</strong>
          <p>{connection === 'ready' ? 'Use your owner’s approved invitation to continue. No camera capture has started.' : 'Continue with your ordinary manual check. Ask the workspace owner before starting a supervised session.'}</p>
        </div>
        <button type="button" disabled={connection === 'checking'} onClick={() => setAttempt(value => value + 1)}>Check again <span aria-hidden="true">↗</span></button>
      </section>
      </>}
      {workspace && <h1 className="compact-title">{view === 'maintenance' ? 'Maintenance requests' : view === 'operator' ? 'Kit inspections' : view === 'invitation' ? 'Invitation review' : 'Workspace review'}</h1>}
      {!workspace && <><button onClick={() => setWorkspace(true)}>Open invited workspace</button><button onClick={() => { window.location.hash = 'maintenance'; setView('maintenance'); setWorkspace(true); }}>Owner maintenance</button></>}
      {!workspace && <details><summary>First owner setup</summary><p>Use this only if the deployment administrator has approved your exact account as the initial owner. Sign in with that account and complete fresh MFA. Setup creates owner access only; inspections remain disabled. Invited team members should use the invited workspace.</p><a href="/api/v1/auth/setup-owner">Set up the approved first owner</a><p>If sign-in stops or confirmation is lost, start a fresh setup sign-in with the same approved account. Do not change accounts or approval settings to retry. Contact the deployment administrator if access remains unavailable.</p></details>}
      {workspace && view === 'maintenance' && <MetadataPanel onBack={() => { try { sessionStorage.removeItem('proofpack.maintenance.entry'); } catch { /* Navigation is not authority. */ } history.replaceState(null, '', window.location.pathname); setView('operator'); setWorkspace(false); }}/>}
      {workspace && view === 'operator' && <OperatorWorkspace onWorkbench={() => { setSupportSeed(false); setEvidenceInspection(''); setView('workbench'); }} onInvitation={() => setView('invitation')} onEvidence={id => { setSupportSeed(false); setEvidenceInspection(id); setView('workbench'); }} onSupport={id => { setSupportSeed(true); setEvidenceInspection(id); setView('workbench'); }}/>} 
      {workspace && view === 'invitation' && <InvitationPanel onBack={() => setView('operator')}/>}
      {workspace && view === 'workbench' && <MemberWorkbench seedInspection={evidenceInspection} seedSupport={supportSeed} onBack={() => { setSupportSeed(false); setEvidenceInspection(''); setView('operator'); }}/>}
      <section aria-labelledby="limits-title"><h2 id="limits-title">Know what a result means</h2><div className="cards">
        <article><span className="number">01</span><h3>Visible, configured parts</h3><p>A qualified recipe defines what can be checked. Hidden contents, material grade and thread specifications need another method.</p></article>
        <article><span className="number">02</span><h3>A current observation</h3><p>Moving parts or losing the live view makes an old result historical. A screenshot or export cannot confirm the current kit.</p></article>
        <article><span className="number">03</span><h3>You remain in control</h3><p>Stop when unsure and ask for help. Manually verify the entire kit before packing during the supervised beta. ProofPack does not authorize shipment.</p></article>
      </div></section>
      <details><summary>Camera, privacy and participation</summary><p>Camera access must start only after your explicit action in an authorized session. Check the displayed capture area and keep faces and paperwork outside it. Optional improvement-data and publicity use are separate choices, off by default. Obtain the owner’s finalized notice, support contact and withdrawal route before participating.</p></details>
    </main><footer>ProofPack <span>Configured observations. Accountable decisions.</span></footer>
  </>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>);
