import { useEffect, useRef, useState } from 'react';
import { statusValue, type Station, type Status, type User } from './api';
import { useReviewDeadline, useTasks, useUnconfirmed, uuid } from './workbench';
import { supportDetail, supportInbox, supportNone, type SupportDetail, type SupportInbox } from './supportHandoff';

type Prepared={inspection:string;version:number;epoch:number;station:string;stationName:string};
type Intent={path:string;version:number;key:string;body:Record<string,unknown>;kind:'request'|'response'|'cancel';inspection:string;id:string|null};
export function SupportPanel({user,seedInspection=''}:{user:User;seedInspection?:string}) {
  const {busy,message,call,perform,say,fresh}=useTasks('Stop capture before requesting help. No notification is sent.');
  const [inspection,setInspection]=useState(seedInspection),[requestId,setRequestId]=useState(''),[recipient,setRecipient]=useState('');
  const [reason,setReason]=useState('support_needed'),[stopAck,setStopAck]=useState(false),[responseAck,setResponseAck]=useState(false);
  const [detail,setDetail]=useState<SupportDetail|null>(null),[inbox,setInbox]=useState<SupportInbox|null>(null),[prepared,setPrepared]=useState<Prepared|null>(null);
  const [pending,setPending]=useState(false),[receipt,setReceipt]=useState('');
  const intent=useRef<Intent|null>(null),expiry=useReviewDeadline(),heading=useRef<HTMLHeadingElement>(null);
  const reviewUntil=useRef(0);
  const liveReview=()=>expiry.valid&&reviewUntil.current>performance.now()&&document.visibilityState==='visible'&&navigator.onLine;
  useUnconfirmed(pending);
  const operator=user.roles.includes('operator'),reviewer=user.roles.includes('reviewer');
  function clear(){reviewUntil.current=0;expiry.clear();setPrepared(null);setDetail(null);setInbox(null);setStopAck(false);setResponseAck(false);setReceipt('');}
  useEffect(()=>{
    heading.current?.focus();
    const interrupted=()=>{clear();say('Review interrupted. Capture must stay stopped; refresh before acting. Any unconfirmed intent is retained.');};
    const hidden=()=>{if(document.visibilityState!=='visible')interrupted();};
    window.addEventListener('offline',interrupted);window.addEventListener('pagehide',interrupted);document.addEventListener('visibilitychange',hidden);
    return()=>{window.removeEventListener('offline',interrupted);window.removeEventListener('pagehide',interrupted);document.removeEventListener('visibilitychange',hidden);};
  },[]);
  async function load(id=inspection,request=requestId){
    if(intent.current)throw new Error('Retry the original unconfirmed intent before another read or operation.');
    clear();const token=expiry.token(),began=performance.now();await fresh(user);
    const value=await call<unknown>('/inspections/'+id+'/handoffs/'+(request||'latest'));
    if(!request&&supportNone(value,id)){say('No recorded support request. An owning operator can prepare a request; nobody has accepted this work.');return;}
    const result=supportDetail(value);
    if(result.inspection_id!==id||(request&&result.id!==request))throw new Error('Support response does not match the selected request.');
    expiry.bound(began,result.remaining_validity_ms,5000,token);reviewUntil.current=began+result.remaining_validity_ms;setInspection(id);setRequestId(result.id);setDetail(result);
    say('Historical support context loaded. Review current eligibility before any separate decision.');
  }
  async function loadInbox(cursor:string|null=null){
    if(intent.current)throw new Error('Retry the original unconfirmed intent first.');
    clear();const token=expiry.token(),began=performance.now();await fresh(user,'reviewer');
    const result=supportInbox(await call<unknown>('/handoffs/inbox'+(cursor?'?cursor='+encodeURIComponent(cursor):'')));
    if(cursor&&result.next_cursor===cursor)throw new Error('Inbox cursor did not advance. Stop and ask the owner.');
    expiry.bound(began,result.remaining_validity_ms,5000,token);reviewUntil.current=began+result.remaining_validity_ms;setInbox(result);say('Recorded recipient references only. Read exact current details before responding.');
  }
  async function prepare(){
    if(intent.current)throw new Error('Retry the original unconfirmed intent first.');
    clear();const token=expiry.token(),began=performance.now();await fresh(user,'operator');
    const work=statusValue(await call<Status>('/inspections/'+inspection));
    if(work.id!==inspection||!uuid.test(work.station_id)||work.effective_state==='CLOSED')throw new Error('An open same inspection is required.');
    const station=await call<Station>('/stations/'+work.station_id);
    if(station.id!==work.station_id||station.active_inspection_id!==inspection||station.owned_by_current_session!==true
      ||station.owner_session_id!==user.session_id||!Number.isSafeInteger(station.epoch)||station.epoch<0
      ||typeof station.name!=='string'||!station.name.trim()||station.name.length>80)throw new Error('The selected inspection is not owned by this operator session.');
    expiry.bound(began,5000,5000,token);reviewUntil.current=began+5000;setPrepared({inspection,version:work.state_version,epoch:station.epoch,station:station.id,stationName:station.name});
    say('Stopped-inspection request prepared. Check the station and inspection, then separately acknowledge and submit. Kit context is confirmed in the returned record.');
  }
  async function send(next?:Intent){
    const chosen=intent.current??next;
    if(!chosen)throw new Error('No original intent is available.');
    // Revalidate before freezing a new intent; an old intent always retains its exact bytes.
    try { await fresh(user,chosen.kind==='response'?'reviewer':undefined); }
    catch(error) { clear();throw error; }
    if(!intent.current){if(!liveReview())throw new Error('Review expired. Refresh before submitting.');intent.current=chosen;setPending(true);}
    clear();
    const result=supportDetail(await call<unknown>(chosen.path,{user,method:'POST',version:chosen.version,idempotencyKey:chosen.key,body:chosen.body}));
    if(result.inspection_id!==chosen.inspection||(chosen.id&&result.id!==chosen.id))throw new Error('Unconfirmed support write: reply does not match the original work. Retry unchanged intent.');
    if(chosen.kind==='request'){
      if(result.request.sender_user_id!==user.id||result.request.recipient_user_id!==chosen.body.recipient_user_id
        ||result.request.reason_code!==chosen.body.reason_code||result.request.station_epoch!==chosen.body.expected_epoch
        ||result.request.source_inspection_revision!==chosen.version)throw new Error('Unconfirmed request: returned source does not match the frozen intent.');
    }else if(result.request_sha256!==chosen.body.request_sha256||result.recorded_status!==(chosen.kind==='cancel'?'cancelled':chosen.body.decision)
      ||result.decision?.actor_user_id!==user.id)throw new Error('Unconfirmed response: decision differs from the frozen intent.');
    intent.current=null;setPending(false);setInspection(result.inspection_id);setRequestId(result.id);setDetail(result);
    // A mutation receipt is historical only. A separate current detail read is required for another action.
    setReceipt(chosen.kind==='request'?'Support request recorded. No recipient acceptance is implied.':'Recorded acknowledgment: '+result.recorded_status+'. No capture or kit approval transferred.');
    say('Original intent confirmed. Read current details before another action.');
  }
  async function requestSupport(){
    const source=prepared??(detail?.current_assignment&&detail.request.recipient_user_id===user.id&&reviewer?
      {inspection:detail.inspection_id,version:detail.inspection_state_version,epoch:detail.request.station_epoch}:null);
    if(!source||!expiry.valid||!stopAck||!uuid.test(recipient)||recipient===user.id)throw new Error('Review the stopped work and choose another authorized reviewer before requesting support.');
    await send({path:'/inspections/'+source.inspection+'/handoffs',version:source.version,key:crypto.randomUUID(),inspection:source.inspection,id:null,kind:'request',
      body:{recipient_user_id:recipient,expected_epoch:source.epoch,reason_code:reason,stop_acknowledged:true}});
  }
  async function respond(decision:'accepted'|'declined'){
    if(!detail||!expiry.valid||!detail.pending_eligible||detail.request.recipient_user_id!==user.id||!responseAck)throw new Error('Read the exact eligible request and acknowledge the response limits.');
    await send({path:'/inspections/'+detail.inspection_id+'/handoffs/'+detail.id+'/respond',version:detail.state_version,key:crypto.randomUUID(),inspection:detail.inspection_id,id:detail.id,kind:'response',
      body:{decision,request_sha256:detail.request_sha256,expected_inspection_version:detail.inspection_state_version,acknowledge_no_capture_transfer:true}});
  }
  async function cancel(){
    if(!detail||!expiry.valid||detail.recorded_status!=='pending'||detail.request.sender_user_id!==user.id)throw new Error('Read your original pending request before canceling.');
    await send({path:'/inspections/'+detail.inspection_id+'/handoffs/'+detail.id+'/cancel',version:detail.state_version,key:crypto.randomUUID(),inspection:detail.inspection_id,id:detail.id,kind:'cancel',body:{request_sha256:detail.request_sha256}});
  }
  const canRespond=reviewer&&detail?.request.recipient_user_id===user.id&&detail.pending_eligible&&expiry.valid;
  const source=prepared||((reviewer&&detail?.current_assignment&&detail.request.recipient_user_id===user.id)?detail:null);
  return <section aria-labelledby="support-title"><h3 id="support-title" ref={heading} tabIndex={-1}>Support handoff</h3>
    <p role="status">{message}</p><p>Camera capture must stay stopped. Acceptance assigns review responsibility only; it never approves a kit or transfers camera ownership. No notification or staffed response is promised.</p>
    <fieldset disabled={busy||pending}><legend>Read stopped work</legend>
      <label>Support inspection ID<input value={inspection} maxLength={36} onChange={e=>{clear();setInspection(e.target.value);setRequestId('');}}/></label>
      <label>Support request ID (optional)<input value={requestId} maxLength={36} onChange={e=>{clear();setRequestId(e.target.value);}}/></label>
      <button disabled={!uuid.test(inspection)||!!requestId&&!uuid.test(requestId)} onClick={()=>void perform(()=>load())}>Read support details</button>
      {reviewer&&<button onClick={()=>void perform(()=>loadInbox())}>Read my support inbox</button>}
    </fieldset>
    {inbox&&<div><p>Recorded recipient history in UUID key order. A pending entry does not establish response eligibility.</p>
      {!expiry.valid&&<p>Inbox review expired or interrupted. Refresh before choosing a request.</p>}
      {inbox.requests.length===0&&<p>No recorded recipient references on this page.</p>}
      <ul>{inbox.requests.map(r=><li key={r.id}>{r.station_name} · {r.kit_reference} · recorded {r.recorded_status}
        <button disabled={busy||pending||!expiry.valid} onClick={()=>void perform(()=>load(r.inspection_id,r.id))}>Read support request {r.id}</button></li>)}</ul>
      {inbox.next_cursor&&<button disabled={busy||pending||!expiry.valid} onClick={()=>void perform(()=>loadInbox(inbox.next_cursor))}>Next support inbox page</button>}
    </div>}
    {detail&&<div><p>Inspection {detail.inspection_id} · request {detail.id}. {detail.request.station_name} · kit {detail.request.kit_reference}.</p>
      <p>Recorded status: {detail.recorded_status}. Effective at read: {detail.effective_status}. {detail.current_assignment?'Assignment was current at this read.':'No current assignment established by this record.'}</p>
      <p>Historical acknowledgment: {detail.acknowledged?'accepted':'not accepted'}. {expiry.valid?'Review window is bounded; the server rechecks all authority.':'Review expired or unconfirmed. Read current details before acting.'}</p>
      <fieldset disabled={busy||pending}><legend>Separate reviewer response</legend>
        <label><input type="checkbox" checked={responseAck} disabled={!canRespond} onChange={e=>setResponseAck(e.target.checked)}/>I acknowledge that this response transfers no capture or kit approval.</label>
        <button disabled={!canRespond||!responseAck} onClick={()=>void perform(()=>respond('accepted'))}>Accept review responsibility</button>
        <button disabled={!canRespond||!responseAck} onClick={()=>void perform(()=>respond('declined'))}>Decline review responsibility</button>
        <button disabled={!expiry.valid||detail.recorded_status!=='pending'||detail.request.sender_user_id!==user.id} onClick={()=>void perform(cancel)}>Cancel my pending support request</button>
      </fieldset>
    </div>}
    <fieldset disabled={busy||pending}><legend>Request support or a separately accepted successor</legend>
      <p>Choose another authorized reviewer through the agreed private business channel. Fill the recipient/reason first, then prepare or read the exact work. No member directory is exposed.</p>
      <label>Intended reviewer ID<input value={recipient} maxLength={36} onChange={e=>{clear();setRecipient(e.target.value);}}/></label>
      <label>Support reason<select value={reason} onChange={e=>{clear();setReason(e.target.value);}}><option value="support_needed">Support needed</option><option value="unresolved_inspection">Unresolved inspection</option><option value="capture_interrupted">Capture interrupted</option></select></label>
      {operator&&<button disabled={!uuid.test(inspection)} onClick={()=>void perform(prepare)}>Prepare stopped inspection request</button>}
      {prepared&&<p>Prepared inspection {prepared.inspection} · {prepared.stationName} · version {prepared.version}, epoch {prepared.epoch}. Confirm the physical kit; no new observation was taken.</p>}
      {prepared&&!expiry.valid&&<p>Stopped-inspection review expired. Prepare again before requesting.</p>}
      <label><input type="checkbox" checked={stopAck} disabled={!source||!expiry.valid} onChange={e=>setStopAck(e.target.checked)}/>I stopped capture and reliance on any previous result.</label>
      <button disabled={!source||!expiry.valid||!stopAck||!uuid.test(recipient)||recipient===user.id} onClick={()=>void perform(requestSupport)}>Request designated review support</button>
    </fieldset>
    {receipt&&<p role="status" aria-label="Support receipt">{receipt}</p>}
    {pending&&<><p>The original server outcome is unconfirmed. Other reads and writes are frozen. Retry the exact original intent here, or use the acknowledged-leave decision to investigate it. Leaving does not cancel it.</p>
      <button disabled={busy} onClick={()=>void perform(()=>send())}>Retry unchanged support intent</button></>}
    <p>If no reviewer accepts, use ordinary manual checking or suspend app-assisted work. Decline, cancel and expiry never refund attempts; a successor must separately accept. Historical records never revive capture or a current pass.</p>
    <p>Historical exports require permission for every included support record and complete source history. Complete metadata/inbox cleanup and offboarding remain unfinished; TTL is not an erasure receipt.</p>
  </section>;
}
