// Pure TypeScript unit checks using the existing runner; no browser or service fixture.
import {test,expect} from '@playwright/test';
import {supportDetail,supportInbox,supportNone} from '../../apps/web/src/supportHandoff';
const A='10000000-0000-4000-8000-000000000001',B='10000000-0000-4000-8000-000000000002';
function detail():any{return {id:A,inspection_id:B,state_version:1,inspection_state_version:3,request_sha256:'a'.repeat(64),recorded_status:'pending',effective_status:'pending',pending_eligible:true,
  acknowledged:false,current_assignment:false,historical:true,machine_approval:false,capture_transferred:false,remaining_validity_ms:5000,
  request:{sender_user_id:A,recipient_user_id:B,reason_code:'support_needed',station_id:A,station_epoch:0,station_name:'Station',kit_reference:'kit-1',source_inspection_revision:1,
    post_request_inspection_revision:2,source_observation_id:null,previous_accepted_handoff_id:null,created_at_ms:1000,expires_at_ms:3601000},decision:null};}
function inbox():any{return {requests:[{id:A,inspection_id:B,state_version:1,request_sha256:'a'.repeat(64),recorded_status:'pending',reason_code:'support_needed',station_name:'Station',kit_reference:'kit-1',
  created_at_ms:1000,expires_at_ms:3601000,historical:true,machine_approval:false}],next_cursor:null,historical:true,machine_approval:false,remaining_validity_ms:5000,
  scope:'recorded recipient references only; read current request details before any response'};}
test('accepts exact pending, held and accepted historical records with separate eligibility',()=>{
  const d=detail();expect(supportDetail(d)).toEqual(d);d.effective_status='held';d.pending_eligible=false;expect(supportDetail(d).pending_eligible).toBe(false);
  d.recorded_status=d.effective_status='accepted';d.state_version=2;d.acknowledged=true;d.current_assignment=true;d.decision={kind:'accepted',actor_user_id:B,at_ms:2000};expect(supportDetail(d).acknowledged).toBe(true);
});
const changes:Record<string,(d:any)=>void>={
  'private extra field':d=>d.cookie='secret','unbounded validity':d=>d.remaining_validity_ms=5001,'no validity':d=>d.remaining_validity_ms=0,
  'fractional version':d=>d.inspection_state_version=1.5,'invalid digest':d=>d.request_sha256='x','string eligibility':d=>d.pending_eligible='true',
  'ineligible current flag':d=>d.current_assignment=true,'wrong post revision':d=>d.request.post_request_inspection_revision=9,
  'same sender recipient':d=>d.request.sender_user_id=B,'invalid station epoch':d=>d.request.station_epoch=-1,
  'unbounded name':d=>d.request.station_name='x'.repeat(81),'invalid kit':d=>d.request.kit_reference='private address',
  'overlong lifetime':d=>d.request.expires_at_ms++,'invalid source id':d=>d.request.source_observation_id='x',
  'machine approval':d=>d.machine_approval=true,'capture transfer':d=>d.capture_transferred=true,
  'decision on pending':d=>d.decision={kind:'accepted',actor_user_id:B,at_ms:2000},'missing field':d=>delete d.request.previous_accepted_handoff_id,
};
for(const [name,change]of Object.entries(changes))test('detail rejects '+name,()=>{const d=detail();change(d);expect(()=>supportDetail(d)).toThrow('Support response is unavailable');});
test('an accepted decision must bind the designated reviewer and recorded status',()=>{
  const d=detail();Object.assign(d,{recorded_status:'accepted',effective_status:'accepted',state_version:2,acknowledged:true,pending_eligible:false,decision:{kind:'accepted',actor_user_id:A,at_ms:2000}});
  expect(()=>supportDetail(d)).toThrow();d.decision.actor_user_id=B;expect(supportDetail(d).acknowledged).toBe(true);d.decision.kind='declined';expect(()=>supportDetail(d)).toThrow();
});
test('accepts bounded historical inbox and exact no-request read without authority',()=>{
  expect(supportInbox(inbox()).requests).toHaveLength(1);
  const none={inspection_id:A,handoff:null,historical:true,machine_approval:false,capture_transferred:false,remaining_validity_ms:5000};
  expect(supportNone(none,A)).toBe(true);expect(supportNone(none,B)).toBe(false);expect(supportNone({...none,token:'private'},A)).toBe(false);
});
const inboxChanges:Record<string,(d:any)=>void>={
  'duplicate requests':d=>d.requests.push({...d.requests[0]}),'21 requests':d=>d.requests=Array.from({length:21},(_,i)=>({...d.requests[0],id:`10000000-0000-4000-8000-${String(i).padStart(12,'0')}`})),
  'foreign cursor':d=>d.next_cursor='member-email','capability claim':d=>d.requests[0].pending_eligible=true,
  'renewed lifetime':d=>d.requests[0].expires_at_ms++,'invalid scope':d=>d.scope='eligible for acceptance',
  'current approval':d=>d.machine_approval=true,'unknown status':d=>d.requests[0].recorded_status='eligible',
};
for(const [name,change]of Object.entries(inboxChanges))test('inbox rejects '+name,()=>{const d=inbox();change(d);expect(()=>supportInbox(d)).toThrow();});
