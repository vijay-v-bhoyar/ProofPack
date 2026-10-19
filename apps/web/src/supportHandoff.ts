import { identifier, positive, sha, uuid } from './workbench';

export type SupportRequest = {
  sender_user_id:string; recipient_user_id:string; reason_code:string; station_id:string; station_epoch:number;
  station_name:string; kit_reference:string; source_inspection_revision:number; post_request_inspection_revision:number;
  source_observation_id:string|null; previous_accepted_handoff_id:string|null; created_at_ms:number; expires_at_ms:number;
};
export type SupportDetail = { id:string; inspection_id:string; state_version:number; inspection_state_version:number;
  request_sha256:string; recorded_status:string; effective_status:string; pending_eligible:boolean; acknowledged:boolean;
  current_assignment:boolean; historical:true; machine_approval:false; capture_transferred:false; remaining_validity_ms:number;
  request:SupportRequest; decision:{kind:string;actor_user_id:string;at_ms:number}|null };
export type InboxItem = {id:string;inspection_id:string;state_version:number;request_sha256:string;recorded_status:string;
  reason_code:string;station_name:string;kit_reference:string;created_at_ms:number;expires_at_ms:number;historical:true;machine_approval:false};
export type SupportInbox = { requests:InboxItem[];next_cursor:string|null;historical:true;machine_approval:false;
  remaining_validity_ms:number;scope:string };
const states=['pending','accepted','declined','cancelled','superseded'];
const reasons=['unresolved_inspection','capture_interrupted','support_needed'];
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
function exact(v:unknown, fields:string[]):boolean {return object(v)&&Object.keys(v).length===fields.length&&fields.every(k=>Object.hasOwn(v,k));}
const ident=(v:unknown)=>typeof v==='string'&&uuid.test(v);
const hash=(v:unknown)=>typeof v==='string'&&sha.test(v);
const optionalId=(v:unknown)=>v===null||ident(v);
const flag=(v:unknown)=>typeof v==='boolean';
const name=(v:unknown)=>typeof v==='string'&&v.trim()===v&&v.length>0&&v.length<=80&&!/[\x00-\x1f\x7f]/.test(v);
const kit=(v:unknown)=>typeof v==='string'&&identifier.test(v);
const validity=(v:unknown)=>positive(v)&&v<=5000;
function period(v:Record<string,unknown>) {return positive(v.created_at_ms)&&positive(v.expires_at_ms)&&v.expires_at_ms>v.created_at_ms&&v.expires_at_ms-v.created_at_ms<=3600000;}
function invalid():never {throw new Error('Support response is unavailable or does not match the selected work. Stop and use manual checking.');}
export function supportDetail(value:unknown):SupportDetail {
  const fields=['id','inspection_id','state_version','inspection_state_version','request_sha256','recorded_status','effective_status','pending_eligible','acknowledged','current_assignment','historical','machine_approval','capture_transferred','remaining_validity_ms','request','decision'];
  if(!exact(value,fields))return invalid();const v=value as unknown as SupportDetail,r=v.request;
  if(!ident(v.id)||!ident(v.inspection_id)||!positive(v.inspection_state_version)||!hash(v.request_sha256)||!states.includes(v.recorded_status)
    ||v.state_version!==(v.recorded_status==='pending'?1:2)||!flag(v.pending_eligible)||!flag(v.acknowledged)||!flag(v.current_assignment)
    ||v.historical!==true||v.machine_approval!==false||v.capture_transferred!==false||!validity(v.remaining_validity_ms)
    ||v.acknowledged!==(v.recorded_status==='accepted')||(v.current_assignment&&!v.acknowledged)
    ||v.pending_eligible!==(v.recorded_status==='pending'&&v.effective_status==='pending')
    ||!(v.recorded_status==='pending'?['pending','held','expired'].includes(v.effective_status):v.effective_status===v.recorded_status))return invalid();
  if(!exact(r,['sender_user_id','recipient_user_id','reason_code','station_id','station_epoch','station_name','kit_reference','source_inspection_revision','post_request_inspection_revision','source_observation_id','previous_accepted_handoff_id','created_at_ms','expires_at_ms'])
    ||!ident(r.sender_user_id)||!ident(r.recipient_user_id)||r.sender_user_id===r.recipient_user_id||!ident(r.station_id)
    ||!Number.isSafeInteger(r.station_epoch)||r.station_epoch<0||!name(r.station_name)||!kit(r.kit_reference)||!reasons.includes(r.reason_code)
    ||!positive(r.source_inspection_revision)||!positive(r.post_request_inspection_revision)||r.post_request_inspection_revision!==r.source_inspection_revision+1
    ||v.inspection_state_version<r.post_request_inspection_revision||!optionalId(r.source_observation_id)||!optionalId(r.previous_accepted_handoff_id)
    ||!period(r as unknown as Record<string,unknown>))return invalid();
  if(v.recorded_status==='pending'){if(v.decision!==null)return invalid();}
  else if(!exact(v.decision,['kind','actor_user_id','at_ms'])||v.decision?.kind!==v.recorded_status||!ident(v.decision?.actor_user_id)
    ||!positive(v.decision?.at_ms)||v.decision!.at_ms<r.created_at_ms
    ||(['accepted','declined'].includes(v.recorded_status)&&v.decision!.actor_user_id!==r.recipient_user_id)
    ||(v.recorded_status==='cancelled'&&v.decision!.actor_user_id!==r.sender_user_id))return invalid();
  return v;
}
export function supportNone(value:unknown,inspection:string):boolean {
  if(!exact(value,['inspection_id','handoff','historical','machine_approval','capture_transferred','remaining_validity_ms']))return false;
  const v=value as Record<string,unknown>;
  return v.inspection_id===inspection&&v.handoff===null&&v.historical===true&&v.machine_approval===false&&v.capture_transferred===false&&validity(v.remaining_validity_ms);
}
export function supportInbox(value:unknown):SupportInbox {
  if(!exact(value,['requests','next_cursor','historical','machine_approval','remaining_validity_ms','scope']))return invalid();
  const v=value as unknown as SupportInbox;
  if(v.historical!==true||v.machine_approval!==false||!validity(v.remaining_validity_ms)||!optionalId(v.next_cursor)
    ||v.scope!=='recorded recipient references only; read current request details before any response'||!Array.isArray(v.requests)||v.requests.length>20)return invalid();
  const seen=new Set<string>();
  for(const r of v.requests){
    if(!exact(r,['id','inspection_id','state_version','request_sha256','recorded_status','reason_code','station_name','kit_reference','created_at_ms','expires_at_ms','historical','machine_approval'])
      ||!ident(r.id)||!ident(r.inspection_id)||!hash(r.request_sha256)||!states.includes(r.recorded_status)
      ||r.state_version!==(r.recorded_status==='pending'?1:2)||!reasons.includes(r.reason_code)||!name(r.station_name)||!kit(r.kit_reference)
      ||r.historical!==true||r.machine_approval!==false||!period(r as unknown as Record<string,unknown>)||seen.has(r.id))return invalid();
    seen.add(r.id);
  }
  return v;
}
