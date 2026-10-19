// Pure client contract checks; no browser, service or human evidence.
import {test,expect} from '@playwright/test';
import {metadataContext} from '../../apps/web/src/metadataRequests';
import {ownerCollateralScope} from '../../apps/web/src/ownerCollateralScope';
const A='00000000-0000-0000-0000-000000000001',B='00000000-0000-0000-0000-000000000002',R='00000000-0000-0000-0000-000000000003';
const binding={id:R,scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:1};
function proposal():any{return {...binding,proposal_policy:'whole-artifact-collateral-proposal-v1',original_inspection_ids:[A],proposed_inspection_ids:[A,B],additional_inspection_ids:[B],implicated_records:2,unresolved_records:1,total_records:4,historical:true,read_only:true,scope_changed:false,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};}
function context():any{return {gate_version:2,gate_phase:'HELD',gate_epoch:1,control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,max_inspections:10,can_create:false,can_confirm_cleanup:false,erasure_complete:false};}
test('closed legacy and boolean opt-in contexts remain distinct',()=>{
  expect(metadataContext(context())).not.toHaveProperty('collateral_review_available');
  for(const enabled of [false,true])expect(metadataContext({...context(),collateral_review_available:enabled}).collateral_review_available).toBe(enabled);
});
for(const extra of [{collateral_review_available:'true'},{collateral_review_available:1},{collateral_review_available:null},{collateral_review_available:true,private_key:'secret'}])test('invalid context '+JSON.stringify(extra),()=>expect(()=>metadataContext({...context(),...extra})).toThrow());
test('exact historical scopes and unknowns accepted without authority',()=>{
  const v=proposal();expect(ownerCollateralScope(v,binding,[A],10)).toEqual(v);
  v.proposed_inspection_ids=[A];v.additional_inspection_ids=[];expect(ownerCollateralScope(v,binding,[A],10).unresolved_records).toBe(1);
});
const faults:Record<string,(v:any)=>void>={
  'private extra':v=>v.objects=['private/key'],'wrong request':v=>v.id=A,'wrong digest':v=>v.scope_sha256='b'.repeat(64),
  'wrong version':v=>v.gate_version++,'policy':v=>v.proposal_policy='other','original binding':v=>v.original_inspection_ids=[B],
  'missing original':v=>v.proposed_inspection_ids=[B],'duplicate':v=>v.proposed_inspection_ids=[A,A,B],'unsorted':v=>v.proposed_inspection_ids=[B,A],
  'extra difference':v=>v.additional_inspection_ids=[A,B],'missing difference':v=>v.additional_inspection_ids=[],
  'invalid id':v=>v.additional_inspection_ids=['private/key'],'bool count':v=>v.implicated_records=true,
  'negative':v=>v.unresolved_records=-1,'fraction':v=>v.total_records=4.5,'unsafe':v=>v.total_records=2**53,
  'sum':v=>v.total_records=2,'overflow sum':v=>{v.implicated_records=Number.MAX_SAFE_INTEGER;v.unresolved_records=1;v.total_records=Number.MAX_SAFE_INTEGER;},
  'historical':v=>v.historical=false,'read_only':v=>v.read_only=false,'scope mutation':v=>v.scope_changed=true,
  'cleanup':v=>v.can_confirm_cleanup=true,'erasure':v=>v.erasure_complete=true,'fulfilled':v=>v.request_fulfilled=true,
};
for(const [name,change] of Object.entries(faults))test('proposal rejects '+name,()=>{const v=proposal();change(v);expect(()=>ownerCollateralScope(v,binding,[A],10)).toThrow();});
test('caller bindings and capacity are also strict',()=>{
  for(const max of [0,1,65,1.5,NaN])expect(()=>ownerCollateralScope(proposal(),binding,[A],max)).toThrow();
  for(const original of [[],[A,A],[B],[B,A]])expect(()=>ownerCollateralScope(proposal(),binding,original,10)).toThrow();
  expect(()=>ownerCollateralScope(proposal(),{...binding,request_version:NaN},[A],10)).toThrow();
});
