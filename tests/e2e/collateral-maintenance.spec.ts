// Actual rendered bundle with synthetic API interception; no store/provider/human proof.
import {test,expect,type Page} from '@playwright/test';
const I='00000000-0000-0000-0000-000000000001',B='00000000-0000-0000-0000-000000000002',R='00000000-0000-0000-0000-000000000003';
const base='/privacy/metadata-requests';
function request(){return {id:R,state_version:1,status:'held',scope_sha256:'a'.repeat(64),inspection_ids:[I],selector_policy:'read-only-family-selection-v3',created_at_ms:100,original_owner_session:true,current_hold:true,gate_version:2,gate_epoch:1,gate_phase:'HELD',control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,drain_status:'empty',can_cancel:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};}
async function setup(page:Page,available:boolean|null=true){
 const posts:{path:string;body:unknown}[]=[],errors:string[]=[];const control={fault:'',delay:0};page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/v1/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname.replace('/api/v1','');const send=(json:unknown,status=200)=>route.fulfill({status,json});
  if(req.method()==='GET'){
   if(path==='/me')return send({id:B,session_id:'synthetic-session',display_name:'Synthetic owner',roles:['owner'],csrf_token:'x'.repeat(43)});
   if(path===base+'/context')return send({gate_version:2,gate_phase:'HELD',gate_epoch:1,control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,max_inspections:10,can_create:false,can_confirm_cleanup:false,erasure_complete:false,...(available===null?{}:{collateral_review_available:available})});
   if(path===base+'/'+R)return send(request());return send({code:'DENIED'},403);
  }
  expect(req.headers()['x-csrf-token']).toBe('x'.repeat(43));posts.push({path,body:req.postDataJSON()});
  if(path===base+'/'+R+'/collateral-scope-proposal'){
   if(control.delay)await new Promise(resolve=>setTimeout(resolve,control.delay));
   if(['denied','held'].includes(control.fault))return send({code:control.fault==='denied'?'ACCESS_DENIED':'METADATA_REVIEW_HELD'},control.fault==='denied'?403:503);
   const v:any={id:R,scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:1,proposal_policy:'whole-artifact-collateral-proposal-v1',original_inspection_ids:[I],proposed_inspection_ids:[I,B],additional_inspection_ids:[B],implicated_records:2,unresolved_records:1,total_records:4,historical:true,read_only:true,scope_changed:false,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
   if(control.fault==='extra')v.objects=['private/key'];if(control.fault==='version')v.gate_version++;
   if(control.fault==='difference')v.additional_inspection_ids=[];if(control.fault==='authority')v.can_confirm_cleanup=true;
   if(control.fault==='empty'){v.proposed_inspection_ids=[I];v.additional_inspection_ids=[];}
   return send(v);
  }
  if(path===base+'/'+R+'/review')return send({id:R,scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:1,accounting_policy:'conservative-family-accounting-v1',counts:{AFFECTED:1,SHARED:0,CONTEXT:1,UNRELATED:1,UNRESOLVED:1},total_records:4,historical:true,read_only:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false});
  return send({code:'UNEXPECTED_MUTATION'},403);
 });
 await page.goto('/#maintenance');await page.getByRole('button',{name:'Read owner status',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Owner snapshot',exact:true})).toBeVisible();
 await page.getByLabel('Metadata request ID',{exact:true}).fill(R);await page.getByRole('button',{name:'Read request status',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();return {posts,control,errors};
}
const proposal=(page:Page)=>page.getByRole('button',{name:'Read collateral scope proposal',exact:true});
const result=(page:Page)=>page.getByRole('heading',{name:'Historical collateral scope proposal',exact:true});
test('explicit proposal binds exact status, explains collateral and persists no proposal',async({page})=>{
 const f=await setup(page);await expect(result(page)).toHaveCount(0);await proposal(page).click();await expect(result(page)).toBeVisible();
 await expect(page.getByText('Additional inspection references: '+B+'.',{exact:true})).toBeVisible();
 await expect(page.getByText(/Other inspections may contain unrelated business records/)).toBeVisible();
 expect(f.posts).toEqual([{path:base+'/'+R+'/collateral-scope-proposal',body:{expected_request_version:1,expected_gate_version:2,expected_control_version:1}}]);
 await expect(proposal(page)).toBeDisabled();expect(await page.evaluate(()=>JSON.stringify({...sessionStorage,...localStorage}))).not.toContain('proposed_inspection_ids');expect(f.errors).toEqual([]);
});
test('count read cannot reenable a second proposal without fresh status',async({page})=>{
 const f=await setup(page);await proposal(page).click();await expect(result(page)).toBeVisible();await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
 await expect(result(page)).toHaveCount(0);await expect(page.getByRole('table')).toBeVisible();await expect(proposal(page)).toBeDisabled();
 await page.getByRole('button',{name:'Read request status',exact:true}).click();await expect(proposal(page)).toBeEnabled();await proposal(page).click();await expect(result(page)).toBeVisible();
 expect(f.posts.filter(p=>p.path.endsWith('/collateral-scope-proposal'))).toHaveLength(2);expect(f.errors).toEqual([]);
});
for(const available of [false,null])test('unconfigured context hides proposal '+String(available),async({page})=>{
 const f=await setup(page,available);await expect(proposal(page)).toHaveCount(0);await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toBeEnabled();expect(f.posts).toEqual([]);
});
for(const fault of ['denied','held','extra','version','difference','authority'])test('withholds '+fault+' without retry or private output',async({page})=>{
 const f=await setup(page);f.control.fault=fault;await proposal(page).click();await expect(page.getByRole('status')).toContainText('no erasure, fulfillment or inspection resumption is confirmed');
 await expect(result(page)).toHaveCount(0);await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toHaveCount(0);await expect(page.getByText('private/key',{exact:false})).toHaveCount(0);expect(f.posts).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('empty additions retain unknown duties and no cleanup claim',async({page})=>{
 const f=await setup(page);f.control.fault='empty';await proposal(page).click();await expect(result(page)).toBeVisible();
 await expect(page.getByText('Additional inspection references: none.',{exact:true})).toBeVisible();await expect(page.getByText(/Unknown obligations remain pending even when no additional inspections/)).toBeVisible();expect(f.posts).toHaveLength(1);
});
for(const mode of ['hidden','offline','selection'])test('withdraws historical proposal on '+mode,async({page})=>{
 const f=await setup(page);await proposal(page).click();await expect(result(page)).toBeVisible();
 if(mode==='selection')await page.getByLabel('Metadata request ID',{exact:true}).fill(I);
 else await page.evaluate(mode=>{if(mode==='offline')window.dispatchEvent(new Event('offline'));else{Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'hidden'});document.dispatchEvent(new Event('visibilitychange'));}},mode);
 await expect(result(page)).toHaveCount(0);expect(f.posts).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('late proposal cannot restore private view after offline interruption',async({page})=>{
 const f=await setup(page);f.control.delay=200;await proposal(page).click();await expect.poll(()=>f.posts.length).toBe(1);
 await page.evaluate(()=>window.dispatchEvent(new Event('offline')));await page.waitForTimeout(300);await expect(result(page)).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Read request status',exact:true})).toHaveCount(0);expect(f.posts).toHaveLength(1);expect(f.errors).toEqual([]);
});
