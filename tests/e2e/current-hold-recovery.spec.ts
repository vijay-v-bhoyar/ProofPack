// Built UI with intercepted synthetic API. No provider/store/human outcome proof.
import {test,expect,type Page} from '@playwright/test';
const I='00000000-0000-0000-0000-000000000001',U='00000000-0000-0000-0000-000000000002',R='00000000-0000-0000-0000-000000000003';
const base='/privacy/metadata-requests',storage='proofpack.metadata.original-intent.v1';
const view=()=>({id:R,state_version:1,status:'held',scope_sha256:'a'.repeat(64),inspection_ids:[I],selector_policy:'read-only-family-selection-v3',created_at_ms:100,original_owner_session:false,current_hold:true,gate_version:2,gate_epoch:1,gate_phase:'HELD',control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,drain_status:'empty',can_cancel:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false});
const intent={schema_version:1,user_id:U,key:'00000000-0000-0000-0000-000000000004',kind:'create',path:base,body:{inspection_ids:[I],expected_gate_version:1,expected_control_version:1,interruption_acknowledged:true}};
async function setup(page:Page,{open=false,pending=false,fault='',busy=0,delay=false,roles=['owner']}={}) {
  const errors:string[]=[],writes:string[]=[],reads:string[]=[];
  const state={waiting:false,finished:false,busy,release:()=>{}};
  page.on('pageerror',error=>errors.push(error.message));
  if(pending)await page.addInitScript(({key,value})=>sessionStorage.setItem(key,value),{key:storage,value:JSON.stringify(intent)});
  await page.route('**/api/v1/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname.replace('/api/v1','');
    const send=(value:unknown,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
    if(request.method()!=='GET'){writes.push(path);return send({code:'DENIED'},403);}
    reads.push(path);
    if(path==='/me')return send({id:U,session_id:'synthetic-session',display_name:'Synthetic owner',roles,csrf_token:'x'.repeat(43)});
    if(path===base+'/context')return send({gate_version:2,gate_phase:open?'OPEN':'HELD',gate_epoch:1,control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,max_inspections:10,can_create:open,can_confirm_cleanup:false,erasure_complete:false});
    if(path===base+'/current'){
      state.waiting=true;
      if(delay)await new Promise<void>(resolve=>{state.release=resolve;});
      if(state.busy>0){state.busy--;return send({code:'METADATA_MAINTENANCE'},503);}
      if(fault==='denied')return send({code:'ACCESS_DENIED'},403);
      const result={status:open?'open':'held',request:open?null:view(),unknown_writes_reconciled:false,inspection_resumption_authorized:false,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:fault==='fulfilled'};
      await send(result);state.finished=true;return;
    }
    return send({code:'DENIED'},403);
  });
  await page.goto('/#maintenance');
  await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  return {errors,writes,reads,state};
}

test('owner recovers a lost current ID with pointer and keeps the result read only',async({page})=>{
  const f=await setup(page);await expect(page.getByLabel('Metadata request ID',{exact:true})).toHaveValue('');
  await page.getByRole('button',{name:'Recover current held request',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();
  await expect(page.getByLabel('Metadata request ID',{exact:true})).toHaveValue(R);
  await expect(page.getByRole('status')).toContainText('Preserve any uncertain original intent');
  await expect(page.getByRole('button',{name:'Cancel this request before cleanup',exact:true})).toBeDisabled();
  await expect(page.getByRole('heading',{name:'Owner snapshot',exact:true})).toHaveCount(0);
  expect(f.reads.filter(path=>path===base+'/current')).toHaveLength(1);expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});

for(const open of [false,true])test('current '+(open?'absence':'hold')+' preserves an uncertain original intent byte for byte',async({page})=>{
  const f=await setup(page,{open,pending:true});const before=await page.evaluate(key=>sessionStorage.getItem(key),storage);
  await page.getByRole('button',{name:'Recover current held request',exact:true}).click();
  await expect(page.getByRole('status')).toContainText(open?'No current held request at this read':'Current held request recovered');
  await expect(page.getByRole('heading',{name:'Original outcome unconfirmed',exact:true})).toBeVisible();
  expect(await page.evaluate(key=>sessionStorage.getItem(key),storage)).toBe(before);
  expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});

for(const fault of ['fulfilled','denied'])test('withholds '+fault+' recovery response without losing the original retry',async({page})=>{
  const f=await setup(page,{pending:true,fault});const before=await page.evaluate(key=>sessionStorage.getItem(key),storage);
  await page.getByRole('button',{name:'Recover current held request',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('no erasure, fulfillment or inspection resumption is confirmed');
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toHaveCount(0);
  expect(await page.evaluate(key=>sessionStorage.getItem(key),storage)).toBe(before);expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});

test('bounded transient current-read recovery never sends a write',async({page})=>{
  const f=await setup(page,{busy:1});await page.getByRole('button',{name:'Recover current held request',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();
  expect(f.reads.filter(path=>path===base+'/current')).toHaveLength(2);expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});

test('keyboard recovery works at narrow width without authorizing cancellation',async({page})=>{
  await page.setViewportSize({width:320,height:900});const f=await setup(page);
  await page.getByRole('button',{name:'Recover current held request',exact:true}).focus();await page.keyboard.press('Enter');
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
  expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});

test('offline abort rejects late current data and preserves pending duties',async({page})=>{
  const f=await setup(page,{pending:true,delay:true});const before=await page.evaluate(key=>sessionStorage.getItem(key),storage);
  await page.getByRole('button',{name:'Recover current held request',exact:true}).click();
  await expect.poll(()=>f.state.waiting).toBe(true);
  await page.evaluate(()=>window.dispatchEvent(new Event('offline')));
  await expect(page.getByRole('status')).toContainText('Connection unavailable');f.state.release();
  await expect.poll(()=>f.state.finished).toBe(true);
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toHaveCount(0);
  expect(await page.evaluate(key=>sessionStorage.getItem(key),storage)).toBe(before);expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});

test('non-owner receives no recovery affordance or request',async({page})=>{
  const f=await setup(page,{roles:['operator']});
  await expect(page.getByRole('status')).toContainText('Only a currently authorized owner');
  await expect(page.getByRole('button',{name:'Recover current held request',exact:true})).toHaveCount(0);
  expect(f.reads).not.toContain(base+'/current');expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});
