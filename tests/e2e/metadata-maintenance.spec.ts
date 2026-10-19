// Rendered candidate with synthetic intercepted API state; no provider, store or human proof.
import { test, expect, type Page } from '@playwright/test';
const I='00000000-0000-0000-0000-000000000001',U='00000000-0000-0000-0000-000000000002',R='00000000-0000-0000-0000-000000000003';
const base='/privacy/metadata-requests';
function result(enabled=false) { return {id:R,state_version:1,status:'held',scope_sha256:'a'.repeat(64),inspection_ids:[I],selector_policy:'read-only-family-selection-v3',created_at_ms:100,original_owner_session:true,current_hold:true,gate_version:2,gate_epoch:1,gate_phase:'HELD',control_version:1,inspection_enabled:enabled,active_count:0,foreign_active:false,drain_status:enabled?'blocked_runtime':'empty',can_cancel:!enabled,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false}; }
async function setup(page:Page,roles=['owner'],contextBusy=0) {
  const errors:string[]=[], writes:{path:string;key:string;body:Record<string,unknown>}[]=[], reads:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  const state={phase:'OPEN',version:1,control:1,enabled:false,record:null as ReturnType<typeof result>|null,drop:false,fault:'',contextBusy,contextDelay:0,createDelay:0};
  await page.route('**/api/v1/**',async route=>{
    const req=route.request(),path=new URL(req.url()).pathname.replace('/api/v1','');
    const send=(body:unknown,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
    if(req.method()==='GET') {
      reads.push(path);
      if(path==='/me')return send({id:U,session_id:'synthetic-session',display_name:'Synthetic owner',roles,csrf_token:'x'.repeat(43)});
      if(path===base+'/context') {
        if(state.contextDelay)await new Promise(resolve=>setTimeout(resolve,state.contextDelay));
        if(state.contextBusy>0){state.contextBusy--;return send({code:'METADATA_MAINTENANCE'},503);}
        if(state.fault==='mfa')return send({code:'ACCESS_DENIED'},403);
        return send({gate_version:state.version,gate_phase:state.phase,gate_epoch:state.phase==='OPEN'&&state.record?2:1,control_version:state.control,inspection_enabled:state.enabled,active_count:0,foreign_active:false,max_inspections:10,can_create:state.phase==='OPEN'&&!state.enabled,can_confirm_cleanup:false,erasure_complete:false});
      }
      if(path===base+'/'+R&&state.record)return send(state.record);
      return send({code:'DENIED'},403);
    }
    expect(req.headers()['x-csrf-token']).toBe('x'.repeat(43));
    const body=req.postDataJSON() as Record<string,unknown>,key=req.headers()['idempotency-key'];
    writes.push({path,key,body});
    if(path===base) {
      const replay=state.record!==null;
      if(!replay){state.phase='HELD';state.version=2;state.record=result();}
      if(state.drop){state.drop=false;return route.abort('failed');}
      if(state.createDelay)await new Promise(resolve=>setTimeout(resolve,state.createDelay));
      const response={...state.record,replayed:replay,original_operation:'held'};
      if(state.fault==='erased')response.erasure_complete=true;
      if(state.fault==='fulfilled')response.request_fulfilled=true;
      if(state.fault==='scope')response.inspection_ids=[U];
      return send(response,201);
    }
    if(path===base+'/'+R+'/cancel'&&state.record){state.record={...state.record,status:'cancelled',state_version:2,current_hold:false,gate_phase:'OPEN',gate_epoch:2,gate_version:3,control_version:2,inspection_enabled:state.enabled,drain_status:'not_current',can_cancel:false};state.phase='OPEN';state.version=3;state.control=2;return send({...state.record,replayed:false,original_operation:'cancelled'});}
    return send({code:'DENIED'},403);
  });
  await page.goto('/#maintenance');
  await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  return {state,writes,reads,errors};
}
async function create(page:Page) {
  await page.getByLabel('Inspection IDs',{exact:true}).fill(I);
  await page.getByLabel('I acknowledge interruption of ordinary work; this hold erases nothing.').check();
  await page.getByRole('button',{name:'Create request and hold',exact:true}).click();
}
test('owner creates, reads and cancels without a cleanup or enable action',async({page})=>{
  const f=await setup(page);await create(page);
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();
  await page.getByLabel('I acknowledge cancellation performs no erasure and leaves inspections disabled.').check();
  await page.getByRole('button',{name:'Cancel this request before cleanup',exact:true}).click();
  await expect(page.getByText('Status: cancelled. Drain: not_current. This is a snapshot, not a cleanup receipt.',{exact:true})).toBeVisible();
  await expect(page.getByRole('status')).toContainText('Inspections at this read: disabled');
  expect(f.writes.map(w=>w.path)).toEqual([base,base+'/'+R+'/cancel']);expect(f.errors).toEqual([]);
});
test('unknown create preserves exact identity across reload and original retry',async({page})=>{
  const f=await setup(page);f.state.drop=true;await create(page);
  await expect(page.getByRole('heading',{name:'Original outcome unconfirmed',exact:true})).toBeVisible();
  const saved=await page.evaluate(()=>sessionStorage.getItem('proofpack.metadata.original-intent.v1'));expect(saved).not.toContain('csrf_token');expect(saved).not.toContain('x'.repeat(43));
  page.once('dialog',dialog=>void dialog.accept());await page.reload();await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  await page.getByRole('button',{name:'Retry original create',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();
  expect(f.writes).toHaveLength(2);expect(f.writes[1]).toEqual(f.writes[0]);
  expect(await page.evaluate(()=>sessionStorage.getItem('proofpack.metadata.original-intent.v1'))).toBeNull();expect(f.errors).toEqual([]);
});
for(const fault of ['erased','fulfilled','scope'])test('withholds '+fault+' write response and retains original intent',async({page})=>{
  const f=await setup(page);f.state.fault=fault;await create(page);
  await expect(page.getByRole('heading',{name:'Original outcome unconfirmed',exact:true})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Retry original create',exact:true})).toBeEnabled();expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('ordinary member has no owner controls or private context request',async({page})=>{
  const f=await setup(page,['operator']);await expect(page.getByRole('status')).toContainText('Only a currently authorized owner');
  await expect(page.getByRole('button',{name:'Create request and hold',exact:true})).toHaveCount(0);expect(f.reads).not.toContain(base+'/context');expect(f.writes).toEqual([]);
});
test('stale MFA clears usable owner state and offers fixed sign-in recovery',async({page})=>{
  const f=await setup(page);f.state.fault='mfa';await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('current session cannot perform');
  await expect(page.getByRole('link',{name:'Sign in or refresh MFA',exact:true})).toHaveAttribute('href','/api/v1/auth/login?mfa=required');
  await expect(page.getByRole('button',{name:'Create request and hold',exact:true})).toHaveCount(0);expect(f.writes).toEqual([]);
});
test('active work keeps cancellation disabled and does not clear registry entries',async({page})=>{
  const f=await setup(page);f.state.record={...result(),active_count:2,foreign_active:true,drain_status:'waiting',can_cancel:false};f.state.phase='HELD';
  await page.getByLabel('Metadata request ID',{exact:true}).fill(R);await page.getByRole('button',{name:'Read request status',exact:true}).click();
  await expect(page.getByText('Drain: waiting.',{exact:false})).toBeVisible();
  await expect(page.getByRole('button',{name:'Cancel this request before cleanup',exact:true})).toBeDisabled();expect(f.writes).toEqual([]);
});
test('duplicate scope is rejected before any original write is sent',async({page})=>{
  const f=await setup(page);await page.getByLabel('Inspection IDs',{exact:true}).fill(I+','+I);
  await page.getByLabel('I acknowledge interruption of ordinary work; this hold erases nothing.').check();await page.getByRole('button',{name:'Create request and hold',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('unique lowercase inspection IDs');expect(f.writes).toEqual([]);
});
test('keyboard entry, narrow zoom and pending scope remain readable',async({page})=>{
  await page.setViewportSize({width:320,height:900});const f=await setup(page);f.state.drop=true;await create(page);
  await expect(page.getByRole('heading',{name:'Original outcome unconfirmed',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Back to workspace',exact:true})).toBeDisabled();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
  await page.getByLabel(/I have kept the original recovery reference privately/).focus();await page.keyboard.press('Space');
  await expect(page.getByRole('button',{name:'Back to workspace',exact:true})).toBeEnabled();expect(f.errors).toEqual([]);
});

test('unread stored recovery blocks silent exit and reveals no original private scope',async({page})=>{
  await page.addInitScript(()=>sessionStorage.setItem('proofpack.metadata.original-intent.v1','{"private":"UNREAD_PRIVATE_SCOPE"}'));
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Owner maintenance',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Back to workspace',exact:true})).toBeDisabled();
  await expect(page.getByText('UNREAD_PRIVATE_SCOPE',{exact:false})).toHaveCount(0);
  await page.getByLabel(/I have kept the original recovery reference privately/).check();
  await expect(page.getByRole('button',{name:'Back to workspace',exact:true})).toBeEnabled();
});

test('context retries only the failed safe read after prior control release',async({page})=>{
  const f=await setup(page,['owner'],1);await expect(page.getByRole('heading',{name:'Owner snapshot',exact:true})).toBeVisible();
  expect(f.reads.filter(p=>p==='/me')).toHaveLength(1);expect(f.reads.filter(p=>p===base+'/context')).toHaveLength(2);expect(f.writes).toEqual([]);
});
test('persistent busy stops at three reads without usable creation authority',async({page})=>{
  const f=await setup(page,['owner'],4);await expect(page.getByRole('status')).toContainText('This workflow is unavailable');
  await expect(page.getByRole('button',{name:'Create request and hold',exact:true})).toBeDisabled();
  expect(f.reads.filter(p=>p==='/me')).toHaveLength(1);expect(f.reads.filter(p=>p===base+'/context')).toHaveLength(3);expect(f.writes).toEqual([]);
});
async function visibility(page:Page,value:'hidden'|'visible'){
  await page.evaluate(value=>{Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>value});document.dispatchEvent(new Event('visibilitychange'));},value);
}
test('late hidden context cannot restore a private review',async({page})=>{
  const f=await setup(page);await expect(page.getByRole('heading',{name:'Owner snapshot',exact:true})).toBeVisible();
  f.state.contextDelay=200;await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  await expect.poll(()=>f.reads.filter(p=>p===base+'/context').length).toBe(2);await visibility(page,'hidden');
  await page.waitForTimeout(250);await visibility(page,'visible');
  await expect(page.getByRole('heading',{name:'Owner snapshot',exact:true})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Create request and hold',exact:true})).toHaveCount(0);expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});
test('interrupted committed write keeps original scope until explicit retry',async({page})=>{
  const f=await setup(page);f.state.createDelay=200;await create(page);
  await expect(page.getByRole('heading',{name:'Original outcome unconfirmed',exact:true})).toBeVisible();await visibility(page,'hidden');
  await page.waitForTimeout(250);await visibility(page,'visible');
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toHaveCount(0);
  const saved=await page.evaluate(()=>sessionStorage.getItem('proofpack.metadata.original-intent.v1'));expect(saved).not.toBeNull();
  f.state.createDelay=0;await page.getByRole('button',{name:'Read owner status',exact:true}).click();await page.getByRole('button',{name:'Retry original create',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();expect(f.writes).toHaveLength(2);expect(f.writes[1]).toEqual(f.writes[0]);expect(f.errors).toEqual([]);
});


async function accounting(page:Page, fault='', auth=false) {
  const f=await setup(page); const reviews:{body:unknown;key:string|undefined}[]=[]; const reviewControl={delayMs:0};
  await page.route('**/api/v1/privacy/metadata-requests/'+R+'/review',async route=>{
    const req=route.request();expect(req.method()).toBe('POST');expect(req.headers()['x-csrf-token']).toBe('x'.repeat(43));
    reviews.push({body:req.postDataJSON(),key:req.headers()['idempotency-key']});
    if(reviewControl.delayMs)await new Promise(resolve=>setTimeout(resolve,reviewControl.delayMs));
    if(fault==='denied'||fault==='held')return route.fulfill({status:fault==='denied'?403:503,json:{code:fault==='denied'?'ACCESS_DENIED':'METADATA_REVIEW_HELD'}});
    const value:Record<string,unknown>={id:R,scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:1,accounting_policy:'conservative-family-accounting-v1',counts:{AFFECTED:1,SHARED:2,CONTEXT:3,UNRELATED:4,UNRESOLVED:5},total_records:15,historical:true,read_only:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
    if(auth){value.accounting_policy='conservative-family-accounting-v5';value.auth_history_policy_resolved=false;value.historical_auth_authority_proven=false;}
    if(fault==='auth-policy')value.auth_history_policy_resolved=true;
    if(fault==='auth-authority')value.historical_auth_authority_proven=true;
    if(fault==='scope')value.scope_sha256='b'.repeat(64);
    if(fault==='version')value.request_version=2;
    if(fault==='authority')value.can_confirm_cleanup=true;
    if(fault==='extra')value.objects=['private/key'];
    if(fault==='sum')value.total_records=14;
    return route.fulfill({status:200,json:value});
  });
  await create(page);await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toBeVisible();return {...f,reviews,reviewControl};
}
test('owner explicitly reads exact non-authorizing historical accounting once',async({page})=>{
  const f=await accounting(page);await expect(page.getByRole('heading',{name:'Historical accounting hints',exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('table',{name:'Historical record counts; no cleanup authority'})).toBeVisible();
  await expect(page.getByRole('row',{name:'UNRESOLVED 5',exact:true})).toBeVisible();await expect(page.getByRole('row',{name:'Total records 15',exact:true})).toBeVisible();
  expect(f.reviews).toEqual([{body:{expected_request_version:1,expected_gate_version:2,expected_control_version:1},key:expect.stringMatching(/^[0-9a-f-]{36}$/)}]);
  await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toBeDisabled();
  expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
  await page.getByLabel('Metadata request ID',{exact:true}).fill(I);await expect(page.getByRole('table')).toHaveCount(0);
});
for(const fault of ['denied','held','scope','version','authority','extra','sum'])test('owner accounting withholds '+fault+' and never auto retries',async({page})=>{
  const f=await accounting(page,fault);await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('status')).toContainText(/no erasure, fulfillment or inspection resumption is confirmed/);
  await expect(page.getByRole('table')).toHaveCount(0);await expect(page.getByRole('heading',{name:'Request '+R,exact:true})).toHaveCount(0);
  expect(f.reviews).toHaveLength(1);expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('offline interruption withdraws historical accounting and usable owner state',async({page})=>{
  const f=await accounting(page);await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('table')).toBeVisible();await page.evaluate(()=>window.dispatchEvent(new Event('offline')));
  await expect(page.getByRole('table')).toHaveCount(0);await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toHaveCount(0);
  expect(f.reviews).toHaveLength(1);expect(f.errors).toEqual([]);
});


test('fresh request status is required before a second explicit accounting read',async({page})=>{
  const f=await accounting(page);await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('table')).toBeVisible();await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Read request status',exact:true}).click();await expect(page.getByRole('table')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toBeEnabled();expect(f.reviews).toHaveLength(1);
  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();await expect(page.getByRole('table')).toBeVisible();expect(f.reviews).toHaveLength(2);
  expect(f.reviews[0].body).toEqual(f.reviews[1].body);expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('cancellation withdraws accounting and offers no review or inspection resumption',async({page})=>{
  const f=await accounting(page);await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();await expect(page.getByRole('table')).toBeVisible();
  await page.getByLabel('I acknowledge cancellation performs no erasure and leaves inspections disabled.').check();
  await page.getByRole('button',{name:'Cancel this request before cleanup',exact:true}).click();
  await expect(page.getByText('Status: cancelled. Drain: not_current. This is a snapshot, not a cleanup receipt.',{exact:true})).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toBeDisabled();
  expect(f.reviews).toHaveLength(1);expect(f.state.enabled).toBe(false);expect(f.errors).toEqual([]);
});
for(const condition of ['hidden','navigation'])test('late accounting cannot restore after '+condition,async({page})=>{
  const f=await accounting(page);f.reviewControl.delayMs=200;await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect.poll(()=>f.reviews.length).toBe(1);
  if(condition==='hidden')await visibility(page,'hidden');else await page.goto('/');
  await page.waitForTimeout(300);if(condition==='hidden')await visibility(page,'visible');
  await expect(page.getByRole('table')).toHaveCount(0);await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toHaveCount(0);
  expect(f.reviews).toHaveLength(1);expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('timed out accounting stays withheld until fresh status and a new explicit read',async({page})=>{
  const f=await accounting(page);f.reviewControl.delayMs=7500;await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect.poll(()=>f.reviews.length).toBe(1);await page.waitForTimeout(7700);
  await expect(page.getByRole('status')).toContainText('no erasure, fulfillment or inspection resumption is confirmed');
  await expect(page.getByRole('table')).toHaveCount(0);await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toHaveCount(0);
  expect(f.reviews).toHaveLength(1);expect(f.errors).toEqual([]);f.reviewControl.delayMs=0;
  await page.getByRole('button',{name:'Read request status',exact:true}).click();await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('table')).toBeVisible();expect(f.reviews).toHaveLength(2);expect(f.writes).toHaveLength(1);
});
test('unconfirmed creation exposes no historical accounting control',async({page})=>{
  const f=await setup(page);f.state.drop=true;await create(page);await expect(page.getByRole('heading',{name:'Original outcome unconfirmed',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toHaveCount(0);expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});


test('configured auth accounting exposes actual policy and unresolved authority without cleanup controls',async({page})=>{
  const f=await accounting(page,'',true);
  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByText('Accounting policy: conservative-family-accounting-v5.',{exact:true})).toBeVisible();
  await expect(page.getByText('Supported authentication history was inspected.',{exact:false})).toContainText('Operational authentication policy remains unresolved');
  await expect(page.getByRole('row',{name:'UNRESOLVED 5',exact:true})).toBeVisible();
  await expect(page.getByText('Read only: yes. Erasure complete: no. Request fulfilled: no.',{exact:false})).toBeVisible();
  expect(f.reviews).toHaveLength(1);expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});
for(const fault of ['auth-policy','auth-authority'])test('auth accounting rejects false '+fault+' claim',async({page})=>{
  const f=await accounting(page,fault,true);
  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('status')).toContainText(/no erasure, fulfillment or inspection resumption is confirmed/);
  await expect(page.getByRole('table')).toHaveCount(0);
  expect(f.reviews).toHaveLength(1);expect(f.errors).toEqual([]);
});
test('offline interruption withdraws configured auth review without changing the held request',async({page})=>{
  const f=await accounting(page,'',true);await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('table')).toBeVisible();await page.evaluate(()=>window.dispatchEvent(new Event('offline')));
  await expect(page.getByRole('table')).toHaveCount(0);
  await expect(page.getByText('Accounting policy: conservative-family-accounting-v5.',{exact:true})).toHaveCount(0);
  expect(f.state.phase).toBe('HELD');expect(f.reviews).toHaveLength(1);expect(f.writes).toHaveLength(1);expect(f.errors).toEqual([]);
});
