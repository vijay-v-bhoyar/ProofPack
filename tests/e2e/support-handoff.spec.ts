/** Rendered frontend with synthetic API/identity; no provider or human proof. */
import { test, expect, type Page } from '@playwright/test';
const USER='10000000-0000-4000-8000-000000000001', OTHER='10000000-0000-4000-8000-000000000002';
const INSPECTION='20000000-0000-4000-8000-000000000001', STATION='30000000-0000-4000-8000-000000000001';
const REQUEST='40000000-0000-4000-8000-000000000001';
async function setup(page: Page, roles=['reviewer']) {
  const state={roles, fault:'', ttl:5000, status:'pending', next:null as string|null,exists:true,sender:OTHER,recipient:USER,inspectionVersion:3,sourceVersion:1,effects:0,stationOwned:true};
  const committed=new Map<string,string>();
  const writes:{path:string;body:any;key:string;version:string}[]=[], errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  const detail=()=>({id:REQUEST,inspection_id:INSPECTION,state_version:state.status==='pending'?1:2,inspection_state_version:state.inspectionVersion,
    request_sha256:'a'.repeat(64),recorded_status:state.status,effective_status:state.fault==='held'?'held':state.status,
    pending_eligible:state.status==='pending'&&state.fault!=='held',acknowledged:state.status==='accepted',current_assignment:state.status==='accepted',
    historical:true,machine_approval:false,capture_transferred:false,remaining_validity_ms:state.ttl,
    request:{sender_user_id:state.sender,recipient_user_id:state.recipient,reason_code:'support_needed',station_id:STATION,station_epoch:1,station_name:'Synthetic station',kit_reference:'kit-1',
      source_inspection_revision:state.sourceVersion,post_request_inspection_revision:state.sourceVersion+1,source_observation_id:null,previous_accepted_handoff_id:null,created_at_ms:1000,expires_at_ms:3601000},
    decision:state.status==='pending'?null:{kind:state.status,actor_user_id:USER,at_ms:2000}});
  await page.route('**/api/v1/**',async route=>{
    const req=route.request(),url=new URL(req.url()),p=url.pathname.replace('/api/v1','');
    const send=(data:unknown,status=200)=>route.fulfill({status,json:data});
    if(p==='/me')return send({id:USER,session_id:'support-session',display_name:'Synthetic member',roles:state.fault==='role-loss'?[]:state.roles,csrf_token:'x'.repeat(43)});
    if(p==='/stations')return send({stations:[],next_cursor:null});
    if(p==='/auth/logout')return send({});
    if(req.method()!=='GET') {
      const body=req.postDataJSON();writes.push({path:p,body,key:req.headers()['idempotency-key'],version:req.headers()['if-match']});
      const key=req.headers()['idempotency-key'],signature=JSON.stringify([p,body,req.headers()['if-match']]);
      if(committed.has(key))expect(committed.get(key)).toBe(signature);
      else {committed.set(key,signature);state.effects++;state.status=body.decision??(p.endsWith('/cancel')?'cancelled':'pending');
        if(p.endsWith('/handoffs')){state.exists=true;state.sender=USER;state.recipient=body.recipient_user_id;state.sourceVersion=Number(req.headers()['if-match']);state.inspectionVersion=state.sourceVersion+1;}}
      if(state.fault==='lost'){state.fault='';return route.abort('failed');}
      const value=detail(); if(state.fault==='mismatch')value.inspection_id=STATION;
      return send(value);
    }
    if(state.fault==='denied')return send({},403);
    if(p==='/inspections/'+INSPECTION)return send({id:INSPECTION,station_id:STATION,state_version:1,effective_state:'REVIEW_REQUIRED',remaining_lease_ms:0,last_observed_at:null});
    if(p==='/stations/'+STATION)return send({id:STATION,name:'Synthetic station',state_version:1,epoch:1,owner_session_id:'support-session',owned_by_current_session:state.stationOwned,active_inspection_id:INSPECTION});
    if(p==='/handoffs/inbox')return send({requests:[{id:REQUEST,inspection_id:INSPECTION,state_version:1,request_sha256:'a'.repeat(64),recorded_status:'pending',
      reason_code:'support_needed',station_name:'Synthetic station',kit_reference:'kit-1',created_at_ms:1000,expires_at_ms:3601000,historical:true,machine_approval:false}],
      next_cursor:state.next,historical:true,machine_approval:false,remaining_validity_ms:state.ttl,scope:'recorded recipient references only; read current request details before any response'});
    if(p.startsWith('/inspections/'+INSPECTION+'/handoffs/')) {
      if(!state.exists)return send({inspection_id:INSPECTION,handoff:null,historical:true,machine_approval:false,capture_transferred:false,remaining_validity_ms:state.ttl});
      const value:any=detail();if(state.fault==='private')value.cookie='forbidden';if(state.fault==='approval')value.machine_approval=true;
      if(state.fault==='wrong-inspection')value.inspection_id=STATION;
      if(state.fault==='wrong-decision-actor'){value.recorded_status='accepted';value.effective_status='accepted';value.state_version=2;value.pending_eligible=false;value.acknowledged=true;value.decision={kind:'accepted',actor_user_id:OTHER,at_ms:2000};}
      return send(value);
    }
    return send({},403);
  });
  await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();
  await page.getByRole('button',{name:'Review and administration',exact:true}).click();
  return {state,writes,errors};
}
test('reviewer can discover a stopped support request and separately acknowledge review responsibility',async({page})=>{
  const f=await setup(page);
  await page.getByRole('button',{name:'Support handoff',exact:true}).click();
  await page.getByRole('button',{name:'Read my support inbox',exact:true}).click();
  await page.getByRole('button',{name:'Read support request '+REQUEST,exact:true}).click();
  await expect(page.getByText('kit-1',{exact:false}).first()).toBeVisible();
  await page.getByLabel('I acknowledge that this response transfers no capture or kit approval.').check();
  await page.getByRole('button',{name:'Accept review responsibility',exact:true}).click();
  await expect(page.getByText('Recorded acknowledgment: accepted.',{exact:false})).toBeVisible();
  expect(f.writes).toHaveLength(1);expect(f.writes[0].body).toEqual({decision:'accepted',request_sha256:'a'.repeat(64),expected_inspection_version:3,acknowledge_no_capture_transfer:true});
  expect(f.errors).toEqual([]);
});

async function openSupport(page:Page){await page.getByRole('button',{name:'Support handoff',exact:true}).click();}
async function read(page:Page){await page.getByLabel('Support inspection ID',{exact:true}).fill(INSPECTION);await page.getByRole('button',{name:'Read support details',exact:true}).click();}
async function acknowledge(page:Page){await page.getByLabel('I acknowledge that this response transfers no capture or kit approval.').check();}
test('owner grant alone exposes no support action and operator has no reviewer inbox',async({page})=>{
  await setup(page,['owner']);await expect(page.getByRole('button',{name:'Support handoff',exact:true})).toHaveCount(0);
});
test('operator prepares fresh stopped same-inspection context before a designated request',async({page})=>{
  const f=await setup(page,['operator']);f.state.exists=false;await openSupport(page);
  await expect(page.getByRole('button',{name:'Read my support inbox',exact:true})).toHaveCount(0);
  await page.getByLabel('Support inspection ID',{exact:true}).fill(INSPECTION);await page.getByLabel('Intended reviewer ID',{exact:true}).fill(OTHER);
  await page.getByRole('button',{name:'Prepare stopped inspection request',exact:true}).click();
  await page.getByLabel('I stopped capture and reliance on any previous result.').check();
  await page.getByRole('button',{name:'Request designated review support',exact:true}).click();
  await expect(page.getByLabel('Support receipt')).toContainText('Support request recorded');
  expect(f.writes[0].body).toEqual({recipient_user_id:OTHER,expected_epoch:1,reason_code:'support_needed',stop_acknowledged:true});
  expect(f.writes[0].version).toBe('1');expect(f.errors).toEqual([]);
});
test('unowned station cannot be prepared or used to request support',async({page})=>{
  const f=await setup(page,['operator']);f.state.stationOwned=false;await openSupport(page);
  await page.getByLabel('Support inspection ID',{exact:true}).fill(INSPECTION);await page.getByRole('button',{name:'Prepare stopped inspection request',exact:true}).click();
  await expect(page.locator('#support-title').locator('..').getByRole('status')).toContainText('not owned');
  await expect(page.getByRole('button',{name:'Request designated review support',exact:true})).toBeDisabled();expect(f.writes).toEqual([]);
});
test('no recorded request does not imply accepted responsibility',async({page})=>{
  const f=await setup(page,['operator']);f.state.exists=false;await openSupport(page);await read(page);
  await expect(page.locator('#support-title').locator('..').getByRole('status')).toContainText('nobody has accepted');expect(f.writes).toEqual([]);
});
for(const fault of ['private','approval','wrong-inspection','wrong-decision-actor'])test('rejects '+fault+' context without an eligible action',async({page})=>{
  const f=await setup(page);f.state.fault=fault;await openSupport(page);await read(page);
  await expect(page.locator('#support-title').locator('..').getByRole('status')).toContainText(/unavailable|does not match/);
  await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toHaveCount(0);expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});
for(const trigger of ['held','expiry','offline','failed-read','role-loss'])test('withdraws response eligibility on '+trigger,async({page})=>{
  const f=await setup(page);await openSupport(page);if(trigger==='held')f.state.fault='held';if(trigger==='expiry')f.state.ttl=900;
  if(trigger==='expiry')await page.clock.install();await read(page);
  if(trigger==='held')await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toBeDisabled();
  if(trigger==='expiry'){await acknowledge(page);await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toBeEnabled();await page.clock.fastForward(1000);await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toBeDisabled();}
  if(trigger==='offline'){await page.evaluate(()=>window.dispatchEvent(new Event('offline')));await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toHaveCount(0);}
  if(trigger==='failed-read'){f.state.fault='denied';await page.getByRole('button',{name:'Read support details',exact:true}).click();await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toHaveCount(0);}
  if(trigger==='role-loss'){await acknowledge(page);f.state.fault='role-loss';await page.getByRole('button',{name:'Accept review responsibility',exact:true}).click();await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toHaveCount(0);}
  expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});
for(const fault of ['lost','mismatch'])test('preserves exact uncertain response intent through '+fault,async({page})=>{
  const f=await setup(page);await openSupport(page);await read(page);await acknowledge(page);f.state.fault=fault;
  await page.getByRole('button',{name:'Accept review responsibility',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged support intent',exact:true})).toBeVisible();
  await expect(page.getByLabel('Support inspection ID',{exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Read support details',exact:true})).toBeDisabled();
  f.state.fault='';await page.getByRole('button',{name:'Retry unchanged support intent',exact:true}).click();
  await expect(page.getByLabel('Support receipt')).toContainText('accepted');expect(f.writes).toHaveLength(2);
  expect(f.writes[0]).toEqual(f.writes[1]);expect(f.state.effects).toBe(1);expect(f.errors).toEqual([]);
});
test('unknown response requires acknowledged departure without canceling the server effect',async({page})=>{
  const f=await setup(page);await openSupport(page);await read(page);await acknowledge(page);f.state.fault='lost';await page.getByRole('button',{name:'Accept review responsibility',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged support intent',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Return to inspections',exact:true}).click();await expect(page.getByRole('alertdialog')).toBeVisible();
  await expect(page.getByRole('button',{name:'Leave and investigate',exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Keep working here',exact:true}).click();await expect(page.getByRole('button',{name:'Return to inspections',exact:true})).toBeFocused();
  expect(f.writes).toHaveLength(1);expect(f.state.status).toBe('accepted');
});
test('decline is a separate acknowledged response with no accepted assignment',async({page})=>{
  const f=await setup(page);await openSupport(page);await read(page);await acknowledge(page);await page.getByRole('button',{name:'Decline review responsibility',exact:true}).click();
  await expect(page.getByLabel('Support receipt')).toContainText('declined');expect(f.writes[0].body.decision).toBe('declined');expect(f.errors).toEqual([]);
});
test('original sender can cancel a freshly read pending record',async({page})=>{
  const f=await setup(page,['operator']);f.state.sender=USER;f.state.recipient=OTHER;await openSupport(page);await read(page);
  await page.getByRole('button',{name:'Cancel my pending support request',exact:true}).click();await expect(page.getByLabel('Support receipt')).toContainText('cancelled');
  expect(f.writes[0].body).toEqual({request_sha256:'a'.repeat(64)});expect(f.errors).toEqual([]);
});
test('accepted reviewer can request a separately acknowledged successor without implying acceptance',async({page})=>{
  const f=await setup(page);f.state.status='accepted';await openSupport(page);await page.getByLabel('Intended reviewer ID',{exact:true}).fill(OTHER);await read(page);
  await page.getByLabel('I stopped capture and reliance on any previous result.').check();await page.getByRole('button',{name:'Request designated review support',exact:true}).click();
  await expect(page.getByLabel('Support receipt')).toContainText('No recipient acceptance');expect(f.writes[0].version).toBe('3');expect(f.errors).toEqual([]);
});
test('support controls remain reachable with keyboard, narrow zoom and forced colors',async({page})=>{
  const f=await setup(page);await openSupport(page);await page.setViewportSize({width:800,height:900});await page.emulateMedia({forcedColors:'active'});await page.evaluate(()=>{document.documentElement.style.zoom='2';});
  await page.getByLabel('Support inspection ID',{exact:true}).focus();await page.keyboard.type(INSPECTION);await page.keyboard.press('Tab');await page.keyboard.press('Tab');
  await expect(page.getByRole('button',{name:'Read support details',exact:true})).toBeFocused();await page.keyboard.press('Enter');
  await expect(page.getByText('Historical acknowledgment:',{exact:false})).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);expect(f.errors).toEqual([]);
});

test('a slow authorization refresh cannot submit after the original detail window expires',async({page})=>{
  const f=await setup(page);await openSupport(page);await page.clock.install();await read(page);await acknowledge(page);
  let release:(()=>Promise<void>)|undefined;
  await page.route('**/api/v1/me',route=>new Promise<void>(resolve=>{release=async()=>{await route.fulfill({json:{id:USER,session_id:'support-session',display_name:'Synthetic member',roles:['reviewer'],csrf_token:'x'.repeat(43)}});resolve();};}));
  await page.getByRole('button',{name:'Accept review responsibility',exact:true}).click();
  await expect.poll(()=>!!release).toBe(true);await page.clock.fastForward(5001);await release!();
  await expect(page.locator('#support-title').locator('..').getByRole('status')).toContainText('Review expired');
  expect(f.writes).toEqual([]);expect(f.errors).toEqual([]);
});
test('inbox pagination replaces a bounded historical page and rejects a nonadvancing cursor',async({page})=>{
  const f=await setup(page);f.state.next=OTHER;await openSupport(page);await page.getByRole('button',{name:'Read my support inbox',exact:true}).click();
  await expect(page.getByRole('button',{name:'Accept review responsibility',exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Next support inbox page',exact:true}).click();
  await expect(page.locator('#support-title').locator('..').getByRole('status')).toContainText('did not advance');
  await expect(page.getByRole('button',{name:'Read support request '+REQUEST,exact:true})).toHaveCount(0);expect(f.writes).toEqual([]);
});
test('an acknowledged departure discards local retry details without another server write',async({page})=>{
  const f=await setup(page);await openSupport(page);await read(page);await acknowledge(page);f.state.fault='lost';await page.getByRole('button',{name:'Accept review responsibility',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged support intent',exact:true})).toBeVisible();await page.getByRole('button',{name:'Return to inspections',exact:true}).click();
  await page.getByLabel('I understand only local retry details will be discarded and the server outcome must still be investigated.').check();
  await page.getByRole('button',{name:'Leave and investigate',exact:true}).click();await expect(page.getByRole('heading',{name:'Kit inspections',exact:true})).toBeVisible();
  expect(f.writes).toHaveLength(1);expect(f.state.effects).toBe(1);expect(f.state.status).toBe('accepted');expect(f.errors).toEqual([]);
});

test('expired initial preparation explains why a fresh preparation is required',async({page})=>{
  const f=await setup(page,['operator']);await openSupport(page);await page.clock.install();
  await page.getByLabel('Support inspection ID',{exact:true}).fill(INSPECTION);await page.getByLabel('Intended reviewer ID',{exact:true}).fill(OTHER);
  await page.getByRole('button',{name:'Prepare stopped inspection request',exact:true}).click();
  await page.getByLabel('I stopped capture and reliance on any previous result.').check();
  await expect(page.getByRole('button',{name:'Request designated review support',exact:true})).toBeEnabled();
  await page.clock.fastForward(5001);await expect(page.getByRole('button',{name:'Request designated review support',exact:true})).toBeDisabled();
  await expect(page.getByText('Stopped-inspection review expired. Prepare again before requesting.',{exact:true})).toBeVisible();expect(f.writes).toEqual([]);
});
