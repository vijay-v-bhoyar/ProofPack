// Built UI/default Chrome with intercepted synthetic API; no human/provider proof.
import {test,expect,type Page} from '@playwright/test';
const I='00000000-0000-0000-0000-000000000001',U='00000000-0000-0000-0000-000000000002',R='00000000-0000-0000-0000-000000000003';
const base='/privacy/metadata-requests';
async function setup(page:Page,fault='') {
  const calls:{path:string;body:unknown}[]=[],errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>sessionStorage.clear());
  await page.route('**/api/v1/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname.replace('/api/v1','');
    const send=(value:unknown,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
    if(path==='/me')return send({id:U,session_id:'synthetic',display_name:'Synthetic owner',roles:['owner'],csrf_token:'x'.repeat(43)});
    if(path===base+'/context')return send({gate_version:2,gate_phase:'HELD',gate_epoch:1,control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,max_inspections:10,can_create:false,can_confirm_cleanup:false,erasure_complete:false});
    if(path===base+'/'+R)return send({id:R,state_version:1,status:'held',scope_sha256:'a'.repeat(64),inspection_ids:[I],selector_policy:'read-only-family-selection-v3',created_at_ms:100,original_owner_session:true,current_hold:true,gate_version:2,gate_epoch:1,gate_phase:'HELD',control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,drain_status:'empty',can_cancel:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false});
    if(request.method()==='POST')calls.push({path,body:request.postDataJSON()});
    const binding={id:R,scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:1};
    const flags={historical:true,read_only:true,auth_history_policy_resolved:false,historical_auth_authority_proven:false,
      metadata_history_policy_resolved:false,historical_metadata_authority_proven:false,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
    if(path===base+'/'+R+'/review')return send({...binding,...flags,accounting_policy:'conservative-family-accounting-v6',
      metadata_history_policy_resolved:fault==='bad-review',counts:{AFFECTED:1,SHARED:0,CONTEXT:4,UNRELATED:0,UNRESOLVED:7},total_records:12});
    if(path===base+'/'+R+'/policy-obligations')return send({...binding,...flags,
      gate_version:fault==='stale'?3:2,policy:'privacy-policy-obligations-v2',accounting_policy:'conservative-family-accounting-v6',
      family_counts:{'access-head':1,bootstrap:1,user:1,identity:1,session:1,cookie:1,invitation:0,'owner-transfer':0,'access-replay':0,'oauth-flow':0,'oauth-quota':0},
      validated_auth_records:6,source_records:12,historical_dependencies_unavailable:0,next_step:'OWNER_D11_POLICY_DECISION_REQUIRED',
      metadata_family_counts:{'metadata-request':1,'metadata-operation':1,'metadata-event':1,'metadata-quota':1},
      validated_metadata_records:4,metadata_historical_dependencies_unavailable:0,
      metadata_history_policy_resolved:fault==='bad-policy',request_fulfilled:fault==='fulfilled'});
    return send({code:'DENIED'},403);
  });
  await page.goto('/#maintenance');await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  await page.getByLabel('Metadata request ID',{exact:true}).fill(R);await page.getByRole('button',{name:'Read request status',exact:true}).click();
  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  return {calls,errors};
}

test('owner reads both category groups without granting policy or cleanup authority',async({page})=>{
  const f=await setup(page);await expect(page.getByRole('heading',{name:'Historical accounting hints',exact:true})).toBeVisible();
  await expect(page.getByText('Supported privacy-request history was also inspected.',{exact:false})).toBeVisible();
  expect(f.calls).toHaveLength(1);await page.getByRole('button',{name:'Explain missing privacy decisions',exact:true}).click();
  await expect(page.getByRole('table',{name:'Reviewed privacy-request categories requiring an operating policy',exact:true})).toContainText('Shared write allowances');
  await expect(page.getByRole('table',{name:'Reviewed authentication categories requiring an operating policy',exact:true})).toContainText('Session references');
  await expect(page.getByRole('status')).toContainText('no cleanup or fulfillment is approved');
  expect(f.calls).toHaveLength(2);expect(f.calls[1].body).toEqual({expected_request_version:1,expected_gate_version:2,expected_control_version:1});
  expect(f.calls.map(c=>c.path)).toEqual([base+'/'+R+'/review',base+'/'+R+'/policy-obligations']);expect(f.errors).toEqual([]);
  await page.getByLabel('Metadata request ID',{exact:true}).fill(I);await expect(page.getByRole('heading',{name:'Missing privacy decisions',exact:true})).toHaveCount(0);
});

for(const fault of ['bad-policy','fulfilled','stale'])test('withholds '+fault+' explanation and its earlier context',async({page})=>{
  const f=await setup(page,fault);await page.getByRole('button',{name:'Explain missing privacy decisions',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Missing privacy decisions',exact:true})).toHaveCount(0);
  await expect(page.getByRole('status')).toContainText('no erasure, fulfillment or inspection resumption is confirmed');
  expect(f.calls).toHaveLength(2);expect(f.errors).toEqual([]);
});

test('rejects a review claiming metadata policy is resolved',async({page})=>{
  const f=await setup(page,'bad-review');await expect(page.getByRole('heading',{name:'Historical accounting hints',exact:true})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Explain missing privacy decisions',exact:true})).toHaveCount(0);
  expect(f.calls).toHaveLength(1);expect(f.errors).toEqual([]);
});

test('keyboard and narrow screen keep both groups readable and offline clears them',async({page})=>{
  await page.setViewportSize({width:320,height:900});const f=await setup(page);
  await page.getByRole('button',{name:'Explain missing privacy decisions',exact:true}).focus();await page.keyboard.press('Enter');
  await expect(page.getByRole('table',{name:'Reviewed privacy-request categories requiring an operating policy',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
  await page.evaluate(()=>window.dispatchEvent(new Event('offline')));
  await expect(page.getByRole('heading',{name:'Missing privacy decisions',exact:true})).toHaveCount(0);
  expect(f.calls).toHaveLength(2);expect(f.errors).toEqual([]);
});
