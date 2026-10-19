// Synthetic API fixtures exercise the actual bundle; native tests prove server controls separately.
import { test, expect, type Page } from '@playwright/test';
const P='a1000000-0000-4000-8000-000000000001', Q='b1000000-0000-4000-8000-000000000002', PREP='c1000000-0000-4000-8000-000000000003', SOURCE='d1000000-0000-4000-8000-000000000004';
const A='e1000000-0000-4000-8000-000000000005', B='e1000000-0000-4000-8000-000000000006', C='e1000000-0000-4000-8000-000000000007';
const M='a2000000-0000-4000-8000-000000000010',R='b2000000-0000-4000-8000-000000000011';
const flags={physical_truth_verified:false,independent_benchmark_qualified:false,operator_effort_measured:false,beta_eligible:false,inspection_enablement_granted:false};
type Settings={role?:'owner'|'reviewer'|'operator'|'combined';complete?:boolean;operation?:'bootstrap'|'promote'|'rollback';qMode?:'installed_default'|'candidate';lost?:'qualification'|'activation';malformed?:'qualification'|'receipt'|'legacy-receipt';fault?:'counts'|'flag'|'registry'|'purpose'|'digest'|'stale'|'held'|'prep'|'page'|'repeatPage'|'refunded';ttl?:number;rejected?:boolean;notOriginal?:boolean;lease?:number;revoked?:boolean};
async function fixture(page:Page,s:Settings={}) {
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  const roles=s.role==='combined'?['owner','reviewer']:[s.role??'reviewer'];
  const user={id:'f1000000-0000-4000-8000-000000000008',session_id:'policy-session',display_name:'Synthetic lifecycle user',roles,csrf_token:'x'.repeat(43)};
  let status=s.complete?'completed':s.lease?'processing':'queued',version=1,mode=s.qMode??'installed_default',lost=false,malformed=false,activeVersion=(s.operation??'bootstrap')==='bootstrap'?0:2,control=7,enabled=activeVersion>0,consumed=false;
  let work:'queued'|'one'|'complete'=s.complete?'complete':s.lease?'one':'queued';
  let evalComplete=true,evalVersion=4;
  const writes:{path:string;body:any;key:string;version?:string}[]=[],reads:string[]=[],commits=new Map<string,any>();
  const rollbackTarget={active_version:2,activation_id:B,predecessor_activation_id:A};
  const digest=s.operation==='rollback'?'a'.repeat(64):'b'.repeat(64),revision=s.operation==='rollback'?1:2;
  let original:any={mode,policy_id:P,policy_revision:revision,policy_state_version:2,policy_revision_sha256:digest,synthetic_demo_acknowledged:true,
    ...(mode==='candidate'?{preparation_id:PREP,preparation_state_version:4,preparation_report_sha256:'e'.repeat(64)}:{}),...(s.operation==='rollback'?{rollback_target:rollbackTarget}:{})};
  const policy=(old=false)=>({id:P,revision:old?1:revision,state_version:2,latest_revision:2,revision_sha256:old?'a'.repeat(64):digest,previous_sha256:old?null:'a'.repeat(64),behavior_sha256:'f'.repeat(64),
    spec:{name:'Synthetic policy',algorithm:'reason_priority_v1',priority:['SEPARATE_REGION','PLACE_FLAT','RECAPTURE']},status:'draft',binding_current:true,evaluation_status:'NOT_VERIFIED',promotion_available:false,can_revise:!old,live_effect:'none_from_draft_write'});
  let evaluation:any={runner:'vision_replay_v1',policy_id:P,policy_revision:revision,policy_state_version:2,policy_revision_sha256:digest,manifest_id:M,manifest_sha256:'b'.repeat(64),historical_diagnostic_acknowledged:true,frozen_holdout_acknowledged:false,
    candidate_recipe_id:R,candidate_recipe_revision:1,candidate_recipe_state_version:1,candidate_recipe_sha256:'e'.repeat(64),vision_measurement_acknowledged:true,...(s.operation==='rollback'?{rollback_target:rollbackTarget}:{})};
  const comparison=()=>{
    const counts={observed_match:0,counterfactual_unknown:0,no_recorded_outcome:0,not_actionable:1,incorrect_finding:0,declared_resolved:0,declared_unresolved:0,measurements:1,observable_frames:1,count_matches:1,count_mismatches:0,unobservable_frames:0};
    return {id:SOURCE,kind:'policy_evaluation',state_version:evalVersion,status:evalComplete?'completed':'queued',...evaluation,candidate_name:'Synthetic policy',example_count:1,prepared_count:evalComplete?1:0,steps_reserved:evalComplete?1:0,
      remaining_ms:s.ttl??30000,lease_remaining_ms:0,report_sha256:evalComplete?'a'.repeat(64):null,failure_reason:null,diagnostic_only:true,independent_benchmark_qualified:false,promotion_eligible:false,operator_effort_measured:false,
      can_advance:!evalComplete,can_cancel:!evalComplete,can_retire:evalComplete,can_read_request:true,result_header_current:evalComplete,pixel_measurement_performed:evalComplete,physical_truth_verified:false,counts:evalComplete?{baseline:counts,candidate:counts}:null};};
  const options=()=>({software_cases:170,golden_cases:12,registry_sha256:'c'.repeat(64),max_reserved_cases:10000,max_steps:2000,lifetime_ms:3600000,lease_ms:15000,page_size:20,synthetic_demo_only:true,...flags});
  const record=()=>{const report=status==='completed'&&!consumed&&s.fault!=='held';const own=roles.includes('reviewer')&&!s.notOriginal;
    return {id:Q,kind:'policy_qualification',state_version:version,status,policy_id:P,policy_revision:original.policy_revision,policy_state_version:2,policy_revision_sha256:original.policy_revision_sha256,
      mode,preparation_id:mode==='candidate'?PREP:null,preparation_state_version:mode==='candidate'?4:null,preparation_report_sha256:mode==='candidate'?'e'.repeat(64):null,
      rollback_target:s.fault==='purpose'?null:(original.rollback_target??null),registry_sha256:s.fault==='registry'?'f'.repeat(64):'c'.repeat(64),source_examples:mode==='candidate'?1:0,
      current:!consumed&&s.fault!=='held',report_current:report,steps_prepared:s.fault==='refunded'&&status==='cancelled'?0:work==='complete'?(mode==='candidate'?22:13):work==='one'?1:0,
      planned_steps:mode==='candidate'?22:13,steps_reserved:s.fault==='refunded'&&status==='cancelled'?0:work==='complete'?(mode==='candidate'?22:13):work==='one'?1:0,
      cases_reserved:s.fault==='refunded'&&status==='cancelled'?0:work==='complete'?(mode==='candidate'?183:182):work==='one'?170:0,required_cases:mode==='candidate'?183:182,
      report_sha256:report?'d'.repeat(64):null,qualification_status:report?(s.rejected?'rejected':'qualified'):'not_qualified',
      counts:report?{passed:(mode==='candidate'?183:182)-(s.rejected?1:0),failed:s.rejected?1:0,unknown:s.fault==='counts'?1:0}:null,
      remaining_ms:s.ttl??30000,lease_remaining_ms:status==='processing'?(s.lease??0):0,can_advance:own&&!(status==='processing'&&s.lease)&&!consumed&&s.fault!=='held'&&['queued','processing'].includes(status),can_cancel:['queued','processing','failed'].includes(status),can_retire:status==='completed',
      can_read_request:own,can_read_details:own&&report,failure_reason:null,...flags,...(s.fault==='flag'?{beta_eligible:true}:{})};};
  const historical=(id:string)=>{
    const previous=id===A;return {transition_id:id,operation:previous?'bootstrap':original.rollback_target?'rollback':s.operation??'bootstrap',policy_id:P,policy_revision:previous?1:original.policy_revision,
      policy_revision_sha256:previous?'a'.repeat(64):s.fault==='digest'?'f'.repeat(64):original.policy_revision_sha256,policy_state_version:2,qualification_id:Q,qualification_report_sha256:'d'.repeat(64),
      previous_active_version:previous?0:(s.operation??'bootstrap')==='bootstrap'?0:2,active_version:previous?1:(s.operation??'bootstrap')==='bootstrap'?1:3,
      previous_control_version:previous?5:7,control_version:previous?6:8,activation_sha256:'f'.repeat(64),predecessor_activation_id:previous||(s.operation??'bootstrap')==='bootstrap'?null:B,
      historical_receipt:true,current_qualification_verified:false,inspection_enablement_granted:false};};
  await page.route('**/api/v1/**',async route=>{
    const r=route.request(),url=new URL(r.url()),path=url.pathname.slice('/api/v1'.length);reads.push(r.method()+' '+path);
    const json=(value:unknown,status=200)=>route.fulfill({json:value,status});
    if(path==='/me')return json({...user,roles:s.revoked?[]:roles});
    if(path==='/auth/logout')return route.fulfill({status:204});
    if(path==='/recipes')return json({recipes:[],next_cursor:null});
    if(path==='/recipes/'+R+'/draft')return json({id:R,revision:1,state_version:1,recipe_sha256:'e'.repeat(64),retired:false});
    if(path==='/evaluations/options')return json({runners:['decision_replay_v1','vision_replay_v1'],promotion_available:false,physical_truth_verified:false});
    if(path==='/jobs/'+M)return json({id:M,kind:'dataset_manifest',status:'completed',receipt_usable:true,example_count:1,manifest_sha256:'b'.repeat(64),remaining_ms:s.ttl??30000,splits:{DEVELOPMENT:1,VALIDATION:0,FROZEN_TEST:0},independent_benchmark_qualified:false});
    if(path==='/qualification-preparations/options')return json({software_cases:170,max_source_examples:1000,max_steps:3000,lifetime_ms:3600000,lease_ms:15000,page_size:20,image_evaluation_required:true,preparation_only:true,registry_sha256:'c'.repeat(64),implementation_sha256:'f'.repeat(64),qualification_eligible:false,promotion_eligible:false,physical_truth_verified:false,independent_benchmark_qualified:false});
    if(path==='/policy-qualifications/options')return json(options());
    if(path==='/policies/active')return json({policy:activeVersion?{id:P,revision:consumed?original.policy_revision:2,revision_sha256:consumed?original.policy_revision_sha256:'b'.repeat(64),name:'Synthetic active',mode:'deterministic_policy'}:null,
      active_version:s.fault==='stale'?activeVersion+1:activeVersion,current:activeVersion>0,current_qualification_verified:activeVersion>0,remaining_ms:s.ttl??30000,historical_head:activeVersion>0,inspection_enablement_granted:false,
      scope:url.searchParams.get('scope')==='owner'?'owner':'summary',...(url.searchParams.get('scope')==='owner'?{control_version:control,inspection_enabled:enabled,activation_id:activeVersion?(consumed?C:B):null,predecessor_activation_id:activeVersion?(consumed?B:A):null}:{})});
    if(path==='/policies/'+P&&r.method()==='GET')return json({...policy(url.searchParams.get('revision')==='1'),...(s.fault==='digest'?{revision_sha256:'f'.repeat(64)}:{})});
    if(path==='/qualification-preparations/'+PREP)return json({id:PREP,kind:'policy_qualification_preparation',policy_id:P,state_version:4,source_evaluation_id:SOURCE,source_report_sha256:'a'.repeat(64),report_sha256:'e'.repeat(64),report_current:s.fault==='prep'?'yes':true,source_current:true,
      status:'completed',qualification_status:'not_qualified',software_cases:170,planned_count:171,prepared_count:171,steps_reserved:171,lease_remaining_ms:0,counts:{software_pass:170,software_fail:0,source_entries_verified:1},blocking_reasons:['INDEPENDENT_EVIDENCE_REQUIRED'],can_advance:false,failure_reason:null,
      source_examples:1,remaining_ms:s.ttl??30000,physical_truth_verified:false,independent_benchmark_qualified:false,promotion_eligible:false,qualification_eligible:false});
    if(path==='/evaluations/'+SOURCE+'/request')return json(evaluation);
    if(path==='/evaluations/'+SOURCE)return json(comparison());
    if(path==='/policy-qualifications/'+Q+'/request')return json(original);
    if(path==='/policy-qualifications'&&r.method()==='GET')return json({qualifications:[{...record(),current:null,report_current:null,currency_not_checked:true}],scope:url.searchParams.get('scope'),next_cursor:null});
    if(path==='/policy-qualifications/'+Q+'/entries'){
      const start=Number(url.searchParams.get('start')),end=Math.min(start+20,mode==='candidate'?22:13);
      return json({id:Q,entries:Array.from({length:end-start},(_,i)=>{
        const n=start+i;if(s.fault==='page')return {index:n+1,phase:'installed_golden',passed:true,new_pixel_measurement:true,physical_truth_verified:false};
        if(mode==='installed_default'&&n===0)return {index:n,phase:'executed_installed_default_contracts',cases:170,passed:s.rejected?169:170,failed:s.rejected?1:0,software_report_sha256:'e'.repeat(64)};
        if(mode==='candidate'&&n<9)return {index:n,phase:'verified_preparation_page',start:n*20,entries:Array.from({length:Math.min(20,171-n*20)},(_,j)=>({index:n*20+j,sha256:'a'.repeat(64)})),passed:Math.min(20,170-n*20),failed:0};
        if(mode==='candidate'&&n===9)return {index:n,phase:'source_regression',source_index:0,source_entry_sha256:'a'.repeat(64),passed:true,unknown:false,physical_truth_verified:false};
        return {index:n,phase:'installed_golden',case_id:'golden-'+n,passed:true,new_pixel_measurement:true,physical_truth_verified:false,expected:{count:1},actual:{count:1}};
      }),next_index:end===(mode==='candidate'?22:13)?null:end,...flags});
    }
    if(path==='/policy-qualifications/'+Q+'/software-cases'){
      const start=Number(url.searchParams.get('start')),end=Math.min(start+20,170);return json({id:Q,cases:Array.from({length:end-start},(_,i)=>({id:'contract-'+(start+i-(s.fault==='repeatPage'&&start>=20?20:0)),status:s.rejected&&start+i===0?'FAIL':'PASS',expected:'PLACE_FLAT',actual:s.rejected&&start+i===0?'RECAPTURE':'PLACE_FLAT',reason:s.rejected&&start+i===0?'mismatch':null})),next_index:end===170?null:end,...flags});
    }
    if(path.startsWith('/policy-activations/')){
      const value=historical(path.split('/').at(-1)!);
      if(s.malformed==='legacy-receipt'&&path.endsWith(C))return json({...value,policy_state_version:null});
      if(s.malformed==='receipt'&&!malformed&&path.endsWith(C)){malformed=true;return json({...value,qualification_report_sha256:'a'.repeat(64)});}
      return json(value);
    }
    if(r.method()==='POST'){
      const body=r.postDataJSON(),key=r.headers()['idempotency-key'];writes.push({path,body,key,version:r.headers()['if-match']});
      let result=commits.get(key);
      const activation=path.startsWith('/policies/');
      if(!result){
        if(path==='/evaluations'||path==='/jobs/'+SOURCE+'/advance'){
          if(path==='/evaluations'){evaluation=body;evalComplete=false;evalVersion=1;}else{evalComplete=true;evalVersion++;}result=comparison();
        }else if(path==='/qualification-preparations'){
          result={id:PREP,kind:'policy_qualification_preparation',state_version:1,status:'queued',policy_id:P,source_evaluation_id:SOURCE,source_report_sha256:'a'.repeat(64),software_cases:170,source_examples:1,planned_count:171,prepared_count:0,steps_reserved:0,
            remaining_ms:30000,lease_remaining_ms:0,source_current:true,report_current:false,report_sha256:null,counts:null,can_advance:true,failure_reason:null,blocking_reasons:['INDEPENDENT_EVIDENCE_REQUIRED'],qualification_status:'not_qualified',qualification_eligible:false,promotion_eligible:false,physical_truth_verified:false,independent_benchmark_qualified:false};
        }else if(activation){
          if(body.expected_active_version!==activeVersion||body.expected_control_version!==control)return json({code:'CONFLICT'},409);
          activeVersion++;control++;enabled=false;consumed=true;result={transition_id:C,operation:body.operation,policy_id:P,policy_revision:body.policy_revision,active_version:activeVersion,control_version:control,activation_sha256:'f'.repeat(64),historical_receipt:true,inspection_enablement_granted:false};
        } else {
          if(path==='/policy-qualifications'){original=body;mode=body.mode;status='queued';work='queued';}
          else if(path.endsWith('/advance')){status='completed';work='complete';}else if(path.endsWith('/cancel'))status='cancelled';else if(path.endsWith('/retire'))status='retired';
          version++;result=record();
        }commits.set(key,result);
      }
      if(!lost&&s.lost===(activation?'activation':'qualification')){lost=true;return route.abort('failed');}
      if(s.malformed==='qualification'&&!malformed&&!activation){malformed=true;return json({...result,policy_revision_sha256:'f'.repeat(64)});}
      return json(result,path==='/policy-qualifications'?201:200);
    }
    if(path==='/policy-qualifications/'+Q)return json(record());
    return json({code:'RESOURCE_UNAVAILABLE'},403);
  });
  await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();await page.getByRole('button',{name:'Review and administration',exact:true}).click();
  return {writes,reads,errors,roles};
}
async function qualify(page:Page,mode='installed_default'){
  await page.getByRole('button',{name:'Policy qualification',exact:true}).click();
  if(mode==='candidate'){await page.getByLabel('Qualification mode',{exact:true}).selectOption('candidate');await page.getByLabel('Completed preparation ID',{exact:true}).fill(PREP);}
  else await page.getByLabel('Qualification candidate ID',{exact:true}).fill(P);
  await page.getByRole('button',{name:'Read qualification inputs',exact:true}).click();
}
async function createQualification(page:Page,confirmed=true){await page.getByRole('checkbox',{name:/I reviewed this exact complete plan/}).check();await page.getByRole('button',{name:'Create synthetic qualification',exact:true}).click();
  if(confirmed)await expect(page.locator('section[aria-labelledby="qualification-title"]').getByRole('status')).toContainText('Qualification operation recorded');}
async function readQualification(page:Page){await page.getByRole('button',{name:'Policy qualification',exact:true}).click();await page.getByLabel('Qualification job ID',{exact:true}).fill(Q);await page.getByRole('button',{name:'Read qualification job',exact:true}).click();}
async function activationPreview(page:Page,operation='bootstrap'){
  await page.getByRole('button',{name:'Policy activation',exact:true}).click();await page.getByLabel('Policy transition',{exact:true}).selectOption(operation);
  await page.getByLabel('Activation qualification job ID',{exact:true}).fill(Q);await page.getByRole('button',{name:'Review exact activation',exact:true}).click();
}
async function confirmActivation(page:Page){await page.getByRole('checkbox',{name:/I reviewed this exact decision/}).check();await page.getByRole('button',{name:'Confirm exact policy transition',exact:true}).click();}

test('reviewer completes qualification creation read step phases and all software pages without activation',async({page})=>{
  const state=await fixture(page);await qualify(page);await expect(page.getByRole('button',{name:'Create synthetic qualification'})).toBeDisabled();await createQualification(page);
  await page.getByRole('button',{name:'Read qualification job',exact:true}).click();await page.getByRole('button',{name:'Advance one qualification step'}).click();await page.getByRole('button',{name:'Read qualification job',exact:true}).click();
  await expect(page.getByText('Current synthetic report.',{exact:false})).toBeVisible();await page.getByRole('button',{name:'Read qualification phases'}).click();await expect(page.getByText(/Step 13: installed golden/)).toBeVisible();
  await page.getByRole('button',{name:'Read qualification software cases'}).click();for(let i=0;i<8;i++)await page.getByRole('button',{name:'Next qualification evidence page'}).click();
  await expect(page.getByText(/contract-169: PASS/)).toBeVisible();await expect(page.getByRole('button',{name:'Next qualification evidence page'})).toBeDisabled();
  expect(state.writes).toHaveLength(2);expect(state.writes[0].body.mode).toBe('installed_default');expect(state.writes[1].version).toBe('2');expect(state.errors).toEqual([]);
});
test('prepared candidate derives exact source and immutable preparation rather than editable assurance',async({page})=>{
  const state=await fixture(page);await qualify(page,'candidate');await createQualification(page);
  expect(state.writes[0].body).toMatchObject({mode:'candidate',policy_id:P,policy_revision:2,policy_state_version:2,preparation_id:PREP,preparation_state_version:4,preparation_report_sha256:'e'.repeat(64),synthetic_demo_acknowledged:true});
  expect(state.writes[0].body).not.toHaveProperty('qualified');expect(state.reads).toContain('GET /evaluations/'+SOURCE+'/request');
});
for(const lost of ['qualification','malformed'] as const)test('qualification preserves exact retry after '+lost,async({page})=>{
  const state=await fixture(page,lost==='qualification'?{lost}:{malformed:'qualification'});await qualify(page);await createQualification(page,false);
  await expect(page.getByRole('button',{name:'Retry unchanged qualification request'})).toBeEnabled();const original=state.writes[0];
  await page.getByRole('button',{name:'Historical comparisons',exact:true}).click();const leave=page.getByRole('alertdialog',{name:'Leave unconfirmed work?'});await expect(leave).toBeVisible();await leave.getByRole('button',{name:'Keep working here'}).click();
  await page.getByRole('button',{name:'Retry unchanged qualification request'}).click();await expect(page.getByRole('button',{name:'Retry unchanged qualification request'})).toHaveCount(0);expect(state.writes[1]).toEqual(original);
});
for(const role of ['operator','owner'] as const)test(role+' has no reviewer qualification creation',async({page})=>{
  const state=await fixture(page,{role});if(role==='operator')await expect(page.getByRole('button',{name:'Policy qualification',exact:true})).toHaveCount(0);
  else{await readQualification(page);await expect(page.getByRole('button',{name:'Create synthetic qualification'})).toHaveCount(0);await expect(page.getByRole('button',{name:'Read qualification phases'})).toHaveCount(0);}
  expect(state.writes).toEqual([]);
});
test('owner aggregates and combined nonoriginal grants never expose source detail controls',async({page})=>{
  await fixture(page,{role:'combined',complete:true,notOriginal:true});await readQualification(page);
  await expect(page.getByRole('button',{name:'Read qualification phases'})).toBeDisabled();await expect(page.getByRole('button',{name:'Read original qualification selectors'})).toBeDisabled();
});
for(const fault of ['counts','flag','registry','prep'] as const)test('qualification rejects malformed '+fault+' without another write',async({page})=>{
  const state=await fixture(page,{complete:true,fault});if(fault==='prep')await qualify(page,'candidate');else await readQualification(page);
  if(fault==='prep')await expect(page.getByRole('button',{name:'Create synthetic qualification'})).toBeDisabled();else await expect(page.getByRole('button',{name:'Read qualification phases'})).toHaveCount(0);
  expect(state.writes).toEqual([]);
});
test('qualification exposes rejected cases and explicit retirement without claiming physical validity',async({page})=>{
  const state=await fixture(page,{complete:true,rejected:true});await readQualification(page);await expect(page.getByText(/Recorded outcomes: 181 passed, 1 failed, 0 unknown/)).toBeVisible();
  await page.getByRole('button',{name:'Read qualification software cases'}).click();await expect(page.getByText(/contract-0: FAIL/)).toBeVisible();
  await expect(page.getByRole('button',{name:'Retire qualification report'})).toBeDisabled();await page.getByRole('checkbox',{name:/I understand stopping preserves history/}).check();await page.getByRole('button',{name:'Retire qualification report'}).click();
  await expect(page.getByText(/Qualification .*retired/)).toBeVisible();expect(state.writes.at(-1)?.body).toEqual({acknowledged:true,reason:'qualification-ended'});
});
test('qualification cancellation remains explicit and original selectors do not submit work',async({page})=>{
  const state=await fixture(page);await readQualification(page);await page.getByRole('button',{name:'Read original qualification selectors'}).click();expect(state.writes).toEqual([]);
  await page.getByRole('button',{name:'Read qualification job',exact:true}).click();await page.getByRole('checkbox',{name:/I understand stopping preserves history/}).check();await page.getByRole('button',{name:'Cancel qualification work'}).click();
  await expect(page.getByText(/Qualification .*cancelled/)).toBeVisible();expect(state.writes[0].path).toBe('/jobs/'+Q+'/cancel');
});
test('malformed qualification phase clears authority',async({page})=>{
  const state=await fixture(page,{complete:true,fault:'page'});await readQualification(page);await page.getByRole('button',{name:'Read qualification phases'}).click();
  await expect(page.getByRole('button',{name:'Read qualification phases'})).toHaveCount(0);expect(state.writes).toEqual([]);
});
for(const operation of ['bootstrap','promote','rollback'] as const)test('owner '+operation+' binds exact versions and inspects historical provenance',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true,operation});await activationPreview(page,operation);await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();await confirmActivation(page);
  await expect(page.getByLabel('Historical policy transition',{exact:true})).toBeVisible();expect(state.writes).toHaveLength(1);const sent=state.writes[0];
  expect(sent.version).toBe('2');expect(sent.body).toMatchObject({operation,expected_active_version:operation==='bootstrap'?0:2,expected_control_version:7,policy_state_version:2,qualification_id:Q,qualification_report_sha256:'d'.repeat(64),invalidation_acknowledged:true});
  if(operation==='rollback')expect(sent.body.predecessor_activation_id).toBe(A);else expect(sent.body).not.toHaveProperty('predecessor_activation_id');
  await page.getByRole('button',{name:'Read current owner policy context'}).click();await expect(page.getByText(/inspections enabled false/)).toBeVisible();expect(state.writes).toHaveLength(1);
});
for(const fault of ['held','counts','purpose','digest','stale'] as const)test('activation rejects '+fault+' before any transition',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true,operation:'rollback',fault});await activationPreview(page,'rollback');await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();expect(state.writes).toEqual([]);
});
for(const kind of ['lost','receipt'] as const)test('activation '+kind+' reply keeps exact decision and key through investigation',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true,operation:'promote',...(kind==='lost'?{lost:'activation' as const}:{malformed:'receipt' as const})});await activationPreview(page,'promote');await confirmActivation(page);
  await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toBeEnabled();const original=state.writes[0];await page.getByRole('button',{name:'Read current owner policy context'}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toBeVisible();await page.getByRole('button',{name:'Retry unchanged policy transition'}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toHaveCount(0);expect(state.writes[1]).toEqual(original);
});
test('reviewer cannot access activation and owner handoff makes no transition',async({page})=>{
  const state=await fixture(page,{role:'reviewer'});await expect(page.getByRole('button',{name:'Policy activation',exact:true})).toHaveCount(0);expect(state.writes).toEqual([]);
});
test('owner can read exact predecessor selectors without qualifying or activating',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true,operation:'rollback'});await page.getByRole('button',{name:'Policy activation',exact:true}).click();await page.getByRole('button',{name:'Read exact predecessor handoff'}).click();
  await expect(page.getByLabel('Exact rollback handoff',{exact:true})).toContainText(A);await expect(page.getByLabel('Exact rollback handoff',{exact:true})).toContainText('revision 1');expect(state.writes).toEqual([]);
});
test('editing or interrupting owner preview clears acknowledgment and is keyboard reachable',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true});await activationPreview(page);await page.getByRole('checkbox',{name:/I reviewed this exact decision/}).check();
  await page.getByLabel('Activation qualification job ID',{exact:true}).fill(A);await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();
  await page.getByLabel('Activation qualification job ID',{exact:true}).fill(Q);await page.getByRole('button',{name:'Review exact activation'}).click();
  await page.evaluate(()=>window.dispatchEvent(new Event('offline')));await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();
  await expect(page.getByLabel('Policy transition',{exact:true})).toBeEnabled();
  await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();
  await page.getByLabel('Policy transition',{exact:true}).focus();await expect(page.getByLabel('Policy transition',{exact:true})).toBeFocused();expect(state.writes).toEqual([]);
});
test('qualification creation authority expires without a write',async({page})=>{
  const state=await fixture(page,{ttl:3000,qMode:'candidate'});await qualify(page,'candidate');await page.getByRole('checkbox',{name:/I reviewed this exact complete plan/}).check();
  await expect(page.getByRole('button',{name:'Create synthetic qualification'})).toBeEnabled();await expect(page.getByRole('button',{name:'Create synthetic qualification'})).toBeDisabled();expect(state.writes).toEqual([]);
});
test('owner activation authority expires without a transition',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true,ttl:3000});await activationPreview(page);await page.getByRole('checkbox',{name:/I reviewed this exact decision/}).check();
  await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeEnabled();await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();expect(state.writes).toEqual([]);
});
test('failed owner reread invalidates an already acknowledged preview',async({page})=>{
  const settings:Settings={role:'owner',complete:true};const state=await fixture(page,settings);await activationPreview(page);await page.getByRole('checkbox',{name:/I reviewed this exact decision/}).check();
  await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeEnabled();settings.fault='held';await page.getByRole('button',{name:'Review exact activation'}).click();
  await expect(page.getByRole('button',{name:'Confirm exact policy transition'})).toBeDisabled();expect(state.writes).toEqual([]);
});
test('default rollback qualification freezes the exact owner handoff and old revision',async({page})=>{
  const state=await fixture(page,{operation:'rollback'});await page.getByRole('button',{name:'Policy qualification',exact:true}).click();
  await page.getByLabel('Qualification candidate ID',{exact:true}).fill(P);await page.getByLabel('Qualification candidate revision (blank for latest)',{exact:true}).fill('1');
  await page.getByRole('checkbox',{name:/Qualify the exact predecessor/}).check();await page.getByLabel('Rollback active version',{exact:true}).fill('2');await page.getByLabel('Rollback current activation ID',{exact:true}).fill(B);await page.getByLabel('Rollback predecessor activation ID',{exact:true}).fill(A);
  await page.getByRole('button',{name:'Read qualification inputs',exact:true}).click();await createQualification(page);
  expect(state.writes[0].body).toMatchObject({policy_revision:1,policy_state_version:2,rollback_target:{active_version:2,activation_id:B,predecessor_activation_id:A}});
});
test('prepared rollback carries original evaluation purpose and exposes all phases',async({page})=>{
  const state=await fixture(page,{operation:'rollback',qMode:'candidate',complete:true});await qualify(page,'candidate');await createQualification(page);
  expect(state.writes[0].body.rollback_target).toEqual({active_version:2,activation_id:B,predecessor_activation_id:A});await page.getByRole('button',{name:'Read qualification job',exact:true}).click();
  await page.getByRole('button',{name:'Advance one qualification step'}).click();await page.getByRole('button',{name:'Read qualification job',exact:true}).click();await page.getByRole('button',{name:'Read qualification phases'}).click();await page.getByRole('button',{name:'Next qualification evidence page'}).click();
  await expect(page.getByText(/Step 22: installed golden/)).toBeVisible();await expect(page.getByRole('button',{name:'Next qualification evidence page'})).toBeDisabled();
});
test('active lease blocks stepping but keeps authorized cancellation available',async({page})=>{
  const state=await fixture(page,{lease:5000});await readQualification(page);await expect(page.getByRole('button',{name:'Advance one qualification step'})).toBeDisabled();
  await page.getByRole('checkbox',{name:/I understand stopping preserves history/}).check();await page.getByRole('button',{name:'Cancel qualification work'}).click();await expect(page.getByText(/Qualification .*cancelled/)).toBeVisible();expect(state.writes[0].path).toBe('/jobs/'+Q+'/cancel');
});
test('owner cancels aggregate work without acquiring original reviewer access',async({page})=>{
  const state=await fixture(page,{role:'owner'});await readQualification(page);await expect(page.getByRole('button',{name:'Read original qualification selectors'})).toHaveCount(0);
  await page.getByRole('checkbox',{name:/I understand stopping preserves history/}).check();await page.getByRole('button',{name:'Cancel qualification work'}).click();await expect(page.getByText(/Qualification .*cancelled/)).toBeVisible();expect(state.writes).toHaveLength(1);
});
test('software pagination rejects a repeated prior case rather than hiding failures',async({page})=>{
  const state=await fixture(page,{complete:true,fault:'repeatPage'});await readQualification(page);await page.getByRole('button',{name:'Read qualification software cases'}).click();await expect(page.getByText(/contract-19: PASS/)).toBeVisible();
  await page.getByRole('button',{name:'Next qualification evidence page'}).click();await expect(page.getByRole('button',{name:'Read qualification software cases'})).toHaveCount(0);expect(state.writes).toEqual([]);
});
test('legacy unrecorded state cannot settle a new activation and explicit finish makes no second write',async({page})=>{
  const state=await fixture(page,{role:'owner',complete:true,malformed:'legacy-receipt'});await activationPreview(page);await confirmActivation(page);await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toBeEnabled();
  await page.getByLabel('Policy transition receipt ID',{exact:true}).fill(C);await page.getByRole('button',{name:'Read historical policy transition'}).click();await expect(page.getByLabel('Historical policy transition',{exact:true})).toContainText('not recorded');
  await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toBeEnabled();await page.getByRole('checkbox',{name:/I understand only local retry details are discarded/}).check();await page.getByRole('button',{name:'Finish without another policy transition'}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toHaveCount(0);expect(state.writes).toHaveLength(1);
});
test('owner role loss prevents the transition and still permits informed sign out',async({page})=>{
  const settings:Settings={role:'owner',complete:true};const state=await fixture(page,settings);await activationPreview(page);await expect(page.getByRole('checkbox',{name:/I reviewed this exact decision/})).toBeEnabled();settings.revoked=true;await confirmActivation(page);await expect(page.getByRole('button',{name:'Retry unchanged policy transition'})).toBeEnabled();expect(state.writes).toEqual([]);
  await page.getByRole('button',{name:'Sign out',exact:true}).click();const leave=page.getByRole('alertdialog',{name:'Leave unconfirmed work?'});await leave.getByRole('checkbox',{name:/I understand only local retry details/}).check();await leave.getByRole('button',{name:'Leave and investigate'}).click();
  await expect(page.getByText('Signed out of ProofPack.',{exact:true})).toBeVisible();expect(state.reads.filter(x=>x==='POST /auth/logout')).toHaveLength(1);expect(state.writes).toEqual([]);
});
test('refunded qualification reply remains unconfirmed instead of granting a fresh budget',async({page})=>{
  const state=await fixture(page,{lease:5000,fault:'refunded'});await readQualification(page);await page.getByRole('checkbox',{name:/I understand stopping preserves history/}).check();
  await page.getByRole('button',{name:'Cancel qualification work'}).click();await expect(page.getByRole('button',{name:'Retry unchanged qualification request'})).toBeEnabled();expect(state.writes).toHaveLength(1);
});
test('rollback image comparison carries the exact predecessor purpose without a console',async({page})=>{
  const state=await fixture(page,{operation:'rollback'});await page.getByRole('button',{name:'Historical comparisons',exact:true}).click();
  await page.getByRole('combobox',{name:'Comparison method',exact:true}).selectOption('vision_replay_v1');
  await expect(page.getByRole('checkbox',{name:'Compare the exact predecessor from an owner rollback handoff',exact:true})).toBeVisible();
  await page.getByRole('checkbox',{name:'Compare the exact predecessor from an owner rollback handoff',exact:true}).check();
  await page.getByLabel('Evaluation candidate ID',{exact:true}).fill(P);await page.getByLabel('Evaluation dataset ID',{exact:true}).fill(M);await page.getByLabel('Candidate recipe ID for image comparison',{exact:true}).fill(R);
  await page.getByLabel('Evaluation predecessor revision',{exact:true}).fill('1');await page.getByLabel('Evaluation rollback active version',{exact:true}).fill('2');await page.getByLabel('Evaluation current activation ID',{exact:true}).fill(B);await page.getByLabel('Evaluation predecessor activation ID',{exact:true}).fill(A);
  await page.getByRole('button',{name:'Read comparison inputs',exact:true}).click();await page.getByRole('checkbox',{name:/I reviewed these exact inputs/}).check();await page.getByRole('checkbox',{name:/I separately authorize fresh measurement/}).check();await page.getByRole('button',{name:'Create original-image comparison'}).click();
  await expect(page.locator('section[aria-labelledby="evaluation-title"]').getByRole('status')).toContainText('Evaluation operation recorded');
  expect(state.writes[0].body).toMatchObject({runner:'vision_replay_v1',policy_revision:1,policy_state_version:2,rollback_target:{active_version:2,activation_id:B,predecessor_activation_id:A}});
});
test('completed image handoff reaches preparation qualification and explicit owner rollback',async({page})=>{
  const state=await fixture(page,{role:'combined',qMode:'candidate',operation:'rollback'});
  await page.getByRole('button',{name:'Historical comparisons',exact:true}).click();await page.getByLabel('Evaluation ID',{exact:true}).fill(SOURCE);await page.getByRole('button',{name:'Read evaluation summary',exact:true}).click();
  await page.getByRole('button',{name:'Review preparation for this image comparison'}).click();await expect(page.getByLabel('Source evaluation ID',{exact:true})).toHaveValue(SOURCE);expect(state.writes).toEqual([]);
  await page.getByRole('button',{name:'Review preparation inputs',exact:true}).click();await page.getByRole('checkbox',{name:'I understand preparation does not qualify or activate the policy.',exact:true}).check();await page.getByRole('button',{name:'Create qualification preparation',exact:true}).click();
  await expect(page.getByText(/Preparation .*queued/)).toBeVisible();await page.getByRole('button',{name:'Read preparation summary',exact:true}).click();
  // The synthetic API worker has completed between explicit reads; no throughput or human-effort claim.
  await page.getByRole('button',{name:'Review synthetic qualification for this preparation'}).click();await expect(page.getByLabel('Completed preparation ID',{exact:true})).toHaveValue(PREP);expect(state.writes).toHaveLength(1);
  await page.getByRole('button',{name:'Read qualification inputs',exact:true}).click();await createQualification(page);await page.getByRole('button',{name:'Read qualification job',exact:true}).click();await page.getByRole('button',{name:'Advance one qualification step'}).click();await page.getByRole('button',{name:'Read qualification job',exact:true}).click();
  await page.getByRole('button',{name:'Review owner activation for this qualification'}).click();await expect(page.getByLabel('Activation qualification job ID',{exact:true})).toHaveValue(Q);expect(state.writes).toHaveLength(3);
  await page.getByLabel('Policy transition',{exact:true}).selectOption('rollback');await page.getByRole('button',{name:'Review exact activation',exact:true}).click();await confirmActivation(page);await expect(page.getByLabel('Historical policy transition',{exact:true})).toBeVisible();
  expect(state.writes).toHaveLength(4);expect(state.writes.at(-1)?.body).toMatchObject({operation:'rollback',qualification_id:Q,policy_revision:1,predecessor_activation_id:A});
});
test('qualification and owner decisions remain readable with keyboard zoom and forced colors',async({page})=>{
  const state=await fixture(page,{role:'combined',complete:true});await readQualification(page);await page.setViewportSize({width:800,height:900});await page.evaluate(()=>{document.documentElement.style.zoom='2';});await page.emulateMedia({forcedColors:'active'});
  await page.getByLabel('Qualification job ID',{exact:true}).focus();await expect(page.getByLabel('Qualification job ID',{exact:true})).toBeFocused();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1)).toBe(true);
  await activationPreview(page);await expect(page.getByRole('checkbox',{name:/I reviewed this exact decision/})).toBeEnabled();await page.getByLabel('Policy transition',{exact:true}).focus();await page.keyboard.press('Tab');await expect(page.getByLabel('Activation qualification job ID',{exact:true})).toBeFocused();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1)).toBe(true);expect(state.writes).toEqual([]);expect(state.errors).toEqual([]);
});
