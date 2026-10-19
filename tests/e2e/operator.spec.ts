/** Browser/API/stream fixtures only: no real login, camera, physical truth or AWS. */
import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import path from 'node:path';
import { createHash } from 'node:crypto';

const stationId='10000000-0000-4000-8000-000000000001', recipeId='20000000-0000-4000-8000-000000000001';
const inspectionId='30000000-0000-4000-8000-000000000001', actionId='40000000-0000-4000-8000-000000000001';

async function fixture(page: Page, options: { role?: string; action?: boolean; delay?: number; logoutFail?: boolean; geometryFail?: boolean; wide?: boolean; occupied?: boolean; decisionLost?: boolean; decisionDenied?: boolean; decisionMismatch?: boolean; holdPlayback?: boolean; originals?: boolean; originalMismatch?: boolean;
  correction?: 'overlap' | 'not_flat'; correctionFault?: 'observation' | 'crop' | 'outside' | 'space' | 'duplicate' | 'dimensions' | 'denied'; correctionExpiry?: number } = {}) {
  const measuredAssetId='a0000000-0000-4000-8000-000000000001', measuredObservationId='b0000000-0000-4000-8000-000000000001';
  if(options.correction)await page.bringToFront();
  const measuredBytes=options.correction ? Buffer.from(await page.evaluate(()=>{const canvas=document.createElement('canvas');canvas.width=600;canvas.height=300;
    const ctx=canvas.getContext('2d')!;ctx.fillStyle='white';ctx.fillRect(0,0,600,300);ctx.fillStyle='black';ctx.fillRect(40,50,100,40);return canvas.toDataURL('image/png').split(',')[1];}),'base64') : Buffer.alloc(0);
  const measuredSha=createHash('sha256').update(measuredBytes).digest('hex');
  const measuredRegion={candidate_index:0,box:[40,50,100,40],reason:options.correction,part_class:options.correction==='not_flat'?'bolt':null,
    aspect_ratio_interval:options.correction==='not_flat'?[3,4]:null};
  const measuredReference={schema_version:1,coordinate_space:'rectified_crop_v1',width:options.correctionFault==='dimensions'?599:600,height:300,
    observation_id:measuredObservationId,source_sha256:'c'.repeat(64),calibration_sha256:'d'.repeat(64),crop_sha256:measuredSha,basis_sha256:'e'.repeat(64),regions:[measuredRegion]};
  if(options.correctionFault==='observation')measuredReference.observation_id=inspectionId;
  if(options.correctionFault==='crop')measuredReference.crop_sha256='f'.repeat(64);
  if(options.correctionFault==='outside')measuredRegion.box=[590,50,100,40];
  if(options.correctionFault==='space')measuredReference.coordinate_space='live_preview';
  if(options.correctionFault==='duplicate')measuredReference.regions.push({...measuredRegion});
  let measuredDownloads=0;
  await page.addInitScript(({wide,holdPlayback}) => {
    const state={requests:0,stops:0,color:'#35483c',deny:false,pending:false,draws:0,drawnColor:'',drawnAt:0,playbacks:0};
    Object.assign(window,{fixtureCamera:state});
    const play=HTMLMediaElement.prototype.play;
    HTMLMediaElement.prototype.play=function(this:HTMLMediaElement){
      if(holdPlayback){state.playbacks++;return new Promise<void>(resolve=>Reflect.set(state,'releasePlayback',()=>resolve()));}
      return play.call(this);
    };
    Object.defineProperty(navigator.mediaDevices,'enumerateDevices',{value:async()=>[]});
    Object.defineProperty(navigator.mediaDevices,'getUserMedia',{value:async()=>{
      state.requests++;
      if(state.deny)throw new DOMException('fixture permission denied','NotAllowedError');
      if(state.pending)await new Promise<void>(resolve=>Reflect.set(state,'grantLate',resolve));
      const canvas=document.createElement('canvas');canvas.width=wide?800:640;canvas.height=480;
      let emit=()=>{};
      const draw=()=>{state.draws++;state.drawnColor=state.color;state.drawnAt=performance.now();const c=canvas.getContext('2d')!;c.fillStyle=state.color;c.fillRect(0,0,canvas.width,480);if(wide){c.fillStyle='#ff0000';c.fillRect(0,0,80,480);c.fillRect(720,0,80,480);}emit();};draw();
      const stream=canvas.captureStream(0);const track=stream.getVideoTracks()[0];const request=Reflect.get(track,'requestFrame');
      if(typeof request!=='function')throw new Error('Synthetic camera requires explicit frame emission support');
      emit=()=>request.call(track);emit();const timer=window.setInterval(draw,100);
      Reflect.set(state,'paint',draw);
      for(const track of stream.getTracks()){const stop=track.stop.bind(track);track.stop=()=>{state.stops++;window.clearInterval(timer);stop();};Reflect.set(state,'end',()=>track.dispatchEvent(new Event('ended')));}
      return stream;
    }});
    const fetch=window.fetch.bind(window);
    window.fetch=async(input,init)=>{
      if(init?.body instanceof FormData){const image=init.body.get('image');if(image instanceof Blob){
        const bitmap=await createImageBitmap(image);const canvas=document.createElement('canvas');canvas.width=bitmap.width;canvas.height=bitmap.height;
        const c=canvas.getContext('2d')!;c.drawImage(bitmap,0,0);
        Reflect.set(state,'uploadedFrame',{width:bitmap.width,height:bitmap.height,left:Array.from(c.getImageData(0,100,1,1).data),right:Array.from(c.getImageData(bitmap.width-1,100,1,1).data)});bitmap.close();
      }}
      return fetch(input,init);
    };
  },{wide:options.wide??false,holdPlayback:options.holdPlayback??false});
  const station={id:stationId,name:'Synthetic station',state_version:1,epoch:0,owner_session_id:(options.occupied?'other-session':null) as string|null,active_inspection_id:null as string|null,
    owned_by_current_session:false,calibration_profile_id:'synthetic-profile'};
  let state='CREATED', version=1, sequence=0, observations=0, uploads=0, acknowledgments=0, pause=false, fail=false;
  const decisionRequests: { key: string; body: unknown; version: string | undefined }[] = [];
  const originalSelections: boolean[] = [];
  const decisionResults = new Map<string, { id: string; inspection_id: string; inspection_state_version: number; decision: { id: string; inspection_id: string; disposition: string; reason: string; human_check_confirmed: boolean; machine_approval: false; independent_truth_verified: false; sha256: string } }>();
  let latestDecision: ReturnType<typeof decisionResults.get> = undefined, decisionWrites = 0;
  const result=()=>({id:inspectionId,station_id:stationId,state_version:version,effective_state:state,remaining_lease_ms:state==='PASSED_CURRENT'?900:0,
    last_observed_at:observations?Date.now():null,action:state==='ACTION_REQUIRED'?{id:actionId,kind:options.correction==='not_flat'?'PLACE_FLAT':'SEPARATE_REGION',message:'Separate the parts in the highlighted region, then recheck.',
      ...(options.correction?{observation_id:measuredObservationId,correction_reference_available:true}:{})}:null});
  await page.route('**/api/v1/**',async route=>{
    const request=route.request(), url=new URL(request.url()), pathname=url.pathname.slice('/api/v1'.length), method=request.method();
    const json=(value:unknown,status=200)=>route.fulfill({status,json:value});
    if(pathname==='/me')return json({id:'operator',display_name:'Fixture operator',roles:[options.role??'operator'],session_id:'session-fixture',csrf_token:'a'.repeat(43)});
    if(pathname==='/stations')return json({stations:[station],next_cursor:null});
    if(pathname==='/recipes')return json({recipes:[{id:recipeId,name:'Synthetic recipe'}],next_cursor:null});
    if(options.correction&&pathname===`/assets/${measuredAssetId}/download`){measuredDownloads++;
      if(options.correctionFault==='denied')return json({code:'ACCESS_DENIED'},403);
      return route.fulfill({status:200,body:measuredBytes,headers:{'content-type':'image/png','content-length':String(measuredBytes.length),
        'x-asset-id':measuredAssetId,'x-asset-state-version':'1','x-content-sha256':measuredSha,'x-evidence-binding-sha256':'b'.repeat(64),'x-evidence-historical':'true',
        'x-remaining-validity-ms':String(options.correctionExpiry??30000)}});}
    if(options.correction&&pathname===`/inspections/${inspectionId}/evidence`)return json({id:measuredAssetId,state_version:1,kind:'inspection_evidence',
      sha256:measuredSha,binding_sha256:'b'.repeat(64),byte_length:measuredBytes.length,content_type:'image/png',data_origin:'synthetic',remaining_validity_ms:options.correctionExpiry??30000,
      can_download:true,historical:true,machine_pass:false,storage_verified:false,derivation:'rectified_roi_jpeg',inspection_id:inspectionId,observation_id:measuredObservationId,correction_reference:measuredReference});
    if(pathname===`/inspections/${inspectionId}/evidence`)return json({id:'a0000000-0000-4000-8000-000000000001',state_version:1,kind:'inspection_evidence',
      sha256:'a'.repeat(64),binding_sha256:'b'.repeat(64),byte_length:20,content_type:'image/jpeg',data_origin:'synthetic',remaining_validity_ms:30000,
      can_download:true,historical:true,machine_pass:false,storage_verified:false});
    if(pathname===`/stations/${stationId}`)return json(station);
    if(pathname===`/stations/${stationId}/acquire`){expect(request.postDataJSON().expected_owner_session_id).toBe(options.occupied?'other-session':null);if(options.occupied){expect(request.postDataJSON().takeover_ack).toBe(true);expect(request.postDataJSON().reason).toBe('Agreed handoff');}station.epoch=1;station.state_version++;station.owner_session_id='session-fixture';station.owned_by_current_session=true;return json({current:station});}
    if(pathname==='/inspections'&&method==='POST'){expect(request.postDataJSON().kit_id).toBe('kit-1');station.active_inspection_id=inspectionId;station.state_version++;return json({inspection_id:inspectionId,state_version:1},201);}
    if(pathname===`/inspections/${inspectionId}`)return json(result());
    if(pathname.endsWith('/capture-context')){
      if(options.geometryFail)return json({code:'DEPENDENCY_UNAVAILABLE'},503);
      return json({context_version:1,capture_transform:'center_crop_resize_no_upscale',inspection_id:inspectionId,
        recipe_name:'Synthetic recipe',recipe_revision:1,data_origin:'synthetic',policy_mode:'deterministic_policy',camera_label:'Fixture camera',
        frame_width:320,frame_height:240,work_polygon:[[.1,.1],[.9,.1],[.9,.9],[.1,.9]],constraints:[{constraint_id:'washers',part_class_id:'washers',expected_count:1}],remaining_context_ms:60000,
        ...(options.originals ? {original_capture_retention_allowed:true,original_capture_remaining_attempts:3-originalSelections.filter(Boolean).length} : {})});
    }
    if(pathname.endsWith('/prepare-capture'))return json({ready:true,inspection_state_version:version});
    if(pathname.endsWith('/capture-permits')){expect(Number(request.headers()['if-match'])).toBe(version);version++;sequence++;
      const selected=request.postDataJSON().retain_original_frame===true;originalSelections.push(selected);
      return json({permit_id:actionId,nonce:'a'.repeat(43),sequence,inspection_state_version:version,usable:true,
        ...(selected&&!options.originalMismatch?{retain_original_frame:true}:{})},201);}
    if(pathname.endsWith('/observations')){
      if(fail)return route.abort('failed');
      uploads++;expect(request.headers()['content-type']).toContain('multipart/form-data; boundary=');
      expect(Number(request.headers()['if-match'])).toBe(version);
      const bytes=request.postDataBuffer()!;expect(bytes.includes(Buffer.from('capture.jpg'))).toBeTruthy();expect(bytes.includes(Buffer.from([255,216,255]))).toBeTruthy();
      if(options.delay||pause)await new Promise(resolve=>setTimeout(resolve,options.delay??1100));
      observations++;version++;state=(options.action||options.correction)&&acknowledgments===0?'ACTION_REQUIRED':observations>=3||options.delay?'PASSED_CURRENT':'OBSERVING';
      return json({observation_id:inspectionId,sequence,operation_status:'completed',replayed:false,measurement:{findings:[state==='ACTION_REQUIRED'?'UNOBSERVABLE':'SATISFIED']},status:result()});
    }
    if(pathname.endsWith('/dispositions/latest'))return json({inspection_id:inspectionId,decision:latestDecision?.decision??null,
      current_disposition:latestDecision?.decision.disposition??null,historical:true,machine_approval:false,inspection_state_version:version});
    if(pathname.endsWith('/dispositions')){
      const key=request.headers()['idempotency-key'], body=request.postDataJSON();decisionRequests.push({key,body,version:request.headers()['if-match']});
      if(options.decisionDenied)return json({detail:'Denied'},403);
      const existing=decisionResults.get(key);if(existing)return json(existing,201);
      expect(Number(request.headers()['if-match'])).toBe(version);decisionWrites++;version++;
      const id='70000000-0000-4000-8000-'+String(decisionWrites).padStart(12,'0');
      const decision={id,inspection_id:inspectionId,disposition:body.disposition as string,reason:body.reason as string,human_check_confirmed:body.human_check_confirmed as boolean,
        machine_approval:false as const,independent_truth_verified:false as const,sha256:'e'.repeat(64)};
      latestDecision={id,inspection_id:inspectionId,inspection_state_version:version,decision};decisionResults.set(key,latestDecision);
      if(options.decisionLost&&decisionWrites===1)return route.abort('failed');
      return json(options.decisionMismatch?{...latestDecision,decision:{...decision,reason:'Different server decision'}}:latestDecision,201);
    }
    if(pathname.endsWith(`/actions/${actionId}/complete`)){acknowledgments++;version++;state='OBSERVING';return json(result());}
    if(pathname.endsWith('/close')){expect(request.postDataJSON().reason).toBeTruthy();state='CLOSED';station.active_inspection_id=null;station.epoch++;station.state_version++;return json({current:station});}
    if(pathname.endsWith('/release')){station.owner_session_id=null;station.owned_by_current_session=false;station.active_inspection_id=null;station.epoch++;station.state_version++;return json({current:station});}
    if(pathname==='/auth/logout')return options.logoutFail?route.abort('failed'):route.fulfill({status:204});
    throw new Error(`Unexpected fixture API request: ${method} ${pathname}`);
  });
  return {originalSelections,get measuredDownloads(){return measuredDownloads;},get decisionWrites(){return decisionWrites;},decisionRequests,get uploads(){return uploads;},get acknowledgments(){return acknowledgments;},pauseReplies(){pause=true;},failReplies(){fail=true;}};
}

async function openKit(page:Page) {
  await page.bringToFront();await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();
  await page.getByRole('button',{name:'Load stations and recipes'}).click();
  await page.getByRole('combobox',{name:'Station',exact:true}).selectOption(stationId);await page.getByRole('combobox',{name:'Approved recipe',exact:true}).selectOption(recipeId);
  await page.getByLabel('Opaque kit reference').fill('kit-1');await page.getByRole('button',{name:'Acquire station',exact:true}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Station acquired');
  await page.getByRole('button',{name:'Start kit inspection',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Synthetic recipe · revision 1'})).toBeVisible();
}
async function startChecks(page:Page){
  await page.getByRole('button',{name:'Start camera preview'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Preview only');
  await page.getByLabel('I checked the full transmitted area',{exact:false}).check();
  await page.getByRole('button',{name:'Start fresh checks'}).click();
}

async function openMeasuredReference(page:Page) {
  await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Action required',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Open measured correction reference (stops camera)',exact:true}).click();
  await expect(page.getByText('Camera stopped. No capture preview.',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Load measured correction reference',exact:true}).click();
}

for(const correction of ['overlap','not_flat'] as const) {
  test(`measured ${correction} reference stops camera and fresh checks remain separate from acknowledgment`,async({page})=>{
    const calls=await fixture(page,{correction});await openMeasuredReference(page);
    expect(calls.measuredDownloads).toBe(0);expect(calls.uploads).toBe(1);
    await expect.poll(()=>page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBe(1);
    await page.getByRole('button',{name:'View retained image',exact:true}).click();
    const image=page.getByRole('img',{name:'Retained historical evidence; not a current inspection result',exact:true});await expect(image).toBeVisible();
    expect(calls.measuredDownloads).toBe(1);await expect(page.locator('.measured-reference svg')).toHaveAttribute('viewBox','0 0 600 300');
    await expect(page.locator('.measured-reference .region-line')).toHaveAttribute('x','40');
    await expect(page.locator('.measured-reference .region-line')).toHaveAttribute('width','100');
    await expect(page.getByText(correction==='overlap'?/Region 1: Unclassified connected region/:/Region 1: bolt projection/)).toBeVisible();
    if(correction==='not_flat')await expect(page.getByText(/3D pose was not measured/)).toBeVisible();
    await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0);
    await page.getByRole('button',{name:'Acknowledge correction completed',exact:true}).click();
    expect(calls.acknowledgments).toBe(1);await expect(image).toHaveCount(0);
    await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('not a pass');
    expect(calls.uploads).toBe(1);await startChecks(page);
    await expect.poll(()=>calls.uploads).toBeGreaterThan(1);
  });
}

for(const correctionFault of ['observation','crop','outside','space','duplicate'] as const) {
  test(`measured reference with ${correctionFault} mismatch is withheld before download`,async({page})=>{
    const calls=await fixture(page,{correction:'overlap',correctionFault});await openMeasuredReference(page);
    await expect(page.getByRole('button',{name:'View retained image',exact:true})).toHaveCount(0);
    await expect(page.getByRole('status').filter({hasText:/mismatched|unavailable/})).toHaveCount(1);
    expect(calls.measuredDownloads).toBe(0);expect(calls.acknowledgments).toBe(0);
    await expect(page.locator('.measured-reference')).toHaveCount(0);
  });
}

for(const correctionFault of ['dimensions','denied'] as const) {
  test(`measured reference with ${correctionFault} download is never rendered`,async({page})=>{
    const calls=await fixture(page,{correction:'overlap',correctionFault});await openMeasuredReference(page);
    await page.getByRole('button',{name:'View retained image',exact:true}).click();
    await expect(page.getByRole('status').filter({hasText:correctionFault==='dimensions'?/dimensions/:/cannot perform this action/})).toHaveCount(1);
    expect(calls.measuredDownloads).toBe(1);await expect(page.locator('.measured-reference')).toHaveCount(0);
    await expect(page.getByRole('button',{name:'View retained image',exact:true})).toHaveCount(0);
  });
}

for(const interruption of ['offline','hidden','expiry','clear','restart'] as const) {
  test(`measured historical reference clears on ${interruption}`,async({page})=>{
    const calls=await fixture(page,{correction:'overlap',...(interruption==='expiry'?{correctionExpiry:1500}:{})});await openMeasuredReference(page);
    await page.getByRole('button',{name:'View retained image',exact:true}).click();
    const image=page.getByRole('img',{name:'Retained historical evidence; not a current inspection result',exact:true});await expect(image).toBeVisible();
    if(interruption==='offline')await page.evaluate(()=>window.dispatchEvent(new Event('offline')));
    if(interruption==='hidden')await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});
    if(interruption==='clear')await page.getByRole('button',{name:'Clear retained image or cancel read',exact:true}).click();
    if(interruption==='restart')await page.getByRole('button',{name:'Start camera preview',exact:true}).click();
    await expect(image).toHaveCount(0);expect(calls.acknowledgments).toBe(0);expect(calls.uploads).toBe(1);
  });
}

test('measured reference has text targets and keyboard controls at narrow zoom and forced colors',async({page})=>{
  await fixture(page,{correction:'not_flat'});await page.setViewportSize({width:650,height:900});await page.emulateMedia({forcedColors:'active'});
  await openMeasuredReference(page);const view=page.getByRole('button',{name:'View retained image',exact:true});await view.focus();await page.keyboard.press('Enter');
  await expect(page.getByText(/Region 1: bolt projection/)).toBeVisible();
  const layout=await page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
    overflow:[...document.querySelectorAll('main *')].map(el=>({tag:el.tagName,cls:el.className,box:el.getBoundingClientRect().toJSON()})).filter(el=>el.box.right>innerWidth+1||el.box.left<0).slice(0,14)}));
  expect(layout.scrollWidth<=layout.width,JSON.stringify(layout)).toBe(true);
  const clear=page.getByRole('button',{name:'Clear retained image or cancel read',exact:true});await clear.focus();await page.keyboard.press('Enter');
  await expect(page.locator('.measured-reference')).toHaveCount(0);await expect(clear).toBeFocused();
});

test('original selection is one attempt only and interruption clears the next choice',async({page})=>{
  const state=await fixture(page,{originals:true});await openKit(page);
  const choice=page.getByRole('checkbox',{name:'Retain the next original transmitted image once for operational review'});
  await expect(choice).not.toBeChecked();await expect(choice).toBeDisabled();
  await page.getByRole('button',{name:'Start camera preview'}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Preview only');
  await choice.check();await page.getByLabel('I checked the full transmitted area',{exact:false}).check();
  await page.getByRole('button',{name:'Start fresh checks'}).click();
  await expect.poll(()=>state.originalSelections.length).toBeGreaterThanOrEqual(3);
  expect(state.originalSelections[0]).toBe(true);expect(state.originalSelections.slice(1).every(value=>value===false)).toBe(true);
  await expect(choice).not.toBeChecked();await expect(page.getByText(/Original attempts remaining: 2 of at most 3/)).toBeVisible();
  await page.getByRole('button',{name:'Stop camera and checks'}).click();
  await page.getByRole('button',{name:'Start camera preview'}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Preview only');
  await choice.check();await page.getByRole('button',{name:'Stop camera and checks'}).click();await expect(choice).not.toBeChecked();await expect(choice).toBeDisabled();
});

test('original selection without a matching permit acknowledgment stops before image upload',async({page})=>{
  const state=await fixture(page,{originals:true,originalMismatch:true});await openKit(page);
  await page.getByRole('button',{name:'Start camera preview'}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Preview only');
  const choice=page.getByRole('checkbox',{name:'Retain the next original transmitted image once for operational review'});
  await choice.check();await page.getByLabel('I checked the full transmitted area',{exact:false}).check();await page.getByRole('button',{name:'Start fresh checks'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Original retention was not confirmed');
  expect(state.originalSelections).toEqual([true]);expect(state.uploads).toBe(0);await expect(choice).not.toBeChecked();
});

test('entering same-inspection support stops the camera and seeds no automatic request',async({page})=>{
  const f=await fixture(page);await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Request support for this inspection',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Support handoff',exact:true})).toBeVisible();
  await expect(page.getByLabel('Support inspection ID',{exact:true})).toHaveValue(inspectionId);
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  const uploaded=f.uploads;await expect(page.getByRole('button',{name:'Request designated review support',exact:true})).toBeDisabled();expect(f.uploads).toBe(uploaded);
});

test('switching to review stops the camera and preserves the open inspection',async({page})=>{
  await fixture(page);await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Review and administration',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Review and administration',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  await page.getByRole('button',{name:'Return to inspections'}).click();
  await page.getByRole('button',{name:'Load stations and recipes'}).click();
  await page.getByRole('combobox',{name:'Station',exact:true}).selectOption(stationId);
  await expect(page.getByRole('button',{name:'Resume my inspection'})).toBeVisible();
});

test('camera playback timeout releases startup without uploading or trusting late playback',async({page})=>{
  const calls=await fixture(page,{holdPlayback:true});await openKit(page);await page.getByRole('button',{name:'Start camera preview'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Camera playback did not start.',{timeout:2000});
  await expect(page.getByRole('button',{name:'Start camera preview'})).toBeEnabled();
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  await page.evaluate(()=>Reflect.get(window,'fixtureCamera').releasePlayback());
  await expect(page.getByRole('button',{name:'Start fresh checks'})).toBeDisabled();expect(calls.uploads).toBe(0);
});

for(const mode of ['stop','hidden'])test('pending camera playback is cancelable by '+mode,async({page})=>{
  const calls=await fixture(page,{holdPlayback:true});await openKit(page);await page.getByRole('button',{name:'Start camera preview'}).click();
  await expect.poll(()=>page.evaluate(()=>Reflect.get(window,'fixtureCamera').playbacks)).toBe(1);
  if(mode==='stop')await page.getByRole('button',{name:'Stop camera and checks'}).click();
  else await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));});
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText(mode==='stop'?'Camera stopped.':'Page hidden.');
  await expect(page.getByRole('button',{name:'Start camera preview'})).toBeEnabled({timeout:2000});
  await expect(page.getByRole('button',{name:'Start fresh checks'})).toBeDisabled();expect(calls.uploads).toBe(0);
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
});

test('operator completes a fixture kit, then stops, closes, releases and signs out',async({page})=>{
  await page.setViewportSize({width:1920,height:1080});
  const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message));const calls=await fixture(page);await openKit(page);
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').requests)).toBe(0);expect(calls.uploads).toBe(0);
  await startChecks(page);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  await page.screenshot({path:path.resolve(__dirname,'../../evidence/local/operator-fixture-desktop.png'),fullPage:true});
  await page.getByRole('button',{name:'Stop camera and checks'}).click();
  await expect(page.getByRole('heading',{name:'Recheck required — no current approval'})).toBeVisible();
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('human_accepted');
  await page.getByLabel('Handoff / close reason').fill('Manual check complete');
  await page.getByRole('button',{name:'Close kit inspection',exact:true}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Inspection closed');
  await page.getByRole('button',{name:'Release station',exact:true}).click();
  await page.getByRole('button',{name:'Sign out',exact:true}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Signed out of ProofPack');expect(errors).toEqual([]);
});

test('correction acknowledgment never becomes approval',async({page})=>{
  const calls=await fixture(page,{action:true});await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Action required',exact:true})).toBeVisible();expect(calls.uploads).toBe(1);
  await page.getByRole('button',{name:'Acknowledge correction completed'}).click();
  expect(calls.acknowledgments).toBe(1);await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0);
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('not a pass');
});

test('owner-only account does not receive operator controls',async({page})=>{
  await fixture(page,{role:'owner'});await page.bringToFront();await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('no operator grant');await expect(page.getByRole('button',{name:'Start kit inspection',exact:true})).toHaveCount(0);
});

test('permission denial and missing geometry block capture without replacing work',async({page})=>{
  const calls=await fixture(page);await openKit(page);await page.evaluate(()=>Reflect.get(window,'fixtureCamera').deny=true);
  await page.getByRole('button',{name:'Start camera preview'}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Camera permission denied');
  expect(calls.uploads).toBe(0);await expect(page.getByRole('button',{name:'Start fresh checks'})).toBeDisabled();
  await page.evaluate(()=>Reflect.get(window,'fixtureCamera').deny=false);await startChecks(page);await expect.poll(()=>calls.uploads).toBeGreaterThan(0);
});

test('late pass response cannot renew a lease and offline logout remains unconfirmed',async({page})=>{
  await fixture(page,{delay:1100,logoutFail:true});await openKit(page);await startChecks(page);
  await expect(page.getByText('Last observation findings',{exact:true})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Server sign-out is unconfirmed');
  await expect(page.getByRole('button',{name:'Retry sign out',exact:true})).toBeVisible();expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
});

test('hidden page clears approval and stops the fixture stream',async({page})=>{
  await fixture(page);await openKit(page);await startChecks(page);await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'hidden'});document.dispatchEvent(new Event('visibilitychange'));});
  await expect(page.getByRole('heading',{name:'Recheck required — no current approval'})).toBeVisible();
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
});

test('changed preview clears current approval before a delayed new result',async({page},testInfo)=>{
  const calls=await fixture(page);await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  calls.pauseReplies();await page.evaluate(()=>{const state=Reflect.get(window,'fixtureCamera');state.color='#b48359';state.paint();});
  // A requested canvas color is not yet a presented camera frame. Diagnose delivery
  // separately, then retain the 500 ms approval-withdrawal bound for the changed preview.
  try { await expect.poll(()=>page.evaluate(()=>{
    const video=document.querySelector('video')!;const canvas=document.createElement('canvas');canvas.width=2;canvas.height=2;
    const c=canvas.getContext('2d',{willReadFrequently:true})!;c.drawImage(video,0,0,2,2);const pixel=c.getImageData(0,0,1,1).data;
    return Math.abs(pixel[0]-180)<6&&Math.abs(pixel[1]-131)<6&&Math.abs(pixel[2]-89)<6;
  }),{timeout:750,message:'Synthetic changed frame must actually reach the video preview'}).toBe(true);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0,{timeout:500}); }
  catch(error) {
    await testInfo.attach('scene-frame-diagnostic',{contentType:'application/json',body:JSON.stringify(await page.evaluate(()=>{
      const video=document.querySelector('video')!;const canvas=document.createElement('canvas');canvas.width=2;canvas.height=2;
      const c=canvas.getContext('2d',{willReadFrequently:true})!;c.drawImage(video,0,0,2,2);
      return {fixture:Reflect.get(window,'fixtureCamera'),now:performance.now(),video:{time:video.currentTime,paused:video.paused,ready:video.readyState,quality:video.getVideoPlaybackQuality()},pixel:Array.from(c.getImageData(0,0,1,1).data),visibility:document.visibilityState};
    }))});throw error;
  }
  await page.getByRole('button',{name:'Stop camera and checks'}).click();
});

test('camera loss and failed transport stop capture without a replacement inspection',async({page})=>{
  const calls=await fixture(page);await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  await page.evaluate(()=>Reflect.get(window,'fixtureCamera').end());
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Camera ended');
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Refresh inspection status'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Review expected contents');
  calls.failReplies();await startChecks(page);
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Connection unavailable');
  await expect(page.getByRole('button',{name:'Start kit inspection',exact:true})).toBeDisabled();
});

test('keyboard can select and acquire a station with visible focus',async({page})=>{
  await fixture(page);await page.bringToFront();await page.goto('/');
  await page.getByRole('button',{name:'Open invited workspace'}).click();
  await expect(page.getByRole('heading',{name:'Operator workspace',exact:true})).toBeFocused();
  await expect(page.getByRole('button',{name:'Load stations and recipes'})).toBeVisible();
  await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Sign out',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'Review and administration',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');await page.keyboard.press('Enter');
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Choose the approved station');
  await page.keyboard.press('Tab');await expect(page.getByRole('combobox',{name:'Station',exact:true})).toBeFocused();await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Tab');await expect(page.getByRole('combobox',{name:'Approved recipe',exact:true})).toBeFocused();await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Tab');await page.keyboard.type('kit-1');await page.keyboard.press('Tab');
  await expect(page.getByRole('button',{name:'Acquire station',exact:true})).toBeFocused();await page.keyboard.press('Enter');
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Station acquired');
});

test('uploaded JPEG uses enrolled dimensions and excludes pixels outside centered crop',async({page})=>{
  const calls=await fixture(page,{wide:true});await openKit(page);await startChecks(page);await expect.poll(()=>calls.uploads).toBeGreaterThan(0);
  const image=await page.evaluate(()=>Reflect.get(window,'fixtureCamera').uploadedFrame);
  expect([image.width,image.height]).toEqual([320,240]);
  // The 800x480 source has red 80px sidebars. The approved 4:3 crop excludes both.
  expect(image.left[0]).toBeLessThan(100);expect(image.right[0]).toBeLessThan(100);
  expect(image.left[1]).toBeGreaterThan(40);expect(image.right[1]).toBeGreaterThan(40);
  await page.getByRole('button',{name:'Stop camera and checks'}).click();
});

test('occupied station requires explicit handoff acknowledgment and reason',async({page})=>{
  await fixture(page,{occupied:true});await page.bringToFront();await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();
  await page.getByRole('button',{name:'Load stations and recipes'}).click();await page.getByRole('combobox',{name:'Station',exact:true}).selectOption(stationId);
  await expect(page.getByRole('button',{name:'Acquire station',exact:true})).toBeDisabled();
  await page.getByRole('checkbox',{name:/I have arranged this station handoff/}).check();
  await expect(page.getByRole('button',{name:'Acquire station',exact:true})).toBeDisabled();await page.getByLabel('Handoff / close reason').fill('Agreed handoff');
  await page.getByRole('button',{name:'Acquire station',exact:true}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Station acquired');
});

test('a denied correction stops preview and changed grants cannot restart the camera',async({page})=>{
  await fixture(page,{action:true});await openKit(page);await startChecks(page);
  await expect(page.getByRole('heading',{name:'Action required',exact:true})).toBeVisible();
  await page.route('**/api/v1/inspections/**/actions/**/complete',route=>route.fulfill({status:403,json:{code:'ACCESS_DENIED'}}));
  await page.getByRole('button',{name:'Acknowledge correction completed'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('cannot perform');
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  const before=await page.evaluate(()=>Reflect.get(window,'fixtureCamera').requests);
  await page.route('**/api/v1/me',route=>route.fulfill({json:{roles:['reviewer'],session_id:'session-fixture'}}));
  await page.getByRole('button',{name:'Start camera preview'}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('operator session changed');
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').requests)).toBe(before);
});

test('stop cancels a pending permission wait and closes a late camera grant',async({page})=>{
  const calls=await fixture(page);await openKit(page);await page.evaluate(()=>Reflect.get(window,'fixtureCamera').pending=true);
  await page.getByRole('button',{name:'Start camera preview'}).click();
  await expect.poll(()=>page.evaluate(()=>Reflect.get(window,'fixtureCamera').requests)).toBe(1);
  await page.getByRole('button',{name:'Stop camera and checks'}).click();
  await expect(page.getByRole('button',{name:'Sign out',exact:true})).toBeEnabled();
  await page.evaluate(()=>Reflect.get(window,'fixtureCamera').grantLate());
  await expect.poll(()=>page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  expect(calls.uploads).toBe(0);await expect(page.getByRole('button',{name:'Start fresh checks'})).toBeDisabled();
});

test('missing geometry preserves status and supports close; keyboard, zoom and contrast layout',async({page})=>{
  await fixture(page,{geometryFail:true});await page.setViewportSize({width:1366,height:768});await page.emulateMedia({forcedColors:'active',reducedMotion:'reduce'});
  await page.bringToFront();await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();await page.getByRole('button',{name:'Load stations and recipes'}).click();
  await page.getByRole('combobox',{name:'Station',exact:true}).selectOption(stationId);await page.getByRole('combobox',{name:'Approved recipe',exact:true}).selectOption(recipeId);await page.getByLabel('Opaque kit reference').fill('kit-1');
  await page.getByRole('button',{name:'Acquire station',exact:true}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Station acquired');
  await page.getByRole('button',{name:'Start kit inspection',exact:true}).click();await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('unavailable');
  await expect(page.getByRole('button',{name:'Refresh inspection status'})).toBeVisible();await expect(page.getByRole('button',{name:'Start camera preview'})).toHaveCount(0);
  await page.evaluate(()=>{document.documentElement.style.zoom='2';});await page.keyboard.press('Tab');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBeTruthy();
  await page.screenshot({path:path.resolve(__dirname,'../../evidence/local/operator-missing-geometry-zoom.png'),fullPage:true});
});


test('operator opens latest retained evidence with camera stopped and the same inspection preserved',async({page})=>{
  await fixture(page);await openKit(page);
  try { await startChecks(page); }
  catch(error) {
    const diagnostic=await page.evaluate(()=>{const v=document.querySelector('video')!;return {visibility:document.visibilityState,scrollY,viewport:[innerWidth,innerHeight],video:{box:v.getBoundingClientRect().toJSON(),readyState:v.readyState,currentTime:v.currentTime,paused:v.paused},camera:Reflect.get(window,'fixtureCamera')};});
    await test.info().attach('camera-frame-diagnostic',{body:JSON.stringify(diagnostic),contentType:'application/json'});throw error;
  }
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Review latest retained evidence',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Retained evidence',exact:true})).toBeVisible();
  await expect(page.getByRole('textbox',{name:'Inspection ID for latest evidence',exact:true})).toHaveValue(inspectionId);
  expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  await page.getByRole('button',{name:'Load latest inspection evidence',exact:true}).click();
  await expect(page.getByRole('textbox',{name:'Retained asset ID',exact:true})).toHaveValue('a0000000-0000-4000-8000-000000000001');
  await page.getByRole('button',{name:'Return to inspections'}).click();await page.getByRole('button',{name:'Load stations and recipes'}).click();
  await page.getByRole('combobox',{name:'Station',exact:true}).selectOption(stationId);await expect(page.getByRole('button',{name:'Resume my inspection'})).toBeVisible();
});


test('operator records separate human handling, stops capture and reads immutable history',async({page})=>{
  const calls=await fixture(page);await openKit(page);await page.getByRole('button',{name:'Start camera preview',exact:true}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('Preview only');
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('rework');
  await page.getByLabel('Handoff / close reason').fill('Manual missing-part review');await page.getByRole('button',{name:'Record separate human decision',exact:true}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('Recorded historical human decision: rework');
  expect(calls.decisionWrites).toBe(1);expect(await page.evaluate(()=>Reflect.get(window,'fixtureCamera').stops)).toBeGreaterThan(0);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Read latest human decision'}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('Latest separately recorded historical decision: rework');
});

test('human acceptance requires an explicit full-kit check and corrections remain human history',async({page})=>{
  const calls=await fixture(page);await openKit(page);
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('human_accepted');
  await page.getByLabel('Handoff / close reason').fill('Entire kit checked manually');
  await expect(page.getByRole('button',{name:'Record separate human decision',exact:true})).toBeDisabled();
  await page.getByLabel('I completed a manual check of the entire kit.',{exact:false}).check();
  await page.getByLabel('Handoff / close reason').fill('Entire kit checked manually after final review');
  await expect(page.getByRole('button',{name:'Record separate human decision',exact:true})).toBeDisabled();
  await page.getByLabel('I completed a manual check of the entire kit.',{exact:false}).check();
  await page.getByRole('button',{name:'Record separate human decision',exact:true}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('human accepted');
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('reject');
  await page.getByLabel('Handoff / close reason').fill('Revised manual decision');await page.getByRole('button',{name:'Record separate human decision',exact:true}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('Recorded historical human decision: reject');
  expect(calls.decisionWrites).toBe(2);expect(calls.decisionRequests[0].key).not.toBe(calls.decisionRequests[1].key);
  await expect(page.getByRole('heading',{name:'Visible checks passed — current observation',exact:true})).toHaveCount(0);
});

test('lost human-decision confirmation freezes intent and retries without another effect',async({page})=>{
  const calls=await fixture(page,{decisionLost:true});await openKit(page);
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('rework');await page.getByLabel('Handoff / close reason').fill('Uncertain manual handling');
  await page.getByRole('button',{name:'Record separate human decision',exact:true}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('outcome is unconfirmed');
  await expect(page.getByLabel('Handoff / close reason')).toBeDisabled();await expect(page.getByRole('button',{name:'Close kit inspection',exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Review latest retained evidence'})).toBeDisabled();
  await page.getByRole('button',{name:'Read latest human decision'}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('Latest separately recorded historical decision: rework');
  await page.getByRole('button',{name:'Retry unchanged human decision'}).click();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('Recorded historical human decision: rework');
  expect(calls.decisionWrites).toBe(1);expect(calls.decisionRequests).toHaveLength(2);expect(calls.decisionRequests[0]).toEqual(calls.decisionRequests[1]);
  await expect(page.getByLabel('Handoff / close reason')).toBeEnabled();
});

test('denied human-decision write does not show a successful decision or machine approval',async({page})=>{
  const calls=await fixture(page,{decisionDenied:true});await openKit(page);
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('reject');await page.getByLabel('Handoff / close reason').fill('Manual rejection');
  await page.getByRole('button',{name:'Record separate human decision',exact:true}).click();
  await expect(page.getByRole('status',{name:'Workspace message'})).toContainText('cannot perform this action');expect(calls.decisionWrites).toBe(0);
  await expect(page.getByRole('status',{name:'Human decision history'})).toHaveCount(0);
});

test('mismatched human confirmation remains uncertain and never displays success',async({page})=>{
  await fixture(page,{decisionMismatch:true});await openKit(page);
  await page.getByRole('combobox',{name:'Human disposition (separate from machine result)',exact:true}).selectOption('rework');await page.getByLabel('Handoff / close reason').fill('Intended manual decision');
  await page.getByRole('button',{name:'Record separate human decision',exact:true}).click();
  await expect(page.getByRole('button',{name:'Retry unchanged human decision'})).toBeVisible();
  await expect(page.getByRole('status',{name:'Human decision history'})).toContainText('outcome is unconfirmed');
  await expect(page.getByRole('status',{name:'Human decision history'})).not.toContainText('Recorded historical');
});
