/** Synthetic API/PNG fixtures only; no provider, retained customer data or AWS. */
import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';

const assetId='a0000000-0000-4000-8000-000000000001', inspectionId='b0000000-0000-4000-8000-000000000001';
async function fixture(page:Page,options:{owner?:boolean;revoke?:boolean;corrupt?:boolean;mismatch?:boolean;ttl?:number;originals?:boolean;badCatalog?:boolean}={}) {
  const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message));
  const encoded=await page.evaluate(()=>{const c=document.createElement('canvas');c.width=2;c.height=2;c.getContext('2d')!.fillRect(0,0,2,2);return c.toDataURL('image/png').split(',')[1];});
  const payload=Buffer.from(encoded,'base64'), sha=createHash('sha256').update(payload).digest('hex');let downloads=0;
  const asset={id:assetId,state_version:1,kind:'inspection_evidence',sha256:sha,binding_sha256:'c'.repeat(64),byte_length:payload.length,
    content_type:'image/png',data_origin:'synthetic',remaining_validity_ms:options.ttl??30000,can_download:!options.owner,historical:true,machine_pass:false,storage_verified:false,
    ...(options.originals ? {derivation:'original_transmitted_frame'} : {})};
  await page.route('**/api/v1/**',async route=>{
    const path=new URL(route.request().url()).pathname.slice('/api/v1'.length),json=(value:unknown,status=200)=>route.fulfill({json:value,status});
    if(path==='/me')return json({id:'synthetic-user',session_id:'synthetic-session',display_name:'Synthetic evidence reader',roles:[options.owner?'owner':'reviewer'],csrf_token:'synthetic-csrf'});
    if(path==='/assets/'+assetId || path==='/inspections/'+inspectionId+'/evidence')return json(asset);
    if(path==='/inspections/'+inspectionId+'/evidence/originals')return json({inspection_id:inspectionId,originals:options.badCatalog?[asset,asset]:options.originals?[asset]:[],remaining_validity_ms:30000,historical:true,machine_pass:false});
    if(path==='/assets/'+assetId+'/download'){
      downloads++;if(options.revoke)return json({},403);
      const body=Buffer.from(payload);if(options.corrupt)body[body.length-1]^=1;
      return route.fulfill({body,headers:{'content-type':'image/png','content-length':String(payload.length),'x-asset-id':assetId,'x-asset-state-version':'1',
        'x-content-sha256':sha,'x-evidence-binding-sha256':(options.mismatch?'d':'c').repeat(64),'x-evidence-historical':'true','x-remaining-validity-ms':String(options.ttl??30000)}});
    }
    throw new Error('Unexpected evidence fixture request '+path);
  });
  await page.bringToFront();await page.goto('/');await page.getByRole('button',{name:'Open invited workspace'}).click();
  await page.getByRole('button',{name:'Review and administration',exact:true}).click();await page.getByRole('button',{name:'Retained evidence',exact:true}).click();
  return {get downloads(){return downloads;},errors};
}
async function metadata(page:Page){await page.getByRole('textbox',{name:'Retained asset ID',exact:true}).fill(assetId);await page.getByRole('button',{name:'Load evidence metadata',exact:true}).click();}

for(const owner of [true,false])test('original discovery preserves fresh metadata review and scoped image rights '+owner,async({page})=>{
  const state=await fixture(page,{originals:true,owner});
  await page.getByRole('textbox',{name:'Inspection ID for latest evidence',exact:true}).fill(inspectionId);
  await page.getByRole('button',{name:'Find selected original images',exact:true}).click();
  await expect(page.getByRole('button',{name:'Review original '+assetId,exact:true})).toBeVisible();expect(state.downloads).toBe(0);
  await page.getByRole('button',{name:'Review original '+assetId,exact:true}).click();
  await expect(page.getByText(/Original transmitted image · origin synthetic/)).toBeVisible();
  const view=page.getByRole('button',{name:'View retained image',exact:true});
  if(owner)await expect(view).toBeDisabled();else{await view.click();await expect(page.getByRole('img')).toBeVisible();}
  expect(state.downloads).toBe(owner?0:1);expect(state.errors).toEqual([]);
});

test('original discovery rejects duplicate catalog entries before offering an image',async({page})=>{
  const state=await fixture(page,{originals:true,badCatalog:true});
  await page.getByRole('textbox',{name:'Inspection ID for latest evidence',exact:true}).fill(inspectionId);
  await page.getByRole('button',{name:'Find selected original images',exact:true}).click();
  await expect(page.getByRole('status').filter({hasText:'Original-image discovery is mismatched'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Review original '+assetId,exact:true})).toHaveCount(0);expect(state.downloads).toBe(0);
});

test('reviewer verifies bytes and sees a historical preview that clears on navigation',async({page})=>{
  const state=await fixture(page);await metadata(page);await page.getByRole('button',{name:'View retained image',exact:true}).click();
  const image=page.getByAltText('Retained historical evidence; not a current inspection result');await expect(image).toBeVisible();
  await expect.poll(()=>image.evaluate((node:HTMLImageElement)=>node.naturalWidth)).toBe(2);
  await expect(page.getByText('Retained historical image. Review its origin and limitations; perform a separate current manual check.')).toBeVisible();
  await page.getByRole('button',{name:'Recipes and qualification',exact:true}).click();await expect(image).toHaveCount(0);expect(state.downloads).toBe(1);expect(state.errors).toEqual([]);
});
test('owner metadata does not grant another operator image bytes',async({page})=>{
  const state=await fixture(page,{owner:true});await metadata(page);await expect(page.getByRole('button',{name:'View retained image',exact:true})).toBeDisabled();
  await expect(page.getByText(/An explicit scoped media grant is required/)).toBeVisible();expect(state.downloads).toBe(0);expect(state.errors).toEqual([]);
});
for(const failure of ['revoke','corrupt','mismatch'] as const)test('evidence '+failure+' never displays an image',async({page})=>{
  const state=await fixture(page,{[failure]:true});await metadata(page);await page.getByRole('button',{name:'View retained image',exact:true}).click();
  await expect(page.getByRole('status').filter({hasText:failure==='revoke'?'Your current session':failure==='corrupt'?'Evidence integrity':'Evidence response does not match'})).toBeVisible();
  await expect(page.getByRole('img')).toHaveCount(0);expect(state.downloads).toBe(1);expect(state.errors).toEqual([]);
});
test('latest inspection lookup discovers the asset without knowing its ID',async({page})=>{
  const state=await fixture(page);await page.getByRole('textbox',{name:'Inspection ID for latest evidence',exact:true}).fill(inspectionId);
  await page.getByRole('button',{name:'Load latest inspection evidence',exact:true}).click();await expect(page.getByRole('textbox',{name:'Retained asset ID',exact:true})).toHaveValue(assetId);
  await page.getByRole('button',{name:'View retained image',exact:true}).click();await expect(page.getByRole('img')).toBeVisible();
  await page.getByRole('button',{name:'Clear retained image or cancel read',exact:true}).click();await expect(page.getByRole('img')).toHaveCount(0);expect(state.errors).toEqual([]);
});
test('expiry clears historical bytes and forces fresh metadata',async({page})=>{
  const state=await fixture(page,{ttl:1500});await metadata(page);await page.getByRole('button',{name:'View retained image',exact:true}).click();
  await expect(page.getByRole('img')).toBeVisible();await expect(page.getByRole('status').filter({hasText:'Historical preview expired'})).toBeVisible();
  await expect(page.getByRole('img')).toHaveCount(0);await expect(page.getByRole('button',{name:'View retained image',exact:true})).toHaveCount(0);expect(state.errors).toEqual([]);
});

for(const interruption of ['offline','hidden'] as const)test('historical evidence is cleared when '+interruption+' without automatic refetch',async({page})=>{
  const state=await fixture(page);await metadata(page);await page.getByRole('button',{name:'View retained image',exact:true}).click();await expect(page.getByRole('img')).toBeVisible();
  if(interruption==='offline')await page.evaluate(()=>window.dispatchEvent(new Event('offline')));
  else await page.evaluate(()=>{Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'hidden'});document.dispatchEvent(new Event('visibilitychange'));});
  await expect(page.getByRole('img')).toHaveCount(0);await expect(page.getByRole('button',{name:'View retained image',exact:true})).toHaveCount(0);
  expect(state.downloads).toBe(1);expect(state.errors).toEqual([]);
});
