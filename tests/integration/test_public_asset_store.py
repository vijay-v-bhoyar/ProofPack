"""Genuine local DynamoDB/public boot and configured HTTPS browser; synthetic identity/STS."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace,asdict
from threading import Barrier,Thread
from pathlib import Path
from uuid import uuid4
from datetime import datetime,timedelta,timezone
from tempfile import TemporaryDirectory
import ipaddress,json,os,shutil,socket,subprocess,sys,time
import pytest
import httpx
import uvicorn
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from test_access_lifecycle import world,repository_factory,proof,ISSUER
from test_privacy_admission_store import setup
from test_owner_metadata_store import prepared,create,cancel
from test_composition import composition_case,identity
from proofpack.auth.http import COOKIE
from proofpack.auth.service import BootstrapApproval
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionConfiguration,AdmissionHeld,REGISTRY,GATE,_bind_control
from proofpack.evidence.owner_metadata import OwnerMetadataLimits
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.runtime.control import RuntimeControl
from proofpack.runtime.composition import create_configured_app


def asset(service):return service._prepare_public_asset(work_id=str(uuid4()),lease_ms=500)


def test_actual_assets_coexist_with_control_but_block_cancel_until_actual_release(world):
    service,owner,ident=prepared(world);a=service.admission;request=create(service,world[5],ident)
    public=[asset(a),asset(a)]
    for item in public:a._admit_public_asset(item)
    own=a._prepare_control(work_id=str(uuid4()),lease_ms=500);a._admit_control(own)
    with _bind_control(a,own):
        current=service.get(world[5],request['id']);assert current['active_count']==2 and not current['can_cancel']
        with pytest.raises(AdmissionHeld):cancel(service,world[5],current)
        for item in public:a._release_public_asset(item)
        ended=cancel(service,world[5],service.get(world[5],request['id']))
        assert ended['status']=='cancelled' and not ended['inspection_enabled'] and not ended['erasure_complete']
        assert world[1].snapshot((REGISTRY,))[REGISTRY].data['active']=={own.work_id:asdict(own)}
        a._checkpoint_control(own)
    a._release_control(own)
    for item in public:
        with pytest.raises(AdmissionHeld):a._admit_public_asset(item)
    assert owner.wait_for_drain(0)


def test_actual_public_capacity_conditional_write_cannot_overwrite_winner(world):
    a,_=setup(world,capacity=1);items=[asset(a),asset(a)];barrier=Barrier(2)
    def admit(item):
        barrier.wait(timeout=5)
        try:a._admit_public_asset(item);return item
        except (AdmissionHeld,StoreConflict):return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(admit,items))
    winners=[x for x in results if x is not None];assert len(winners)==1
    assert set(world[1].snapshot((REGISTRY,))[REGISTRY].data['active'])=={winners[0].work_id}
    assert a._release_public_asset(winners[0])


@pytest.mark.parametrize('operation',['admit','release'])
def test_actual_unknown_asset_write_recovers_original_without_duplicate_or_renewal(world,monkeypatch,operation):
    a,_=setup(world);item=asset(a);repo=world[1]
    if operation=='release':a._admit_public_asset(item)
    original=repo.transact;lost=[]
    def uncertain(*args,**kwargs):
        result=original(*args,**kwargs)
        if not lost:lost.append(True);raise StoreUnavailable('synthetic lost acknowledgment after actual commit')
        return result
    monkeypatch.setattr(repo,'transact',uncertain)
    if operation=='admit':
        assert a._admit_public_asset(item)==item
        assert a._admit_public_asset(item)==item
        assert repo.snapshot((REGISTRY,))[REGISTRY].data['active']=={item.work_id:asdict(item)}
        a._release_public_asset(item)
    else:
        assert a._release_public_asset(item) is False
        assert not repo.snapshot((REGISTRY,))[REGISTRY].data['active']
    assert len(lost)==1


def test_actual_expired_asset_never_frees_capacity_or_claims_completion(world):
    a,_=setup(world,capacity=1);item=asset(a);a._admit_public_asset(item);world[2].value=item.expires_at_ms
    with pytest.raises(AdmissionHeld):a._checkpoint_public_asset(item)
    with pytest.raises(AdmissionHeld):a._admit_public_asset(asset(a))
    assert set(world[1].snapshot((REGISTRY,))[REGISTRY].data['active'])=={item.work_id}
    assert a._release_public_asset(item)


def test_actual_restart_retains_foreign_asset_until_original_executor_releases(world):
    old,rt=setup(world);item=asset(old);old._admit_public_asset(item)
    runtime=RuntimeControl(world[0],instance_id=str(uuid4()),artifact_sha256=rt.artifact_sha256,controls_sha256=rt.controls_sha256,environment=rt.environment);runtime.start()
    current=PersistentAdmission(runtime,limits=old.limits,clock_ms=world[2]);current.require_enrollment('a'*64)
    assert current.require_enrollment('a'*64).foreign_active
    with pytest.raises(AdmissionHeld):current._release_public_asset(item)
    new=asset(current);current._admit_public_asset(new)
    assert len(world[1].snapshot((REGISTRY,))[REGISTRY].data['active'])==2
    assert old._release_public_asset(item) and current._release_public_asset(new)


BROWSER=r"""
const fs=require('node:fs'),path=require('node:path');
(async()=>{
 const data=JSON.parse(fs.readFileSync(0,'utf8'));
 const {chromium,expect}=require(require.resolve('@playwright/test',{paths:[data.root]}));
 const browser=await chromium.launch({channel:'chrome',headless:true});let page;const responses=[];
 try{
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  await context.route('**/*',route=>new URL(route.request().url()).origin===data.endpoint?route.continue():route.abort());
  await context.addCookies([{name:data.cookieName,value:data.cookie,url:data.endpoint,secure:true,httpOnly:true,sameSite:'Lax'}]);
  page=await context.newPage();page.setDefaultTimeout(5000);
  page.on('response',response=>{const url=new URL(response.url());responses.push({path:url.pathname,status:response.status()});});
  page.on('requestfailed',request=>responses.push({path:new URL(request.url()).pathname,failure:request.failure()?.errorText}));
  await page.goto(data.endpoint+'/#maintenance');
  await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  await expect(page.getByLabel('Inspection IDs',{exact:true})).toBeEnabled();
  await page.getByLabel('Inspection IDs',{exact:true}).fill(data.inspection);
  await page.getByLabel('I acknowledge interruption of ordinary work; this hold erases nothing.').check();
  await page.getByRole('button',{name:'Create request and hold',exact:true}).click();
  await expect(page.getByRole('heading',{name:/^Request [0-9a-f-]{36}$/})).toBeVisible();
  const heading=await page.getByRole('heading',{name:/^Request [0-9a-f-]{36}$/}).innerText();
  const id=heading.slice(8);
  await page.getByRole('button',{name:'Read request status',exact:true}).click();
  await expect(page.getByRole('button',{name:'Cancel this request before cleanup',exact:true})).toBeDisabled();
  await page.getByLabel('I acknowledge cancellation performs no erasure and leaves inspections disabled.').check();
  await page.getByRole('button',{name:'Cancel this request before cleanup',exact:true}).click();
  await expect(page.getByText('Status: cancelled. Drain: not_current. This is a snapshot, not a cleanup receipt.',{exact:true})).toBeVisible();
  await expect(page.getByRole('status')).toContainText('Inspections at this read: disabled');
  await context.clearCookies();await page.reload();
  await page.getByRole('button',{name:'Read owner status',exact:true}).click();
  await expect(page.getByRole('button',{name:'Create request and hold',exact:true})).toHaveCount(0);
  console.log(JSON.stringify({status:'PASS',request_id:id,responses,scope:'actual configured local HTTPS/DynamoDB UI; synthetic bootstrap/identity, intercepted STS, self-signed TLS ignored only by test browser; no simulated API responses'}));
 }catch(error){let visible='',diagnosticError='',dom=null,png=false,keyboard=null;
  try{visible=page?(await page.locator('body').textContent({timeout:1000})||'').slice(0,2200):'';}catch(diagnostic){diagnosticError=String(diagnostic);}
  if(page){
   try{dom=await Promise.race([page.evaluate(()=>({visibility:document.visibilityState,busy:document.querySelector('.metadata-maintenance')?.getAttribute('aria-busy'),viewport:[innerWidth,innerHeight,scrollY],checkboxes:[...document.querySelectorAll('input[type=checkbox]')].map(el=>{const r=el.getBoundingClientRect(),style=getComputedStyle(el);return {disabled:el.matches(':disabled'),checked:el.checked,rect:[r.x,r.y,r.width,r.height],display:style.display,visibility:style.visibility,pointer:style.pointerEvents};})})).catch(e=>({error:String(e)})),new Promise(resolve=>setTimeout(()=>resolve({error:'diagnostic observation timed out'}),1000))]);}catch(diagnostic){diagnosticError+=String(diagnostic);}
   try{await page.screenshot({path:data.diagnostic_png,fullPage:false,timeout:1000});png=true;}catch{}
   try{const box=page.getByLabel('I acknowledge interruption of ordinary work; this hold erases nothing.');await box.focus({timeout:1000});await page.keyboard.press('Space');keyboard={checked:await box.isChecked()};}catch(diagnostic){keyboard={error:String(diagnostic)};}
  }
  console.log(JSON.stringify({status:'FAIL',message:String(error),responses,visible,diagnosticError,dom,png,keyboard}));process.exitCode=1;}
 finally{await browser.close();}
})().catch(error=>{console.error(String(error));process.exitCode=1;});
"""


def certificate(directory):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ProofPack ephemeral loopback test')]);now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256()))
    private=Path(directory)/'key.pem';public=Path(directory)/'cert.pem'
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return private,public


def test_configured_https_browser_owner_flow_uses_real_local_store_and_auth(composition_case,monkeypatch):
    repository,config,clients,stub,clock=composition_case;root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
    sock=socket.socket()
    if sys.platform=='win32':sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
    sock.bind(('127.0.0.1',443));sock.listen(128);port=443;endpoint='https://127.0.0.1'
    server=None;thread=None;process=None;tls_path=None;result=None
    try:
        config=replace(config,app_origin=endpoint,oauth=replace(config.oauth,redirect_uri=endpoint+'/api/v1/auth/callback'),
            auth=replace(config.auth,initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64),metadata_admission=AdmissionConfiguration(8,20000,20000,15000,3,'c'*64),owner_metadata=OwnerMetadataLimits(10,20,100,20000))
        identity(stub);app=create_configured_app(config,clients,clock_ms=clock);access=app.state.access_service
        access.bootstrap(BootstrapApproval(ISSUER,'owner','a'*64),proof(clock));app.state.runtime_control.start();app.state.metadata_admission.initialize('c'*64)
        credentials=access.login(proof(clock));inspection=str(uuid4());repository.transact((Write(Key('state','inspection#'+inspection),None,{'id':inspection,'state':'CLOSED','synthetic_selector':True}),))
        control_denials=[];original_prepare=app.state.metadata_admission._prepare_control
        def observed_prepare(**arguments):
            try:return original_prepare(**arguments)
            except AdmissionHeld as error:
                control_denials.append('CONTROL_COMPLETION_PENDING' if str(error)=='previous control completion remains unconfirmed' else 'OTHER_ADMISSION_HOLD')
                raise
        monkeypatch.setattr(app.state.metadata_admission,'_prepare_control',observed_prepare)
        with TemporaryDirectory(prefix='proofpack-loopback-tls-') as directory:
            tls_path=Path(directory);private,public=certificate(directory)
            server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,ssl_keyfile=str(private),ssl_certfile=str(public),log_level='error',access_log=False,timeout_graceful_shutdown=30))
            thread=Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);thread.start();deadline=time.monotonic()+20
            with httpx.Client(verify=False,trust_env=False,timeout=1) as http:
                while not server.started:
                    assert thread.is_alive() and time.monotonic()<deadline,'owned HTTPS server did not start'
                    time.sleep(.05)
                assert http.get(endpoint+'/').status_code==200
            payload={'root':str(root),'endpoint':endpoint,'inspection':inspection,'cookieName':COOKIE,'cookie':credentials.cookie,
                'diagnostic_png':str(Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).with_name('configured-https-failure.png'))}
            process=subprocess.Popen([node,'-e',BROWSER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform=='win32' else 0,start_new_session=sys.platform!='win32')
            try:output,_=process.communicate(json.dumps(payload),timeout=60)
            except subprocess.TimeoutExpired:
                if sys.platform=='win32':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=10)
                else:
                    import signal
                    os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=10);raise AssertionError('owned browser process exceeded original 60-second fixture bound')
            assert process.returncode==0,output+'\n'+json.dumps({'control_prepare_denials':control_denials})
            result=json.loads(output.strip().splitlines()[-1]);assert result['status']=='PASS'
            assert app.state.resource_owner.wait_for_drain(5000),'HTTP execution must actually finish before harness readback'
            row=app.state.owner_metadata_service.get(access.resolve(credentials.cookie),result['request_id'])
            assert row['status']=='cancelled' and not row['inspection_enabled'] and not row['request_fulfilled'] and not row['erasure_complete']
    finally:
        if server is not None:server.should_exit=True
        if thread is not None:thread.join(40);assert not thread.is_alive(),'HTTPS executor completion remains unconfirmed'
        sock.close()
        assert tls_path is None or not tls_path.exists(),'ephemeral TLS private material must be removed'
    assert process is not None and process.poll()==0 and app.state.composition_status=='closed'
    assert app.state.resource_owner.wait_for_drain(0)
    assert not repository.snapshot((REGISTRY,))[REGISTRY].data['active']

    receipt=Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).with_name('configured-https-browser.json')
    receipt.write_text(json.dumps({**result,'browser_exit_code':process.returncode,'server_thread_exited':not thread.is_alive(),
        'ephemeral_tls_material_removed':not tls_path.exists(),'application_closed':app.state.composition_status=='closed',
        'resource_drain_verified':app.state.resource_owner.wait_for_drain(0),'credentials_retained':False,'parent_complete':False,'beta_decision':'NO_GO'},indent=2)+'\n')
