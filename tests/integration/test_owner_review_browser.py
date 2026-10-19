"""Actual configured loopback HTTPS/store/rendered accounting; synthetic provider identity."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import hashlib,json,os,shutil,socket,subprocess,sys,time
import httpx,uvicorn
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case,identity
from test_owner_review_host import configuration
from test_public_asset_store import certificate,BROWSER as CONTROL_BROWSER
from proofpack.runtime.composition import create_configured_app
from proofpack.auth.http import COOKIE
from proofpack.evidence.owner_metadata import OwnerMetadataLimits
from proofpack.evidence.privacy_admission import AdmissionConfiguration,REGISTRY
from proofpack.evidence.repository import Key

REVIEW_BROWSER=CONTROL_BROWSER.replace(
 "  await expect(page.getByRole('button',{name:'Cancel this request before cleanup',exact:true})).toBeDisabled();",
 """  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();
  await expect(page.getByRole('table',{name:'Historical record counts; no cleanup authority'})).toBeVisible();
  const rows=await page.getByRole('table').getByRole('row').allTextContents();
  if(!rows.some(row=>row.includes('AFFECTED'))||!rows.some(row=>row.includes('UNRESOLVED')))throw new Error('Complete accounting hints missing');
  await expect(page.getByText('Read only: yes. Erasure complete: no. Request fulfilled: no. Inspections cannot resume from this snapshot.',{exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Read historical accounting',exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Read request status',exact:true}).click();
  await expect(page.getByRole('table')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Cancel this request before cleanup',exact:true})).toBeDisabled();""")
assert REVIEW_BROWSER!=CONTROL_BROWSER

def retain_timeout_output(error,destination):
    """Best-effort partial diagnostics; never overwrite prior evidence or mask cleanup."""
    value=error.output
    data=value.encode('utf-8') if isinstance(value,str) else value or b''
    try:
        destination.touch(exist_ok=False)
        destination.write_bytes(data)
    except OSError:
        return False
    return True

def test_actual_configured_https_owner_review_uses_published_cv_history(world,publication_case,composition_case):
    return exercise_configured_owner_review(world,publication_case,composition_case,
        review_configuration=configuration(),browser=REVIEW_BROWSER,receipt_name='configured-review-browser.json')


def exercise_configured_owner_review(world,publication_case,composition_case,*,review_configuration,browser,receipt_name):
    _,capture,started,operator,_,_,_,_,_,observe=publication_case
    observe();inspection=started['inspection_id'];key=Key('state','inspection#'+inspection)
    row=world[1].snapshot((key,))[key]
    capture.stations.close(operator,inspection_id=inspection,expected_version=row.revision,
        expected_epoch=int(row.data['station_epoch']),reason='configured browser review fixture',disposition='cancelled',idempotency_key='close-before-browser-review')
    _,base,clients,stub,_=composition_case;assert clients.dynamodb.meta.endpoint_url==world[1].client.meta.endpoint_url
    root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
    sock=socket.socket()
    if sys.platform=='win32':sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
    sock.bind(('127.0.0.1',443));sock.listen(128);endpoint='https://127.0.0.1'
    server=thread=process=tls_path=result=None
    try:
        config=replace(base,app_origin=endpoint,auth=world[0].config,
            oauth=replace(base.oauth,deployment=world[1].deployment,redirect_uri=endpoint+'/api/v1/auth/callback'),
            objects=replace(base.objects,deployment=world[1].deployment),state_table=world[1].tables['state'],events_table=world[1].tables['events'],
            metadata_admission=AdmissionConfiguration(8,20000,20000,15000,3,'c'*64),owner_metadata=OwnerMetadataLimits(10,20,100,20000),owner_metadata_review=review_configuration)
        identity(stub);app=create_configured_app(config,clients,clock_ms=world[2]);app.state.runtime_control.start();app.state.metadata_admission.initialize('c'*64)
        with TemporaryDirectory(prefix='proofpack-review-tls-') as directory:
            tls_path=Path(directory);private,public=certificate(directory)
            server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=443,ssl_keyfile=str(private),ssl_certfile=str(public),log_level='error',access_log=False,timeout_graceful_shutdown=30))
            thread=Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);thread.start();deadline=time.monotonic()+20
            while not server.started:
                assert thread.is_alive() and time.monotonic()<deadline,'owned configured review server failed startup';time.sleep(.05)
            with httpx.Client(verify=False,trust_env=False,timeout=1) as http:assert http.get(endpoint+'/').status_code==200
            payload={'root':str(root),'endpoint':endpoint,'inspection':inspection,'cookieName':COOKIE,'cookie':world[4].cookie,
                'diagnostic_png':str(Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).with_name('review-https-failure.png'))}
            process=subprocess.Popen([node,'-e',browser],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform=='win32' else 0,start_new_session=sys.platform!='win32')
            try:output,_=process.communicate(json.dumps(payload),timeout=60)
            except subprocess.TimeoutExpired as error:
                case=hashlib.sha256(os.environ.get('PYTEST_CURRENT_TEST','unknown').encode()).hexdigest()[:16]
                partial=error.output
                if sys.platform=='win32':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=10)
                else:
                    import signal
                    os.killpg(process.pid,signal.SIGKILL)
                cleanup_deadline=time.monotonic()+10
                process.wait(timeout=10)
                try:
                    drained,_=process.communicate(timeout=max(0,cleanup_deadline-time.monotonic()))
                    if drained is not None:partial=drained
                except subprocess.TimeoutExpired:
                    pass  # Preserve the available prefix and original failure; cleanup time is not renewed.
                retain_timeout_output(subprocess.TimeoutExpired(error.cmd,error.timeout,output=partial),Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).with_name('review-https-timeout-'+case+'.partial.log'))
                raise AssertionError('owned review browser exceeded original 60-second fixture bound')
            assert process.returncode==0,output
            result=json.loads(output.strip().splitlines()[-1]);assert result['status']=='PASS'
            reviews=[r for r in result['responses'] if r['path'].endswith('/review')]
            assert len(reviews)==1 and reviews[0]['status']==200
            assert app.state.resource_owner.wait_for_drain(5000)
            final=app.state.owner_metadata_service.get(app.state.access_service.resolve(world[4].cookie),result['request_id'])
            assert final['status']=='cancelled' and not final['inspection_enabled'] and not final['erasure_complete'] and not final['request_fulfilled']
    finally:
        if server is not None:server.should_exit=True
        if thread is not None:thread.join(40);assert not thread.is_alive()
        sock.close();assert tls_path is None or not tls_path.exists()
    assert process is not None and process.poll()==0 and app.state.composition_status=='closed' and app.state.resource_owner.wait_for_drain(0)
    assert not app.state.owner_metadata_service.repository.snapshot((REGISTRY,))[REGISTRY].data['active']
    receipt=Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).with_name(receipt_name)
    receipt.write_text(json.dumps({**result,'scope':'actual configured local HTTPS/store/rendered review of genuine synthetic CV history; synthetic trusted identity/bootstrap, intercepted STS/S3, test-only self-signed TLS bypass','browser_exit_code':0,'server_thread_exited':True,'ephemeral_tls_material_removed':not tls_path.exists(),'application_closed':True,'resource_drain_verified':True,'credentials_retained':False,'parent_complete':False,'beta_decision':'NO_GO'},indent=2)+'\n')
