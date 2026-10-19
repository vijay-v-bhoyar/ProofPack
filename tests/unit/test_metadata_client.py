"""Execute actual standalone TypeScript response/intent guards in Node; no UI/user proof."""
from pathlib import Path
import shutil,subprocess
import pytest

SCRIPT=r"""
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.argv[1]).href),fault=process.argv[2];
const id='00000000-0000-0000-0000-000000000001',other='00000000-0000-0000-0000-000000000002';
const context={gate_version:1,gate_phase:'OPEN',gate_epoch:1,control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,max_inspections:10,can_create:true,can_confirm_cleanup:false,erasure_complete:false};
const view={id,state_version:1,status:'held',scope_sha256:'a'.repeat(64),inspection_ids:[id],selector_policy:'read-only-family-selection-v3',created_at_ms:100,original_owner_session:true,current_hold:true,gate_version:2,gate_epoch:1,gate_phase:'HELD',control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,drain_status:'empty',can_cancel:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
const intent={schema_version:1,user_id:id,key:other,kind:'create',path:m.metadataBase,body:{inspection_ids:[id],expected_gate_version:1,expected_control_version:1,interruption_acknowledged:true}};
if(fault.startsWith('read_')){
 const controller=new AbortController(),busy=new Error('busy');let calls=0;
 const operation=async signal=>{assert.equal(signal,controller.signal);calls++;if(fault==='read_late'){await new Promise(resolve=>setTimeout(resolve,20));return 'LATE';}if(fault==='read_transient'&&calls===2)return 'CURRENT';throw busy;};
 if(fault==='read_aborted')controller.abort();
 if(fault==='read_cancel_wait'||fault==='read_late')setTimeout(()=>controller.abort(),5);
 if(fault==='read_transient')assert.equal(await m.metadataRead(operation,()=>true,controller.signal),'CURRENT');
 else await assert.rejects(m.metadataRead(operation,()=>fault!=='read_denied',controller.signal));
 assert.equal(calls,{read_transient:2,read_permanent:3,read_denied:1,read_aborted:0,read_cancel_wait:1,read_late:1}[fault]);
}
else if(fault==='valid'){
 assert.equal(m.metadataContext(context).can_create,true);assert.equal(m.metadataRequest(view,id).can_cancel,true);
 assert.deepEqual(m.inspectionIds(other+','+id),[id,other]);assert.deepEqual(m.parseMetadataIntent(JSON.stringify(intent),id),intent);
 assert.equal(m.metadataRequest({...view,replayed:true,original_operation:'held'},id,'held').replayed,true);
 const ended={...view,status:'cancelled',state_version:2,current_hold:false,gate_phase:'OPEN',gate_epoch:2,can_cancel:false,drain_status:'not_current'};
 assert.equal(m.metadataRequest(ended,id).erasure_complete,false);
 const historical=m.metadataRequest({...ended,inspection_enabled:true},id);assert.match(m.metadataOutcome(historical),/enabled under separate authority/);assert.doesNotMatch(m.metadataOutcome(historical),/remain disabled/);assert.match(m.metadataOutcome(historical),/cannot authorize resumption/);
 const cancel={...intent,kind:'cancel',path:m.metadataBase+'/'+id+'/cancel',body:{confirmed_scope_sha256:'a'.repeat(64),expected_request_version:1,expected_gate_version:2,expected_control_version:1,no_erasure_acknowledged:true}};
 assert.equal(m.metadataIntent(cancel,id).kind,'cancel');
}else if(fault.startsWith('context_')){
 if(fault==='context_enable')context.can_create=false;
 if(fault==='context_private')context.storage_key='private';
 if(fault==='context_bool')context.gate_version=true;
 if(fault==='context_foreign')context.foreign_active=true;
 assert.throws(()=>m.metadataContext(context));
}else if(fault.startsWith('view_')){
 if(fault==='view_fulfilled')view.request_fulfilled=true;
 if(fault==='view_erased')view.erasure_complete=true;
 if(fault==='view_cleanup')view.can_confirm_cleanup=true;
 if(fault==='view_wrong_id')view.id=other;
 if(fault==='view_scope')view.inspection_ids=[other,id];
 if(fault==='view_policy')view.selector_policy='permissive';
 if(fault==='view_cancelled')view.status='cancelled';
 if(fault==='view_private')view.raw_rows=[];
 if(fault==='view_version')view.control_version=Number.MAX_SAFE_INTEGER+1;
 if(fault==='view_budget')view.active_count=true;
 assert.throws(()=>m.metadataRequest(view,id));
}else{
 if(fault==='intent_owner')intent.user_id=other;
 if(fault==='intent_path')intent.path='/admin/enable';
 if(fault==='intent_secret')intent.csrf_token='SECRET';
 if(fault==='intent_unsorted')intent.body.inspection_ids=[other,id];
 if(fault==='intent_duplicate')intent.body.inspection_ids=[id,id];
 if(fault==='intent_bool')intent.body.expected_gate_version=true;
 if(fault==='intent_version')intent.body.expected_control_version=Number.MAX_SAFE_INTEGER+1;
 if(fault==='intent_body')intent.body=[];
 if(fault==='intent_kind')intent.kind='erase';
 if(fault==='intent_oversize')assert.throws(()=>m.parseMetadataIntent(' '.repeat(8193),id));
 else assert.throws(()=>m.parseMetadataIntent(JSON.stringify(intent),id));
}
"""

@pytest.mark.parametrize('fault',['valid','context_enable','context_private','context_bool','context_foreign',
 'view_fulfilled','view_erased','view_cleanup','view_wrong_id','view_scope','view_policy','view_cancelled','view_private','view_version','view_budget',
 'read_transient','read_permanent','read_denied','read_aborted','read_cancel_wait','read_late',
 'intent_owner','intent_path','intent_secret','intent_unsorted','intent_duplicate','intent_bool','intent_version','intent_body','intent_kind','intent_oversize'])
def test_actual_typescript_guards(fault):
    root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node,'Node runtime is required; missing execution is not a pass'
    result=subprocess.run([node,'--input-type=module','-e',SCRIPT,str(root/'apps/web/src/metadataRequests.ts'),fault],cwd=root,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr


def test_client_read_recovery_bounds_match_documented_controls():
    import json,yaml
    root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
    source="import {pathToFileURL} from 'node:url';const m=await import(pathToFileURL(process.argv[1]).href);console.log(JSON.stringify([m.metadataOperationMs,m.metadataReadAttempts,m.metadataReadDelayMs]));"
    result=subprocess.run([node,'--input-type=module','-e',source,str(root/'apps/web/src/metadataRequests.ts')],cwd=root,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
    controls=yaml.safe_load((root/'docs/controls.yaml').read_text())['metadata_ui']
    assert json.loads(result.stdout)==[controls['operation_deadline_ms'],controls['read_max_attempts'],controls['read_retry_delay_ms']]==[7000,3,100]
