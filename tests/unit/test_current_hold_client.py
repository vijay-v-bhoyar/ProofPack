"""Execute closed current-hold TypeScript parsing in Node; no browser/user claims."""
from pathlib import Path
import shutil
import subprocess

import pytest

SCRIPT = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.argv[1]).href),fault=process.argv[2];
assert.equal(typeof m.metadataCurrent,'function','current hold parser must exist');
const id='00000000-0000-0000-0000-000000000001';
const request={id,state_version:1,status:'held',scope_sha256:'a'.repeat(64),inspection_ids:[id],selector_policy:'read-only-family-selection-v3',created_at_ms:100,original_owner_session:false,current_hold:true,gate_version:2,gate_epoch:1,gate_phase:'HELD',control_version:1,inspection_enabled:false,active_count:0,foreign_active:false,drain_status:'empty',can_cancel:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
const value={status:'held',request,unknown_writes_reconciled:false,inspection_resumption_authorized:false,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
if(fault==='valid-held'){assert.deepEqual(m.metadataCurrent(value),value);}
else if(fault==='valid-open'){value.status='open';value.request=null;assert.deepEqual(m.metadataCurrent(value),value);}
else {
if(fault==='unknown-writes')value.unknown_writes_reconciled=true;
if(fault==='resumption')value.inspection_resumption_authorized=true;
if(fault==='cleanup')value.can_confirm_cleanup=true;
if(fault==='erased')value.erasure_complete=true;
if(fault==='fulfilled')value.request_fulfilled=true;
if(fault==='boolean')value.request_fulfilled=0;
if(fault==='outer-extra')value.private='DO_NOT_DISCLOSE';
if(fault==='nested-extra')request.private='DO_NOT_DISCLOSE';
if(fault==='open-record')value.status='open';
if(fault==='held-null')value.request=null;
if(fault==='not-current'){request.current_hold=false;request.drain_status='not_current';request.can_cancel=false;}
if(fault==='cancelled'){request.status='cancelled';request.state_version=2;request.current_hold=false;request.gate_phase='OPEN';request.drain_status='not_current';request.can_cancel=false;}
if(fault==='bad-id')request.id='caller-selected';
if(fault==='bad-count')request.active_count=-1;
assert.throws(()=>m.metadataCurrent(value));
}
'''


@pytest.mark.parametrize('fault', ['valid-held', 'valid-open', 'unknown-writes', 'resumption', 'cleanup', 'erased',
    'fulfilled', 'boolean', 'outer-extra', 'nested-extra', 'open-record', 'held-null', 'not-current', 'cancelled', 'bad-id', 'bad-count'])
def test_actual_current_hold_parser(fault):
    root = Path(__file__).resolve().parents[2]; node = shutil.which('node'); assert node
    result = subprocess.run([node, '--input-type=module', '-e', SCRIPT, str(root/'apps/web/src/metadataRequests.ts'), fault],
        cwd=root, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
