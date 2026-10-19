"""Closed v5 DTO and authority flags; Node mechanism checks, not human proof."""
from pathlib import Path
import shutil,subprocess
import pytest

SCRIPT=r"""
import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.argv[1]).href),fault=process.argv[2];
const binding={id:'00000000-0000-0000-0000-000000000001',scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:3};
const value={...binding,accounting_policy:'conservative-family-accounting-v5',auth_history_policy_resolved:false,historical_auth_authority_proven:false,counts:{AFFECTED:1,SHARED:0,CONTEXT:2,UNRELATED:0,UNRESOLVED:3},total_records:6,historical:true,read_only:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
if(fault==='valid'){assert.deepEqual(m.ownerMetadataReview(value,binding),value);}
else{
 if(fault==='policy_true')value.auth_history_policy_resolved=true;
 if(fault==='authority_true')value.historical_auth_authority_proven=true;
 if(fault==='missing_policy')delete value.auth_history_policy_resolved;
 if(fault==='missing_authority')delete value.historical_auth_authority_proven;
 if(fault==='string_flag')value.auth_history_policy_resolved='false';
 if(fault==='null_flag')value.historical_auth_authority_proven=null;
 if(fault==='wrong_version')value.accounting_policy='conservative-family-accounting-v4';
 if(fault==='v1_extra')value.accounting_policy='conservative-family-accounting-v1';
 if(fault==='private')value.records=['cookie#private'];
 if(fault==='cleanup')value.can_confirm_cleanup=true;
 if(fault==='fulfilled')value.request_fulfilled=true;
 if(fault==='sum')value.total_records=7;
 if(fault==='scope')value.scope_sha256='b'.repeat(64);
 assert.throws(()=>m.ownerMetadataReview(value,binding));
}
"""

@pytest.mark.parametrize('fault',['valid','policy_true','authority_true','missing_policy','missing_authority','string_flag','null_flag','wrong_version','v1_extra','private','cleanup','fulfilled','sum','scope'])
def test_auth_review_response(fault):
    root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
    result=subprocess.run([node,'--input-type=module','-e',SCRIPT,str(root/'apps/web/src/ownerMetadataReview.ts'),fault],
        cwd=root,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
