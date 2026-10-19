"""Execute strict owner-review response binding in actual Node; no UI/human proof."""
from pathlib import Path
import shutil,subprocess
import pytest

SCRIPT=r"""
import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.argv[1]).href),fault=process.argv[2];
const binding={id:'00000000-0000-0000-0000-000000000001',scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:3};
const value={...binding,accounting_policy:'conservative-family-accounting-v1',counts:{AFFECTED:1,SHARED:2,CONTEXT:3,UNRELATED:4,UNRESOLVED:5},total_records:15,historical:true,read_only:true,can_confirm_cleanup:false,erasure_complete:false,request_fulfilled:false};
if(fault==='valid'||fault==='empty'||fault==='maximum'){
 if(fault==='empty'){for(const k of Object.keys(value.counts))value.counts[k]=0;value.total_records=0;}
 if(fault==='maximum'){value.counts={AFFECTED:Number.MAX_SAFE_INTEGER,SHARED:0,CONTEXT:0,UNRELATED:0,UNRESOLVED:0};value.total_records=Number.MAX_SAFE_INTEGER;}
 const got=m.ownerMetadataReview(value,binding);assert.deepEqual(got,value);assert.equal(got.erasure_complete,false);assert.equal(got.can_confirm_cleanup,false);
}else{
 if(fault==='id')value.id='00000000-0000-0000-0000-000000000002';
 if(fault==='scope')value.scope_sha256='b'.repeat(64);
 if(fault.startsWith('version_'))value[fault.slice(8)]++;
 if(fault.startsWith('flag_'))value[fault.slice(5)]=!value[fault.slice(5)];
 if(fault==='extra')value.objects=['private/object'];
 if(fault==='count_extra')value.counts.PRIVATE=1;
 if(fault==='count_missing')delete value.counts.CONTEXT;
 if(fault==='count_negative')value.counts.AFFECTED=-1;
 if(fault==='count_bool')value.counts.AFFECTED=true;
 if(fault==='count_string')value.counts.AFFECTED='1';
 if(fault==='count_fraction')value.counts.AFFECTED=1.5;
 if(fault==='count_unsafe'){value.counts.AFFECTED=Number.MAX_SAFE_INTEGER+1;value.total_records=Number.MAX_SAFE_INTEGER+15;}
 if(fault==='sum')value.total_records=14;
 if(fault==='sum_overflow'){value.counts={AFFECTED:Number.MAX_SAFE_INTEGER,SHARED:1,CONTEXT:0,UNRELATED:0,UNRESOLVED:0};value.total_records=Number.MAX_SAFE_INTEGER+1;}
 if(fault==='policy')value.accounting_policy='new-policy';
 if(fault==='array')value.counts=[1,2,3,4,5];
 if(fault==='null')value.counts=null;
 if(fault==='binding_extra')binding.cleanup=true;
 if(fault==='binding_version')binding.gate_version=true;
 if(fault==='binding_id')binding.id='../../private';
 if(fault==='binding_scope')binding.scope_sha256='a';
 if(fault==='missing_flag')delete value.read_only;
 if(fault==='flag_string')value.historical='true';
 assert.throws(()=>m.ownerMetadataReview(value,binding));
}
"""

@pytest.mark.parametrize('fault',['valid','empty','maximum','id','scope','version_request_version','version_gate_version','version_control_version',
 'flag_historical','flag_read_only','flag_can_confirm_cleanup','flag_erasure_complete','flag_request_fulfilled','extra','count_extra','count_missing',
 'count_negative','count_bool','count_string','count_fraction','count_unsafe','sum','sum_overflow','policy','array','null','binding_extra','binding_version','binding_id','binding_scope','missing_flag','flag_string'])
def test_owner_review_response(fault):
 root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
 result=subprocess.run([node,'--input-type=module','-e',SCRIPT,str(root/'apps/web/src/ownerMetadataReview.ts'),fault],cwd=root,capture_output=True,text=True,timeout=20)
 assert result.returncode==0,result.stdout+result.stderr
