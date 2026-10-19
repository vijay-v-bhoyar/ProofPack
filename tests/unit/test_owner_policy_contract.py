"""Closed DTO and executed TypeScript parser; synthetic shape, not user proof."""
from pathlib import Path
import json,shutil,subprocess
import pytest
from pydantic import ValidationError
from proofpack.evidence.owner_metadata_http import PolicyObligationsResult
from proofpack.evidence.auth_history import FAMILIES

def response():
    families={name:0 for name in sorted(FAMILIES)};families['user']=2
    return dict(id='00000000-0000-0000-0000-000000000001',scope_sha256='a'*64,request_version=1,gate_version=2,
        control_version=3,policy='auth-policy-obligations-v1',accounting_policy='conservative-family-accounting-v5',
        family_counts=families,validated_auth_records=2,source_records=5,historical_dependencies_unavailable=0,
        next_step='OWNER_D11_POLICY_DECISION_REQUIRED',historical=True,read_only=True,
        auth_history_policy_resolved=False,historical_auth_authority_proven=False,can_confirm_cleanup=False,
        erasure_complete=False,request_fulfilled=False)

FAULTS=['missing_family','extra_family','bool_count','sum','exceeds_source','negative','private',
    'policy_resolved','authority','cleanup','fulfilled','read_only','next_step','version','coerced','missing_flag']
def mutate(v,fault):
    if fault=='missing_family':del v['family_counts']['cookie']
    elif fault=='extra_family':v['family_counts']['private-cookie']=0
    elif fault=='bool_count':v['family_counts']['user']=True
    elif fault=='sum':v['validated_auth_records']=3
    elif fault=='exceeds_source':v['source_records']=1
    elif fault=='negative':v['historical_dependencies_unavailable']=-1
    elif fault=='private':v['records']=['cookie#private']
    elif fault=='policy_resolved':v['auth_history_policy_resolved']=True
    elif fault=='authority':v['historical_auth_authority_proven']=True
    elif fault=='cleanup':v['can_confirm_cleanup']=True
    elif fault=='fulfilled':v['request_fulfilled']=True
    elif fault=='read_only':v['read_only']=False
    elif fault=='next_step':v['next_step']='DELETE_NOW'
    elif fault=='version':v['accounting_policy']='conservative-family-accounting-v1'
    elif fault=='coerced':v['validated_auth_records']='2'
    elif fault=='missing_flag':del v['request_fulfilled']
    return v

@pytest.mark.parametrize('fault',['valid',*FAULTS])
def test_strict_minimized_response(fault):
    v=mutate(response(),fault)
    if fault=='valid':assert PolicyObligationsResult.model_validate(v).model_dump()==v
    else:
        with pytest.raises(ValidationError):PolicyObligationsResult.model_validate(v)

SCRIPT=r"""
import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.argv[1]).href),value=JSON.parse(process.argv[2]),fault=process.argv[3];
const binding={id:'00000000-0000-0000-0000-000000000001',scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:3};
if(fault==='stale')value.gate_version++;
if(fault==='unsafe')value.source_records=Number.MAX_SAFE_INTEGER+1;
if(fault==='valid')assert.deepEqual(m.ownerPolicyObligations(value,binding),value);
else assert.throws(()=>m.ownerPolicyObligations(value,binding));
"""
@pytest.mark.parametrize('fault',['valid',*FAULTS,'stale','unsafe'])
def test_actual_typescript_parser(fault):
    root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
    result=subprocess.run([node,'--input-type=module','-e',SCRIPT,str(root/'apps/web/src/ownerPolicyObligations.ts'),
        json.dumps(mutate(response(),fault)),fault],cwd=root,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
