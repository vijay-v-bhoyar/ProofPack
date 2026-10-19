"""Execute strict server DTOs and actual TypeScript parsers for v6/v2 delivery."""
from pathlib import Path
import json,shutil,subprocess
import pytest
from pydantic import ValidationError
from proofpack.evidence.owner_metadata_http import MetadataReviewResult,MetadataPolicyObligationsResult
from proofpack.evidence.auth_history import FAMILIES


def response(kind):
    value=dict(id='00000000-0000-0000-0000-000000000001',scope_sha256='a'*64,request_version=1,gate_version=2,
        control_version=3,accounting_policy='conservative-family-accounting-v6',historical=True,read_only=True,
        auth_history_policy_resolved=False,historical_auth_authority_proven=False,metadata_history_policy_resolved=False,
        historical_metadata_authority_proven=False,can_confirm_cleanup=False,erasure_complete=False,request_fulfilled=False)
    if kind=='review':value.update(counts=dict(AFFECTED=1,SHARED=0,CONTEXT=2,UNRELATED=0,UNRESOLVED=3),total_records=6)
    else:
        families={name:0 for name in FAMILIES};families['user']=1
        value.update(policy='privacy-policy-obligations-v2',family_counts=families,validated_auth_records=1,source_records=24,
            historical_dependencies_unavailable=0,next_step='OWNER_D11_POLICY_DECISION_REQUIRED',
            metadata_family_counts={name:1 for name in ['metadata-request','metadata-operation','metadata-event','metadata-quota']},
            validated_metadata_records=4,metadata_historical_dependencies_unavailable=0)
    return value


FAULTS=['private','metadata-policy','metadata-authority','auth-policy','cleanup','fulfilled','missing-flag','coerced-flag',
        'bool-count','sum','source-total','version','extra-family','missing-auth','unsafe']
def mutate(value,kind,fault):
    if fault=='private':value['records']=['metadata-request#private']
    elif fault=='metadata-policy':value['metadata_history_policy_resolved']=True
    elif fault=='metadata-authority':value['historical_metadata_authority_proven']=True
    elif fault=='auth-policy':value['auth_history_policy_resolved']=True
    elif fault=='cleanup':value['can_confirm_cleanup']=True
    elif fault=='fulfilled':value['request_fulfilled']=True
    elif fault=='missing-flag':del value['metadata_history_policy_resolved']
    elif fault=='coerced-flag':value['historical_metadata_authority_proven']=0
    elif fault=='bool-count':value['counts' if kind=='review' else 'metadata_family_counts']['CONTEXT' if kind=='review' else 'metadata-quota']=True
    elif fault=='sum':value['total_records' if kind=='review' else 'validated_metadata_records']+=1
    elif fault=='source-total':value['total_records' if kind=='review' else 'source_records']=4
    elif fault=='version':value['accounting_policy']='conservative-family-accounting-v5'
    elif fault=='extra-family':
        if kind=='review':value['metadata_family_counts']={}
        else:value['metadata_family_counts']['unknown-family']=0
    elif fault=='missing-auth':del value['historical_auth_authority_proven']
    elif fault=='unsafe':value['total_records' if kind=='review' else 'source_records']=2**53
    return value


@pytest.mark.parametrize('kind',['review','policy'])
@pytest.mark.parametrize('fault',['valid',*FAULTS])
def test_closed_server_contract_cannot_claim_policy_approval_or_deliver_private_history(kind,fault):
    value=mutate(response(kind),kind,fault);model=MetadataReviewResult if kind=='review' else MetadataPolicyObligationsResult
    if fault=='valid':assert model.model_validate(value).model_dump()==value
    else:
        with pytest.raises(ValidationError):model.model_validate(value)


SCRIPT=r"""
import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.argv[1]).href),value=JSON.parse(process.argv[2]),fault=process.argv[3],name=process.argv[4];
const binding={id:'00000000-0000-0000-0000-000000000001',scope_sha256:'a'.repeat(64),request_version:1,gate_version:2,control_version:3};
if(fault==='stale')value.gate_version++;
if(fault==='valid')assert.deepEqual(m[name](value,binding),value);
else assert.throws(()=>m[name](value,binding));
"""
@pytest.mark.parametrize('kind',['review','policy'])
@pytest.mark.parametrize('fault',['valid',*FAULTS,'stale'])
def test_actual_typescript_parser_checks_versions_flags_counts_and_request_binding(kind,fault):
    root=Path(__file__).resolve().parents[2];node=shutil.which('node');assert node
    name='ownerMetadataReview' if kind=='review' else 'ownerPolicyObligations'
    result=subprocess.run([node,'--input-type=module','-e',SCRIPT,str(root/('apps/web/src/'+name+'.ts')),
        json.dumps(mutate(response(kind),kind,fault)),fault,name],cwd=root,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
