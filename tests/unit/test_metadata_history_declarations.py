"""Coherent malformed metadata cannot invent gate/runtime declarations."""
from copy import deepcopy
from dataclasses import replace
import json
import pytest
from test_metadata_history_consumption import configured, read, no_sdk
from proofpack.auth.service import digest
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.repository import Key
from proofpack.evidence.resource_bindings import _payload_sha256


@pytest.mark.parametrize('field',['initial_gate_revision','initial_runtime_epoch'])
def test_root_declaration_must_match_available_original_writer_references(monkeypatch,field):
    w=configured(monkeypatch);key=Key('state','metadata-request#'+w[7]['id']);root=w[5][key]
    value=deepcopy(root.data);value[field]+=1
    value['original_request_sha256']=_payload_sha256({k:v for k,v in value.items() if k!='original_request_sha256'})
    w[5][key]=replace(root,data=value)
    # Rebind current-schema hashes coherently. This does not change the actual
    # gate write's predecessor or the original runtime check declaration.
    for k,row in list(w[5].items()):
        binding=row.data.get('resource_bindings',{})
        if binding.get('operation')!='owner-metadata-create':continue
        data=deepcopy(row.data)
        for ref in data['resource_bindings']['writes']:
            if ref['table']==key.table and ref['resource']==key.resource:ref['sha256']=_payload_sha256(value)
        if k.table=='state':
            data['result']['request_sha256']=value['original_request_sha256']
            body={'inspection_ids':value['scope']['inspection_ids'],'expected_gate_version':value['initial_gate_revision'],
                'expected_control_version':value['initial_control_version'],'interruption_acknowledged':True}
            data['body_hash']=digest(json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False))
        w[5][k]=replace(row,data=data)
    before=deepcopy(w[5])
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[5]==before and w[-1].wait_for_drain(0)
