"""Even a matching digest cannot admit malformed or cross-kind initial releases."""
from dataclasses import replace
import hashlib
import json

import pytest

from test_host import host_files
from test_fresh_enrollment import world,run,approve_candidate
from test_restore_fence import canonical
from proofpack.evidence.restore_fence import RestoreDataFence,RestoreFenceHeld


def committed(host_files):
    w=world(host_files);approve_candidate(w,run(w));run(w,commit=True)
    key=next(k for k in w.client.items if k[2].startswith('restore-admission#'))
    return w,key


@pytest.mark.parametrize('fault',['unknown','missing','bool-created','bool-expires','expanded-review','role-account',
    'role-path','upper-operation','same-identifiers','configuration','schema-bool','restore-proof'])
def test_initial_release_rejects_unsupported_shape_even_with_matching_protected_hash(host_files,fault):
    w,key=committed(host_files);item=w.client.items[key];body=json.loads(item['body']['S'])
    if fault=='unknown':body['approved']=True
    elif fault=='missing':body.pop('initial_state_sha256')
    elif fault=='bool-created':body['created_at_ms']=True
    elif fault=='bool-expires':body['expires_at_ms']=True
    elif fault=='expanded-review':body['expires_at_ms']=301001
    elif fault=='role-account':body['enrollment_role_arn']='arn:aws:iam::111111111111:role/ProofPackEnrollment'
    elif fault=='role-path':body['enrollment_role_arn']='arn:aws:iam::000000000000:role/path/ProofPackEnrollment'
    elif fault=='upper-operation':body['operation_id']='00000000-0000-4000-8000-0000000000AA'
    elif fault=='same-identifiers':body['instance_id']=body['operation_id']
    elif fault=='configuration':body['configuration_sha256']='0'*64
    elif fault=='schema-bool':body['schema_version']=True
    else:body['backup_sha256']='a'*64
    item['body']={'S':canonical(body)}
    digest=hashlib.sha256(canonical(['initial-data-release/v1',w.loaded.config.auth.deployment,w.loaded.config.restore_fence.journal_arn,body]).encode()).hexdigest()
    item['sha256']={'S':digest};config=replace(w.loaded.config.restore_fence,release_sha256=digest)
    fence=RestoreDataFence(w.client,deployment=w.loaded.config.auth.deployment,state_table=w.loaded.config.state_table,events_table=w.loaded.config.events_table,config=config,tick=lambda:1)
    with pytest.raises(RestoreFenceHeld):fence.check()


def test_same_name_replaced_physical_journal_cannot_supply_an_initial_release(host_files):
    w,key=committed(host_files);config=w.loaded.config;w.client.calls.clear()
    w.client.ids[config.restore_fence.journal_table]='replacement-journal-creation'
    fence=RestoreDataFence(w.client,deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table,config=config.restore_fence,tick=lambda:1)
    with pytest.raises(RestoreFenceHeld,match='journal creation'):fence.check()
    assert not any(n=='transact_get_items' for n,k in w.client.calls)


def test_fresh_release_cannot_be_relabelled_as_a_restored_backup_release(host_files):
    w,key=committed(host_files);config=w.loaded.config
    restored=replace(config.restore_fence,release_kind='restored-data-release',journal_table_id=None,initial_configuration_sha256=None)
    fence=RestoreDataFence(w.client,deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table,config=restored,tick=lambda:1)
    with pytest.raises(RestoreFenceHeld):fence.check()
