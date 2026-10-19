"""Real local metadata denial and ten-item seed storage mechanics, not IAM admission."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

from botocore.exceptions import ClientError
import pytest

from test_access_lifecycle import repository_factory
from test_host import host_files
from test_restore_fence import canonical
from test_fresh_enrollment import world
from proofpack.runtime import host
from proofpack.runtime.enrollment import _plan,_Operation
from proofpack.evidence.repository import DynamoRepository
from proofpack.runtime.control import RUNTIME,DATA
from proofpack.runtime.startup_schema import restore_startup
from proofpack.evidence.privacy_admission import GATE,REGISTRY


@pytest.fixture
def native_plan(repository_factory,host_files):
    base=repository_factory();client=base.client;names={role:'proofpack-initial-'+role+'-'+uuid4().hex[:12] for role in ('state','events','journal')}
    created=[]
    try:
        for name in names.values():
            client.create_table(TableName=name,KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
                AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST');created.append(name)
        w=world(host_files);doc=w.document;doc['deployment']=base.deployment
        doc['aws'].update(state_table=names['state'],events_table=names['events'])
        cfg=doc['restore_fence'];cfg.update(journal_table=names['journal'],journal_arn='arn:aws:dynamodb:us-east-1:000000000000:table/'+names['journal'])
        root={'schema':1,'kind':'journal_root','genesis':cfg['genesis_sha256'],'sequence':0,'previous':'0'*64}
        cfg['checkpoint']['digest']=hashlib.sha256(canonical(['sealed-journal-history/v1',doc['deployment'],cfg['journal_arn'],root]).encode()).hexdigest()
        w.path.write_text(json.dumps(doc));loaded=host.load_configuration(w.path,w.secret)
        intent=replace(w.intent,operation_id=str(uuid4()),instance_id=str(uuid4()))
        plan=_plan(loaded,intent)
        yield client,names,loaded,intent,plan
    finally:
        for name in created:client.delete_table(TableName=name)


def test_actual_missing_table_id_denies_enrollment_target_before_data_or_effect(native_plan):
    client,names,loaded,intent,plan=native_plan;calls=[]
    assert not client.describe_table(TableName=names['state'])['Table'].get('TableId')
    def call(name,**kwargs):
        calls.append(name)
        if name=='get_caller_identity':
            return {'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/ProofPackEnrollment/synthetic-session'}
        assert name=='describe_table'
        return client.describe_table(**kwargs)
    # Invoke the same target validator with actual metadata. No fabricated ID or
    # regional-endpoint facade: this is not full private-command admission.
    target=SimpleNamespace(loaded=loaded,intent=intent,call=call)
    with pytest.raises(ValueError,match='physical target'):_Operation.target(target)
    assert calls==['get_caller_identity','describe_table']
    assert all(client.scan(TableName=name,Select='COUNT')['Count']==0 for name in names.values())


def test_compiled_seed_uses_real_atomic_storage_and_canonical_payloads_only(native_plan):
    client,names,loaded,intent,plan=native_plan
    # Deliberately test raw storage mechanics. This bypass is not an enrollment
    # role, metadata, quarantine, approval, release or production acceptance.
    client.transact_write_items(TransactItems=json.loads(plan.encoded_items),ClientRequestToken=intent.operation_id)
    actual=client.transact_get_items(TransactItems=json.loads(plan.encoded_reads))['Responses']
    assert actual==[{'Item':row} for row in json.loads(plan.encoded_expected)]
    repo=DynamoRepository(client,deployment=loaded.config.auth.deployment,state_table=names['state'],events_table=names['events'])
    from proofpack.evidence.repository import Key
    marker=Key('state','runtime-start#'+intent.instance_id)
    rows=repo.snapshot((RUNTIME,DATA,GATE,REGISTRY,marker))
    assert rows[RUNTIME].data['inspection_enabled'] is False and rows[DATA].data['epoch']==1
    assert rows[GATE].data['phase']=='OPEN' and rows[REGISTRY].data['active']=={}
    parsed=restore_startup(rows[marker].data);assert parsed[1:]==(0,1)
    assert sum(client.scan(TableName=name,Select='COUNT')['Count'] for name in names.values())==10


def test_native_missing_key_conflict_leaves_no_partial_protected_seed(native_plan):
    client,names,loaded,intent,plan=native_plan
    conflict=next(entry['Put'] for entry in json.loads(plan.encoded_items) if entry['Put']['Item']['sk']['S']==RUNTIME.resource)
    client.put_item(TableName=names['state'],Item=conflict['Item'])
    with pytest.raises(ClientError) as error:
        client.transact_write_items(TransactItems=json.loads(plan.encoded_items),ClientRequestToken=intent.operation_id)
    assert error.value.response['Error']['Code']=='TransactionCanceledException'
    assert client.scan(TableName=names['journal'],Select='COUNT')['Count']==0
    assert client.scan(TableName=names['events'],Select='COUNT')['Count']==0
    assert client.scan(TableName=names['state'],Select='COUNT')['Count']==1
