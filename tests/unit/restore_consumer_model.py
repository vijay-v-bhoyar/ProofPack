"""Closed SDK protocol model; all protected release/provenance is TEST-INJECTED."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4
from botocore.exceptions import ClientError, ReadTimeoutError

from test_restore_fence import world
from proofpack.auth.service import AccessService, AuthConfig, IdentityProof, BootstrapApproval
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionLimits
from proofpack.runtime.control import RuntimeControl
from proofpack.runtime.host import load_configuration
from proofpack.runtime.composition import ApplicationClients, create_configured_app


ISSUER = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic'


def sdk_world(*, deployment='synthetic', artifact_sha256='b'*64):
    repo, fence, client, identities = world(deployment=deployment,artifact_sha256=artifact_sha256)
    install_model_transactions(client)
    return repo, fence, client, identities


def install_model_transactions(client):
    """Shared SDK-condition interpreter; adds no rows or release authority."""
    def transact(**kw):
        client.calls.append(('transact_write_items', deepcopy(kw)))
        if client.before_commit: client.before_commit()
        staged = []
        for request in kw['TransactItems']:
            if 'ConditionCheck' in request:
                value = request['ConditionCheck']
                old = client.items.get(client.identity(value['TableName'], value['Key']))
                values = value['ExpressionAttributeValues']
                if ':body' in values:
                    valid = old is not None and old.get('body') == values[':body'] and old.get('sha256') == values[':sha']
                else:
                    valid = old is not None and old.get('revision') == values[':expected'] and 'payload_erasure' not in old
            else:
                value = request['Put']; item = value['Item']; identity = client.identity(value['TableName'], item)
                old = client.items.get(identity)
                valid = (old is None if value['ConditionExpression'].startswith('attribute_not_exists') else
                    old is not None and old.get('revision') == value['ExpressionAttributeValues'][':expected'] and 'payload_erasure' not in old)
                staged.append((identity,deepcopy(item)))
            if not valid:
                raise ClientError({'Error':{'Code':'TransactionCanceledException'},
                    'CancellationReasons':[{'Code':'ConditionalCheckFailed'}]}, 'TransactWriteItems')
        client.items.update(staged)
        if client.lost_reply: raise ReadTimeoutError(endpoint_url='synthetic-local')
        return {}
    client.transact_write_items = transact


def auth_world():
    repo, fence, client, identities = sdk_world()
    config = AuthConfig(repo.deployment,ISSUER,b'x'*32,initial_owner_subject='owner',
        bootstrap_receipt_sha256='a'*64,notice_version='synthetic-v1',notice_text='Synthetic notice, no real consent.')
    clock = [1000]
    access = AccessService(repo,config,clock_ms=lambda:clock[0])
    proof = IdentityProof(ISSUER,'owner','owner@example.invalid',True,True,1000,61000,'Synthetic owner')
    access.bootstrap(BootstrapApproval(ISSUER,'owner','a'*64),proof)
    return access, fence, client, identities, proof, clock


def factory_world(host_files):
    config = load_configuration(*host_files[:2]).config
    _, fence, client, identities = sdk_world(artifact_sha256=config.artifact_sha256)
    config = replace(config, artifact_sha256=fence.config.artifact_sha256,
        auth=replace(config.auth,deployment='synthetic'), oauth=replace(config.oauth,deployment='synthetic'),
        objects=replace(config.objects,deployment='synthetic'),state_table='restored-state',events_table='restored-events',
        restore_fence=fence.config,maintenance_enabled=False)
    closed = []
    client.meta.service_model = SimpleNamespace(service_name='dynamodb')
    client.meta.region_name = 'us-east-1'; client.meta.endpoint_url = 'https://dynamodb.us-east-1.amazonaws.com'
    client.close = lambda:closed.append('dynamodb')
    def transport(service):
        return SimpleNamespace(meta=SimpleNamespace(service_model=SimpleNamespace(service_name=service),
            region_name='us-east-1',endpoint_url='https://'+service+'.us-east-1.amazonaws.com',
            config=SimpleNamespace(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1})),
            get_caller_identity=lambda:{'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/synthetic/test'},
            close=lambda:closed.append(service))
    clients = ApplicationClients(client,transport('s3'),transport('sts'))
    app = create_configured_app(config,clients,clock_ms=lambda:1000,tick_ns=lambda:1)
    return app, config, clients, identities, closed


def seed_admission(app, config):
    # A separate explicit fixture incarnation enrolls the metadata coordinator.
    # Configured startup must consume this enrollment, never synthesize it.
    access = app.state.access_service
    runtime = RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256=config.artifact_sha256,
        controls_sha256=config.controls_sha256,environment=config.environment)
    runtime.start()
    limits = config.metadata_admission
    coordinator = PersistentAdmission(runtime,limits=AdmissionLimits(limits.max_active,limits.max_lease_ms),clock_ms=lambda:1000)
    coordinator.initialize(limits.enrollment_sha256)
