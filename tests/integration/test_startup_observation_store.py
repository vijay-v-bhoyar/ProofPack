"""Locked local metadata is not accepted as genuine protected restore identity."""
from time import monotonic_ns
from uuid import uuid4
import boto3
from botocore.config import Config
import pytest

from test_access_lifecycle import repository_factory
from proofpack.auth.service import AccessService,AuthConfig
from proofpack.evidence.repository import DynamoRepository,StoreUnavailable
from proofpack.evidence.restore_fence import RestoreDataFence,RestoreFenceConfig
from proofpack.evidence.journal_anchors import AnchorCheckpoint
from proofpack.runtime.control import RuntimeControl


def test_locked_local_creation_metadata_cannot_expose_startup_or_trigger_fallback(repository_factory,monkeypatch):
    original=repository_factory()
    client=boto3.client('dynamodb',region_name='us-east-1',endpoint_url=original.client.meta.endpoint_url,
        aws_access_key_id='localtest',aws_secret_access_key='localtest',
        config=Config(connect_timeout=1,read_timeout=2,retries={'total_max_attempts':1}))
    calls=[];native=client._make_api_call
    def watched(operation,parameters):
        calls.append(operation)
        if operation not in {'DescribeTable','DescribeTimeToLive'}:
            pytest.fail('unadmitted restore identity must not read primary records or mutate startup')
        return native(operation,parameters)
    try:
        metadata=client.describe_table(TableName=original.tables['state'])['Table']
        assert not metadata.get('TableId')  # Pinned emulator limitation; no synthetic adapter.
        cfg=RestoreFenceConfig('protected-observation-journal',
            'arn:aws:dynamodb:us-east-1:000000000000:table/protected-observation-journal',
            '9'*64,AnchorCheckpoint(0,'a'*64),'b'*64,
            (('events','expected-events-creation'),('state','expected-state-creation')),'a'*64,15000)
        fence=RestoreDataFence(client,deployment=original.deployment,state_table=original.tables['state'],
            events_table=original.tables['events'],config=cfg,tick=monotonic_ns)
        repo=DynamoRepository(client,deployment=original.deployment,state_table=original.tables['state'],
            events_table=original.tables['events'],data_fence=fence)
        access=AccessService(repo,AuthConfig(original.deployment,'https://identity.example.test',b'x'*32))
        observer=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='test')
        monkeypatch.setattr(client,'_make_api_call',watched)
        with pytest.raises(StoreUnavailable,match='creation identity'):observer.observe_startup()
        assert observer.handle is None and calls==['DescribeTable']
    finally:client.close()
