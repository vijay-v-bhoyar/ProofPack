"""Corrupt only owned DynamoDB Local fixtures; no provider or production proof."""
from copy import deepcopy
import json
import pytest
from test_access_lifecycle import repository_factory,world,proof
from proofpack.auth.service import HEAD
from proofpack.evidence.repository import StoreUnavailable,Write


def state_snapshot(repository):
    result=repository.client.scan(TableName=repository.tables['state'],ConsistentRead=True,Limit=100)
    assert not result.get('LastEvaluatedKey'), 'bounded fixture snapshot must be complete'
    return sorted(json.dumps(item,sort_keys=True) for item in result['Items'])


@pytest.mark.parametrize('fault',['boolean_schema','undeclared_field','missing_bootstrap'])
@pytest.mark.parametrize('operation',['resolve','login'])
def test_invalid_stored_head_denies_actor_and_session_without_writes(world,fault,operation):
    service,repository,clock,_,credentials,_=world
    head=repository.snapshot((HEAD,))[HEAD];changed=deepcopy(head.data)
    if fault=='boolean_schema':changed['schema_version']=True
    elif fault=='undeclared_field':changed['inspection_id']='00000000-0000-0000-0000-000000000099'
    else:changed.pop('bootstrap_scope')
    repository.transact((Write(HEAD,head.revision,changed),))
    before=state_snapshot(repository)
    persisted=repository.snapshot((HEAD,))[HEAD]
    if fault=='boolean_schema':assert type(persisted.data['schema_version']) is bool
    with pytest.raises(StoreUnavailable):
        if operation=='login':service.login(proof(clock))
        else:service.resolve(credentials.cookie)
    assert state_snapshot(repository)==before
