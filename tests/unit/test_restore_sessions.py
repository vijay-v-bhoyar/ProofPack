"""Real auth writers/resolvers on a fenced SDK model, not real identity proof."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import pytest

from restore_consumer_model import auth_world
from proofpack.auth.service import AccessService
from proofpack.auth.policy import Denied
from proofpack.auth.session_schema import session_generation, LEGACY_FIELDS
from proofpack.evidence.repository import DynamoRepository, StoreUnavailable
from proofpack.evidence.restore_fence import RestoreDataFence


def test_fenced_login_emits_version2_and_resolves_only_current_generation():
    access,fence,client,identities,proof,clock = auth_world()
    credential = access.login(proof); actor = access.resolve(credential.cookie)
    assert actor.session.data['session_schema_version'] == 2
    assert actor.session.data['restore_generation_sha256'] == fence.generation_sha256() == 'c'*64
    assert access._fresh(actor).session == actor.session


@pytest.mark.parametrize('fault',['legacy','generation','bool_version','missing_generation','unknown_field'])
def test_legacy_malformed_or_mismatched_sessions_cannot_resolve_or_refresh(fault):
    access,fence,client,identities,proof,clock = auth_world(); credential = access.login(proof)
    actor = access.resolve(credential.cookie); key = access.repository.key(actor.session.key)
    item = client.items[client.identity(access.repository.tables['state'],key)]
    body = item['data']['M']
    if fault=='legacy':body.pop('session_schema_version');body.pop('restore_generation_sha256')
    elif fault=='generation':body['restore_generation_sha256']={'S':'f'*64}
    elif fault=='bool_version':body['session_schema_version']={'BOOL':True}
    elif fault=='missing_generation':body.pop('restore_generation_sha256')
    else:body['unreviewed']={'BOOL':True}
    with pytest.raises(Denied):access.resolve(credential.cookie)
    with pytest.raises(Denied):access._fresh(actor)


def test_new_protected_release_needs_new_login_and_old_resolver_is_fenced_out():
    access,fence,client,identities,proof,clock = auth_world(); old = access.login(proof)
    raw = client.items[identities[2]]; body = json.loads(raw['body']['S']);body['runtime_generation_sha256']='d'*64
    encode=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True)
    digest=hashlib.sha256(encode(['restored-data-release/v1',access.repository.deployment,fence.config.journal_arn,body]).encode()).hexdigest()
    raw['body']['S']=encode(body);raw['sha256']['S']=digest
    current=RestoreDataFence(client,deployment=access.repository.deployment,state_table=access.repository.tables['state'],
        events_table=access.repository.tables['events'],config=replace(fence.config,release_sha256=digest),tick=lambda:1)
    repo=DynamoRepository(client,deployment=access.repository.deployment,state_table=access.repository.tables['state'],
        events_table=access.repository.tables['events'],data_fence=current)
    service=AccessService(repo,access.config,clock_ms=lambda:clock[0])
    with pytest.raises(Denied):service.resolve(old.cookie)
    with pytest.raises(StoreUnavailable):access.resolve(old.cookie)
    new=service.login(proof)
    assert service.resolve(new.cookie).session.data['restore_generation_sha256']=='d'*64


def test_unfenced_resolver_cannot_accept_a_version2_session():
    access,fence,client,identities,proof,clock=auth_world();credential=access.login(proof)
    repo=DynamoRepository(client,deployment=access.repository.deployment,state_table=access.repository.tables['state'],events_table=access.repository.tables['events'])
    plain=AccessService(repo,access.config,clock_ms=lambda:clock[0])
    with pytest.raises(Denied):plain.resolve(credential.cookie)


@pytest.mark.parametrize('bad',[True,False,1,3,'2',None])
def test_history_session_version_is_an_exact_discriminator(bad):
    body={k:None for k in LEGACY_FIELDS};body.update(session_schema_version=bad,restore_generation_sha256='a'*64)
    with pytest.raises(ValueError):session_generation(body)


def test_history_shape_supports_legacy_and_version2_without_authentication_claim():
    body={k:None for k in LEGACY_FIELDS}
    assert session_generation(body) is None
    v2=body|{'session_schema_version':2,'restore_generation_sha256':'a'*64}
    assert session_generation(v2)=='a'*64
    for mutation in [v2|{'extra':True},body|{'restore_generation_sha256':'a'*64},v2|{'restore_generation_sha256':'A'*64}]:
        with pytest.raises(ValueError):session_generation(mutation)
