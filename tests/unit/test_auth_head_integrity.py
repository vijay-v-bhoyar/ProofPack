"""Current access-head integrity using real auth writers on modeled storage."""
from copy import deepcopy
from decimal import Decimal
from uuid import UUID
import pytest
from botocore.client import BaseClient
from test_privacy_admission import ModelRepository
from proofpack.auth.service import AccessService,AuthConfig,IdentityProof,BootstrapApproval,HEAD
from proofpack.evidence.repository import Key,Row,StoreUnavailable


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('head model test attempted an SDK call')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def world():
    repository=ModelRepository()
    issuer='https://identity.example.test'
    config=AuthConfig(repository.deployment,issuer,b'x'*32,initial_owner_subject='schema-owner',bootstrap_receipt_sha256='f'*64)
    service=AccessService(repository,config,clock_ms=lambda:1000)
    proof=IdentityProof(issuer,'schema-owner','owner@example.test',True,True,1000,100000,'Synthetic owner')
    uid=service.bootstrap(BootstrapApproval(issuer,proof.subject,'f'*64),proof)
    credentials=service.login(proof)
    return service,repository,proof,credentials,uid


def corrupt(repository,changes,*,drop=None,revision=None,key=None):
    original=repository.rows[HEAD]
    data={**deepcopy(original.data),**changes}
    if drop is not None:data.pop(drop)
    repository.rows[HEAD]=Row(key or HEAD,original.revision+1 if revision is None else revision,data)


@pytest.mark.parametrize('version',[1,Decimal('1'),Decimal('1.000')],ids=['integer','stored-decimal','integral-decimal'])
@pytest.mark.parametrize('operation',['resolve','login'])
def test_exact_writer_head_and_supported_storage_integer_remain_usable(version,operation):
    service,repository,proof,credentials,uid=world()
    corrupt(repository,{'schema_version':version})
    if operation=='login':credentials=service.login(proof)
    actor=service.resolve(credentials.cookie)
    assert actor.member.data['id']==uid and service.me(actor)['id']==uid
    assert actor.head.data['schema_version']==version


BAD=[
    pytest.param({'schema_version':True},None,id='boolean-schema'),
    pytest.param({'schema_version':1.0},None,id='float-schema'),
    pytest.param({'schema_version':'1'},None,id='text-schema'),
    pytest.param({'schema_version':Decimal('NaN')},None,id='nan-schema'),
    pytest.param({'schema_version':Decimal('sNaN')},None,id='signaling-nan-schema'),
    pytest.param({'schema_version':Decimal('Infinity')},None,id='infinite-schema'),
    pytest.param({'inspection_id':str(UUID(int=99))},None,id='undeclared-business-field'),
    pytest.param({},'bootstrap_scope',id='missing-bootstrap-binding'),
    pytest.param({'bootstrap_scope':'not-a-sha'},None,id='invalid-bootstrap-scope'),
    pytest.param({'bootstrap_receipt':'F'*64},None,id='noncanonical-bootstrap-receipt'),
    pytest.param({'bootstrap_user_id':'not-a-uuid'},None,id='invalid-bootstrap-user'),
]


@pytest.mark.parametrize('changes,drop',BAD)
@pytest.mark.parametrize('operation',['resolve','login'])
def test_malformed_head_blocks_session_admission_without_writes(changes,drop,operation):
    service,repository,proof,credentials,_=world()
    corrupt(repository,changes,drop=drop)
    before=deepcopy(repository.rows)
    with pytest.raises(StoreUnavailable):
        if operation=='login':service.login(proof)
        else:service.resolve(credentials.cookie)
    assert repository.rows==before


@pytest.mark.parametrize('field',['enabled_user_ids','owner_ids','pending_invitation_ids'])
def test_nonwriter_collection_type_is_not_silently_normalized(field):
    service,repository,_,credentials,_=world()
    corrupt(repository,{field:tuple(repository.rows[HEAD].data[field])})
    before=deepcopy(repository.rows)
    with pytest.raises(StoreUnavailable):service.resolve(credentials.cookie)
    assert repository.rows==before


def test_duplicate_owner_membership_is_invalid_security_state():
    service,repository,_,credentials,uid=world()
    corrupt(repository,{'owner_ids':[uid,uid]})
    before=deepcopy(repository.rows)
    with pytest.raises(StoreUnavailable):service.resolve(credentials.cookie)
    assert repository.rows==before


@pytest.mark.parametrize('revision',[True,0,Decimal('1')])
def test_repository_revision_is_not_a_stored_payload_integer(revision):
    service,repository,_,credentials,_=world();corrupt(repository,{},revision=revision)
    with pytest.raises(StoreUnavailable):service.resolve(credentials.cookie)


def test_wrong_row_key_cannot_be_used_as_access_head():
    service,repository,_,credentials,_=world();corrupt(repository,{},key=Key('state','other-head'))
    with pytest.raises(StoreUnavailable):service.resolve(credentials.cookie)


def test_historical_bootstrap_user_is_not_required_to_remain_enabled():
    service,repository,_,_,_=world()
    corrupt(repository,{'bootstrap_user_id':str(UUID(int=98))})
    assert service._head(repository.rows[HEAD])['bootstrap_user_id']==str(UUID(int=98))
