"""Real loopback SDK transactions plus signed offline provider; no AWS/IAM proof."""
from dataclasses import replace
import pytest

from test_access_lifecycle import repository_factory
from test_first_owner import signing, setup, owner, start, head
from proofpack.auth.cognito import CognitoProvider
from proofpack.auth.oauth import OAuthFlows
from proofpack.auth.policy import Denied
from proofpack.auth.service import AccessService, HEAD, RUNTIME, user_key
from proofpack.auth.signin import SignInService
from proofpack.evidence.repository import StoreUnavailable


def world(signing, repository_factory):
    w=setup(signing);repo=repository_factory()
    w.repo=repo
    w.access=AccessService(repo,replace(w.access.config,deployment=repo.deployment),clock_ms=lambda:w.clock[0])
    config=replace(w.ordinary.flows.config,deployment=repo.deployment)
    w.ordinary=SignInService(OAuthFlows(repo,config,clock_ms=lambda:w.clock[0]),
        CognitoProvider(config,w.ordinary.provider.tokens,transport=w.ordinary.provider.transport),w.access)
    return w


def test_signed_setup_atomically_creates_one_owner_with_disabled_inspections_on_actual_store(signing,repository_factory):
    w=world(signing,repository_factory);service,args=start(w)
    credential=service.complete(**args);h=head(w);uid=h.data['bootstrap_user_id']
    rows=w.repo.snapshot((user_key(uid),RUNTIME))
    assert h.data['owner_ids']==[uid]==h.data['enabled_user_ids']
    assert rows[user_key(uid)].data['roles']==['owner']
    assert rows[RUNTIME].data['inspection_enabled'] is False
    assert w.access.resolve(credential.cookie).principal.roles==frozenset({'owner'})
    with pytest.raises(Denied):service.complete(**args)


def test_actual_store_lost_bootstrap_reply_reconciles_same_owner_without_second_effect(signing,repository_factory):
    w=world(signing,repository_factory);service,args=start(w);original=w.repo.transact;commits=[]
    def lost(writes,checks=()):
        result=original(writes,checks)
        if any(write.key==HEAD for write in writes):
            commits.append(True);raise StoreUnavailable('synthetic lost reply after actual commit')
        return result
    w.repo.transact=lost
    with pytest.raises(StoreUnavailable):service.complete(**args)
    original_head=head(w);assert original_head is not None and commits==[True]
    w.repo.transact=original;service,args=start(w,service);service.complete(**args)
    assert head(w)==original_head
    events=w.repo.client.scan(TableName=w.repo.tables['events'],ConsistentRead=True,Limit=100)
    assert not events.get('LastEvaluatedKey')
    own=[item for item in events['Items'] if item['pk']['S']=='deployment#'+w.repo.deployment]
    assert sum(item.get('data',{}).get('M',{}).get('kind')=={'S':'bootstrap'} for item in own)==1


def test_expiry_during_actual_store_bootstrap_read_prevents_owner_transaction(signing,repository_factory):
    w=world(signing,repository_factory);service,args=start(w);original=w.repo.snapshot
    def slow(keys):
        result=original(keys)
        if HEAD in keys and RUNTIME in keys:w.clock[0]+=300000
        return result
    w.repo.snapshot=slow
    with pytest.raises(Denied):service.complete(**args)
    assert head(w) is None
