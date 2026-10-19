"""Full held readers consume genuine v2 writer output on isolated model rows.

Protected release/identity is synthetic; these checks grant no restore, current
authentication, approved retention, classification or cleanup authority.
"""
from copy import deepcopy
from dataclasses import replace
from uuid import UUID
import pytest

from restore_consumer_model import sdk_world
from test_access_context import complete, read as read_access
from test_auth_history_consumption import read as read_auth
from test_capture_lineage import DEPLOYMENT, uid
from proofpack.auth.service import AccessService, AuthConfig, IdentityProof, digest
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.held_corpus import HeldCorpusHeld


def versioned_history(monkeypatch):
    reader, owner, _, rows, old_cookie = complete(monkeypatch)
    repo, fence, client, _ = sdk_world(deployment=DEPLOYMENT)
    session = Key('state','session#'+uid(5))
    # Copy an isolated source fixture, excluding the original login pair so the
    # real fenced writer can create this inspection's exact origin session.
    for key,row in rows.items():
        if key in (session,old_cookie):
            continue
        item=repo.key(key)|{'revision':{'N':str(row.revision)},'data':repo.serialize.serialize(row.data)}
        client.items[client.identity(repo.tables[key.table],item)]=item
    issuer='https://identity.example.test'
    config=AuthConfig(DEPLOYMENT,issuer,b'x'*32)
    access=AccessService(repo,config,clock_ms=lambda:2)
    proof=IdentityProof(issuer,'synthetic-origin','origin@example.test',True,True,1,400,'Synthetic origin')
    with monkeypatch.context() as m:
        m.setattr('proofpack.auth.service.uuid4',lambda:UUID(uid(5)))
        credential=access.login(proof)
    actor=access.resolve(credential.cookie)
    assert actor.session.key==session
    assert actor.session.data['restore_generation_sha256']==fence.generation_sha256()=='c'*64
    cookie=Key('state','cookie#'+digest(credential.cookie))
    generated=repo.snapshot((session,cookie))
    rows.pop(old_cookie)
    rows.update(generated)
    return reader,owner,rows,session


@pytest.mark.parametrize('read',[read_access,read_auth],ids=['origin-context','complete-auth-history'])
def test_full_readers_consume_fenced_writer_session_without_current_authority(monkeypatch,read):
    reader,owner,rows,session=versioned_history(monkeypatch)
    before=deepcopy(rows)
    result=read(reader)
    assert rows==before and owner.wait_for_drain(0)
    context=result.corpus.access_context
    assert context.read_only is True and context.can_confirm_cleanup is False
    assert session in {r.key for r in context.records}
    if read is read_auth:
        auth=result.corpus.auth_history
        assert auth.read_only is True and auth.can_confirm_cleanup is False and auth.policy_resolved is False
        assert any(r.family=='session' for r in auth.records)
    # Intact old-generation content is history, never current login authority.
    rows[session]=replace(rows[session],data=rows[session].data|{'restore_generation_sha256':'d'*64})
    historical=read(reader)
    assert historical.corpus.binding_sha256!=result.corpus.binding_sha256
    assert historical.corpus.access_context.can_confirm_cleanup is False
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('read',[read_access,read_auth],ids=['origin-context','complete-auth-history'])
@pytest.mark.parametrize('fault',['bool_version','float_version','missing_generation','uppercase_generation','unknown_field'])
def test_full_readers_hold_malformed_v2_without_repair_or_cleanup(monkeypatch,read,fault):
    reader,owner,rows,session=versioned_history(monkeypatch)
    body=deepcopy(rows[session].data)
    if fault=='bool_version':body['session_schema_version']=True
    elif fault=='float_version':body['session_schema_version']=2.0
    elif fault=='missing_generation':body.pop('restore_generation_sha256')
    elif fault=='uppercase_generation':body['restore_generation_sha256']='A'*64
    else:body['unreviewed']=True
    rows[session]=Row(session,rows[session].revision,body)
    before=deepcopy(rows)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert rows==before and owner.wait_for_drain(0)
