"""Cross-owner/collateral/lifetime checks under genuine modeled request writers."""
from copy import deepcopy
from dataclasses import replace
import pytest

from test_metadata_history_consumption import configured, read, limits, create, cancel, no_sdk
from test_capture_lineage import uid
from proofpack.auth.service import IdentityProof, digest
from proofpack.evidence.repository import Key
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.metadata_history import derive, MetadataHistoryHeld


def test_successor_owner_cancellation_keeps_original_creator_and_separate_quotas(monkeypatch):
    # The base fixture has no operational notice; provision one at construction
    # rather than bypassing the genuine invitee acceptance requirement.
    import test_access_context as context
    original_config=context.AuthConfig
    monkeypatch.setattr(context,'AuthConfig',lambda *a,**k:original_config(*a,
        **(k|{'notice_version':'synthetic-metadata-v1','notice_text':'Synthetic metadata history test notice'})))
    w=configured(monkeypatch);access=w[1].access
    invitation=access.create_invitation(w[3],target_subject='metadata-successor',target_email='successor@example.test',
        roles=['operator'],ttl_seconds=60,idempotency_key='metadata-successor-invite')
    proof=IdentityProof(access.config.issuer,'metadata-successor','successor@example.test',True,True,100,10000,'Synthetic successor')
    credential=access.login(proof,invitation_id=invitation['id'])
    accepted=access.accept_invitation(access.resolve(credential.cookie,allow_invitee=True),invitation_id=invitation['id'],
        capability=invitation['capability'],idempotency_key='metadata-successor-accept',
        notice_version=access.config.notice_version,notice_sha256=digest(access.config.notice_text))
    credential=access.login(proof)  # Acceptance invalidates the restricted session.
    transfer=access.begin_transfer(w[3],target_id=accepted['user_id'],expected_target_version=1,idempotency_key='metadata-transfer')
    access.accept_transfer(access.resolve(credential.cookie),transfer_id=transfer['id'],idempotency_key='metadata-transfer-accept')
    actor=access.resolve(access.login(proof).cookie)  # Transfer invalidates earlier grants.
    cancel(w[1],actor,w[7]);current=create(w[1],actor,idempotency_key='successor-metadata-request')
    w=(*w[:3],actor,*w[4:7],current,w[8]);before=deepcopy(w[5]);result=read(w)
    assert sum(r.family=='metadata-quota' for r in result.corpus.metadata_history.records)==2
    assert result.corpus.metadata_history.historical_authority_proven is False
    assert result.corpus.metadata_history.policy_resolved is False and w[5]==before and w[-1].wait_for_drain(0)


def test_mixed_historical_scope_remains_collateral_and_current_scope_is_not_expanded(monkeypatch):
    w=configured(monkeypatch);original=w[5][Key('state','inspection#'+uid(1))]
    second=replace(original,key=Key('state','inspection#'+uid(100)),data={**original.data,'id':uid(100),
        'latest_input_sequence':0,'verified_sequence':0,'latest_observation_id':None})
    w[5][second.key]=second
    cancel(w[1],w[3],w[7]);mixed=create(w[1],w[3],inspection_ids=(uid(1),uid(100)),idempotency_key='mixed-metadata-scope')
    cancel(w[1],w[3],mixed,idempotency_key='cancel-mixed-metadata')
    current=create(w[1],w[3],idempotency_key='current-single-metadata')
    w=(*w[:7],current,w[8]);before=deepcopy(w[5]);result=read(w)
    record=next(r for r in result.accounting.entries if r.reference.key==Key('state','metadata-request#'+mixed['id']))
    assert record.inspection_ids==(uid(1),uid(100)) and record.reason=='METADATA_RETENTION_POLICY_REQUIRED'
    assert result.corpus.scope.inspection_ids==(uid(1),)
    links=[link for link in result.accounting.relationships if link.source==record.reference.key]
    assert {link.inspection for link in links}=={Key('state','inspection#'+uid(1)),Key('state','inspection#'+uid(100))}
    assert w[5]==before and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['unknown-root-schema','missing-original-root','foreign-configuration','orphan-quota'])
def test_legacy_missing_or_foreign_history_stays_held(monkeypatch,fault):
    w=configured(monkeypatch);key=Key('state','metadata-request#'+w[7]['id'])
    if fault=='unknown-root-schema':w[5][key].data['schema_version']=2
    elif fault=='missing-original-root':del w[5][key]
    elif fault=='foreign-configuration':
        with pytest.raises(HeldCorpusHeld):read(w,metadata_configuration_sha256='0'*64)
        assert w[-1].wait_for_drain(0)
        return
    else:
        from proofpack.evidence.repository import Row
        k=Key('state','metadata-owner-quota#'+'0'*64);w[5][k]=Row(k,1,{'minute':0,'count':1})
    before=deepcopy(w[5])
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[5]==before and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['deadline','backward-clock','cancelled','final-source','final-limit'])
def test_original_direct_lifetime_and_final_source_are_preserved(monkeypatch,fault):
    w=configured(monkeypatch);result=read(w);corpus=result.corpus
    rows=tuple(w[5].values());bound=limits();calls=[0];clock=[1]
    arguments=dict(configuration_sha256=w[1]._configuration,requested_inspections=corpus.scope.inspection_ids,
        scope_sha256=corpus.metadata_history.scope_sha256,now_ms=100,limits=bound,
        deadline_ns=1000,tick=lambda:clock[0])
    if fault in {'final-source','final-limit'}:
        derive(rows,corpus.inventory,corpus.proof,corpus.auth_history,**arguments,checkpoint=lambda:calls.__setitem__(0,calls[0]+1))
        target=calls[0];calls[0]=0
    def checkpoint():
        calls[0]+=1
        if fault=='deadline':clock[0]=1000
        elif fault=='backward-clock':clock[0]=2 if calls[0]==1 else 1
        elif fault=='cancelled':raise MetadataHistoryHeld('synthetic cancellation')
        elif calls[0]==target:
            if fault=='final-source':w[5][Key('state','metadata-request#'+w[7]['id'])].data['status']='changed'
            else:object.__setattr__(bound,'max_work',bound.max_work+1)
    with pytest.raises(MetadataHistoryHeld):derive(rows,corpus.inventory,corpus.proof,corpus.auth_history,**arguments,checkpoint=checkpoint)


def test_request_history_read_does_not_commit_business_or_quota_writes(monkeypatch):
    w=configured(monkeypatch);before=deepcopy(w[5])
    monkeypatch.setattr(w[4],'transact',lambda *a,**k:pytest.fail('history read attempted write'))
    read(w)
    assert w[5]==before and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('field,bad',[('max_inspections',65),('writes_per_minute',101)])
def test_original_writer_limit_caps_cannot_be_raised(field,bad):
    with pytest.raises(ValueError):replace(limits(),**{field:bad})


def test_v6_digest_independently_binds_auth_and_metadata_context(monkeypatch):
    import hashlib,json
    from dataclasses import asdict
    w=configured(monkeypatch);result=read(w);c=result.corpus;a=result.accounting
    header=(a.policy,c.inventory.summary_sha256,c.scope.inspection_ids,c.runtime_context.summary_sha256,
        c.access_context.summary_sha256,c.auth_history.summary_sha256,c.metadata_history.summary_sha256)
    payloads=[header,*[asdict(e) for e in a.entries],*[asdict(e) for e in a.relationships]]
    frames=[]
    for value in payloads:
        encoded=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        frames.append(str(len(encoded)).encode()+b':'+encoded)
    framed=b''.join(frames)
    assert len(framed)==a.summary_bytes and hashlib.sha256(framed).hexdigest()==a.summary_sha256


def test_ambiguous_or_partial_consumer_configuration_rejected_before_inventory(monkeypatch):
    w=configured(monkeypatch)
    monkeypatch.setattr(w[1].admission,'drained',lambda **k:pytest.fail('invalid configuration reached inventory'))
    for change in [dict(auth_history_limits=None),dict(metadata_history_limits=None),dict(metadata_configuration_sha256=None)]:
        with pytest.raises(ValueError):read(w,**change)
