"""Genuine auth writers on isolated model rows; no provider/user acceptance."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from urllib.parse import parse_qs, urlsplit
import pytest
from botocore.client import BaseClient
from test_access_context import complete, limits as access_limits, read as read_v4
from test_runtime_context import limits as runtime_limits
from test_corpus_accounting import LIMITS
from test_held_corpus import REQUEST
from test_capture_lineage import uid, DEPLOYMENT
from proofpack.auth.service import AccessService, AuthConfig, IdentityProof, digest
from proofpack.auth.policy import Role
from proofpack.auth.oauth import OAuthFlows, OAuthConfig
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.held_corpus import HeldCorpusHeld


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    monkeypatch.setattr(BaseClient, '_make_api_call', lambda *a, **k: pytest.fail('model attempted SDK'))


def history(monkeypatch, mode='full'):
    reader, owner, repo, rows, owner_cookie = complete(monkeypatch)
    config = AuthConfig(DEPLOYMENT, 'https://identity.example.test', b'x'*32,
        notice_version='synthetic-v1', notice_text='synthetic notice')
    clock=[10]
    service = AccessService(repo, config, clock_ms=lambda: clock[0])
    actor = lambda: service._resolve_key(owner_cookie)
    if mode != 'bootstrap':
        invite = service.create_invitation(actor(), target_subject='target', target_email='target@example.test',
            roles=['operator'], ttl_seconds=1 if mode.startswith('expired') else 60, idempotency_key='invite')
        proof = IdentityProof(config.issuer, 'target', 'target@example.test', True, True, 10, 1000, 'Synthetic target')
        credential = service.login(proof, invitation_id=invite['id'])
        if mode in {'revoked','repeat-revoked'}:
            for n in range(2 if mode=='repeat-revoked' else 1):
                root=rows[Key('state','invitation#'+invite['id'])]
                service.revoke_invitation(actor(),invitation_id=invite['id'],expected_revision=root.revision,idempotency_key='revoke-'+str(n))
        elif mode=='declined':
            service.decline_invitation(service.resolve(credential.cookie,allow_invitee=True),invitation_id=invite['id'],idempotency_key='decline')
        elif mode.startswith('expired'):
            clock[0]=2010
            fresh=IdentityProof(config.issuer,'synthetic-origin','origin@example.test',True,True,2010,100000,'Synthetic origin')
            owner_cookie=Key('state','cookie#'+digest(service.login(fresh).cookie))
            service.create_invitation(actor(),target_subject='second',target_email='second@example.test',roles=['operator'],ttl_seconds=60,idempotency_key='second')
            if mode=='expired-revoked':
                root=rows[Key('state','invitation#'+invite['id'])]
                service.revoke_invitation(actor(),invitation_id=invite['id'],expected_revision=root.revision,idempotency_key='revoke-expired')
            reader.admission.clock_ms=lambda:3000
        elif mode != 'restricted':
            target = service.resolve(credential.cookie, allow_invitee=True)
            accepted = service.accept_invitation(target, invitation_id=invite['id'], capability=invite['capability'],
                idempotency_key='accept', notice_version='synthetic-v1', notice_sha256=digest('synthetic notice'))
            target_id = accepted['user_id']
            if mode in {'full', 'disabled'}:
                service.change_access(actor(), user_id=target_id, roles=['operator', 'reviewer'],
                    enabled=mode != 'disabled', expected_version=1, idempotency_key='change')
                service.revoke_sessions(actor(), user_id=target_id, expected_version=2, idempotency_key='revoke')
            if mode=='pending-transfer':
                service.begin_transfer(actor(),target_id=target_id,expected_target_version=1,idempotency_key='pending-transfer')
            if mode == 'full':
                credentials = service.login(proof)
                transfer = service.begin_transfer(actor(), target_id=target_id, expected_target_version=3, idempotency_key='transfer')
                service.accept_transfer(service.resolve(credentials.cookie), transfer_id=transfer['id'], idempotency_key='accept-transfer')
                service.logout(credentials.cookie, credentials.csrf)
    flows = OAuthFlows(repo, OAuthConfig(DEPLOYMENT, 'https://provider.example.test', 'syntheticclient',
        'https://proofpack.example.test/api/v1/auth/callback', b'z'*32), clock_ms=lambda: clock[0])
    started = flows.begin()
    if mode == 'full':
        state = parse_qs(urlsplit(started.authorization_url).query)['state'][0]
        flows.admit_callback()
        flows.consume(state=state, browser_cookie=started.browser_cookie)
    return reader, owner, repo, rows


def limits(**changes):
    from proofpack.evidence.auth_history import AuthHistoryLimits
    return AuthHistoryLimits(**(dict(max_records=1000, max_payload_bytes=4_000_000,
        max_dependencies=4000, max_work=400_000, max_summary_bytes=4_000_000) | changes))


def read(reader, **changes):
    return reader.read_auth_accounting(**(dict(request_id=REQUEST, inspection_ids=(uid(1),),
        deadline_ns=1000, accounting_limits=LIMITS, runtime_context_limits=runtime_limits(),
        access_context_limits=access_limits(), auth_history_limits=limits()) | changes))


@pytest.mark.parametrize('mode', ['bootstrap','restricted','accepted','disabled','full','revoked','repeat-revoked','declined','expired','expired-revoked','pending-transfer'])
def test_real_writer_histories_are_consumed_inside_original_read_without_claiming_policy(monkeypatch, mode):
    reader, owner, repo, rows = history(monkeypatch, mode)
    original = read_v4(reader)
    before = deepcopy(rows)
    monkeypatch.setattr(repo, 'transact', lambda *a, **k: pytest.fail('auth read mutated business rows'))
    result = read(reader)
    auth = result.corpus.auth_history
    assert auth.policy == 'held-authentication-history-v1'
    assert auth.inventory_sha256 == result.corpus.inventory.summary_sha256
    assert auth.scope_sha256 == result.corpus.proof.scope_sha256
    assert auth.source_records == len(result.corpus.inventory.entries)
    assert result.accounting.policy == 'conservative-family-accounting-v5'
    assert result.accounting.counts == original.accounting.counts
    assert dict(result.accounting.counts)['UNRESOLVED'] > 0
    assert auth.read_only is True and auth.can_confirm_cleanup is False and auth.policy_resolved is False
    assert uid(6) not in repr(auth) and 'identity.example' not in repr(auth)
    assert 'cookie#' not in repr(auth.records[0])
    assert rows == before and owner.wait_for_drain(0)
    assert result == read(reader)
    with pytest.raises(FrozenInstanceError): auth.work = 0
    if mode == 'full':
        assert auth.invitation_families == 1 and auth.transfer_families == 1
        assert {'access-head', 'bootstrap', 'user', 'identity', 'session', 'cookie', 'invitation',
                'owner-transfer', 'access-replay', 'oauth-flow', 'oauth-quota'} <= {r.family for r in auth.records}


def test_new_method_requires_explicit_limits_and_keeps_v4_unchanged(monkeypatch):
    reader, owner, _, _ = history(monkeypatch, 'bootstrap')
    before = read_v4(reader)
    with pytest.raises(ValueError): read(reader, auth_history_limits=None)
    assert read_v4(reader) == before and owner.wait_for_drain(0)


def test_valid_history_does_not_authorize_full_classification(monkeypatch):
    reader, owner, _, rows = history(monkeypatch)
    before = deepcopy(rows)
    from test_ownership_classification import bounds
    with pytest.raises(HeldCorpusHeld):
        reader.read_auth_classification(request_id=REQUEST, inspection_ids=(uid(1),), deadline_ns=1000,
            accounting_limits=LIMITS, runtime_context_limits=runtime_limits(), access_context_limits=access_limits(),
            auth_history_limits=limits(), classification_limits=bounds())
    assert before == rows and owner.wait_for_drain(0)


@pytest.mark.parametrize('name', ['max_records','max_payload_bytes','max_dependencies','max_work','max_summary_bytes'])
@pytest.mark.parametrize('bad', [None, True, 0, -1, 1.5, 2**63])
def test_all_five_limits_are_independent_finite_exact_integers(name, bad):
    with pytest.raises(ValueError): limits(**{name:bad})


@pytest.mark.parametrize('name, measured', [('max_records','source_records'),('max_payload_bytes','payload_bytes'),
    ('max_dependencies','dependencies'),('max_work','work'),('max_summary_bytes','summary_bytes')])
def test_exact_limits_pass_one_below_holds_without_writes(monkeypatch, name, measured):
    reader, owner, _, rows = history(monkeypatch)
    before=deepcopy(rows); result=read(reader); value=getattr(result.corpus.auth_history,measured)
    exact=read(reader,auth_history_limits=limits(**{name:value}))
    assert exact.corpus.auth_history==result.corpus.auth_history and exact.accounting==result.accounting
    assert exact.corpus.binding_sha256!=result.corpus.binding_sha256  # Limits are part of the held read binding.
    with pytest.raises(HeldCorpusHeld): read(reader,auth_history_limits=limits(**{name:value-1}))
    assert rows==before and owner.wait_for_drain(0)


def _choose(rows, family, *, kind=None):
    return next(r for r in rows.values() if r.key.resource.partition('#')[0]==family and
        (kind is None or r.data.get('kind')==kind or r.data.get('resource_bindings',{}).get('operation')==kind))


@pytest.mark.parametrize('family, field, bad', [
    ('access-head','schema_version',True),('access-head','owner_ids',[]),('access-head','unexpected',True),
    ('user','enabled',1),('user','roles',['operator','operator']),('user','notice_version','not-an-existing-field'),
    ('identity','user_id',uid(777)),('session','active',1),('session','access_version',999999),
    ('cookie','user_id',uid(777)),('invitation','history_schema_version',0),
    ('owner-transfer','status','revoked'),('oauth-flow','configuration','arbitrary'),
    ('oauth-flow','status','ready'),('oauth-flow','consumed_at_ms',999999),
    ('oauth-quota','count',999999),('oauth-quota','window_start_ms',1),
])
def test_current_schema_corruption_holds_without_repair(monkeypatch,family,field,bad):
    reader, owner, _, rows=history(monkeypatch)
    row=_choose(rows,family); row.data[field]=bad; before=deepcopy(rows)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('family', ['access','idempotency','identity','session','cookie','invitation','owner-transfer'])
def test_missing_auth_family_or_peer_holds(monkeypatch,family):
    reader, owner, _, rows=history(monkeypatch)
    row=_choose(rows,family); del rows[row.key]; before=deepcopy(rows)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('kind', ['change-access','revoke-sessions'])
@pytest.mark.parametrize('field,bad', [('body_hash','0'*64),('result',{'user_id':uid(777),'access_version':2}),('at_ms',999999)])
def test_mutated_access_replay_has_no_generic_acceptance(monkeypatch,kind,field,bad):
    reader, owner, _, rows=history(monkeypatch)
    row=_choose(rows,'idempotency',kind=kind); row.data[field]=bad; before=deepcopy(rows)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert rows==before and owner.wait_for_drain(0)


def test_missing_legacy_invitation_history_is_not_backfilled(monkeypatch):
    reader, owner, _, rows=history(monkeypatch,'restricted')
    root=_choose(rows,'invitation')
    for k in ('history_schema_version','created_at_ms','ttl_seconds'):root.data.pop(k)
    before=deepcopy(rows)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert rows==before and owner.wait_for_drain(0)


def test_decimal_native_storage_numbers_remain_supported(monkeypatch):
    from decimal import Decimal
    reader, owner, _, rows=history(monkeypatch)
    expected=read(reader)
    def convert(v):
        if type(v) is int:return Decimal(v)
        if type(v) is list:return [convert(x) for x in v]
        if type(v) is dict:return {k:convert(x) for k,x in v.items()}
        return v
    for k,r in tuple(rows.items()):rows[k]=Row(k,r.revision,convert(r.data))
    assert read(reader)==expected and owner.wait_for_drain(0)


def test_no_prefix_or_unmatched_identity_proves_unrelated_content(monkeypatch):
    reader, owner, _, rows=history(monkeypatch,'bootstrap')
    unknown=Key('state','not-a-supported-family#'+uid(700));rows[unknown]=Row(unknown,1,{'user_id':uid(701)})
    result=read(reader)
    entry=next(e for e in result.accounting.entries if e.reference.key==unknown)
    assert entry.disposition=='UNRESOLVED' and entry.reason=='UNSUPPORTED_FAMILY_POLICY'
    assert unknown not in {r.reference.key for r in result.corpus.auth_history.records}
    assert owner.wait_for_drain(0)


def test_final_store_race_cannot_publish_a_stale_review(monkeypatch):
    reader,owner,repo,rows=history(monkeypatch)
    from proofpack.evidence import held_corpus
    original=held_corpus.auth_derive
    def race(*a,**k):
        result=original(*a,**k)
        row=_choose(rows,'oauth-quota');rows[row.key]=Row(row.key,row.revision+1,{**row.data,'count':2})
        return result
    monkeypatch.setattr(held_corpus,'auth_derive',race)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_classification_cannot_renew_work_for_auth_phase(monkeypatch):
    reader,owner,_,rows=history(monkeypatch)
    base=read(reader);auth=base.corpus.auth_history;before=deepcopy(rows)
    from test_ownership_classification import bounds
    minimum=base.corpus.runtime_context.work+base.corpus.access_context.work+auth.work
    with pytest.raises(HeldCorpusHeld):
        reader.read_auth_classification(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,
            accounting_limits=LIMITS,runtime_context_limits=runtime_limits(),access_context_limits=access_limits(),
            auth_history_limits=limits(),classification_limits=replace(bounds(),max_work=minimum-1))
    assert rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['expiry','reversal','source-change','cancel'])
def test_last_authority_callback_preserves_deadline_source_and_cancellation(monkeypatch,fault):
    from proofpack.evidence.auth_history import derive,AuthHistoryHeld
    reader,owner,_,rows=history(monkeypatch)
    c=read(reader).corpus
    args=dict(requested_inspections=c.scope.inspection_ids,scope_sha256=c.proof.scope_sha256,
        now_ms=500,limits=limits(),deadline_ns=1000)
    count=[0]
    def count_check():count[0]+=1
    derive(tuple(rows.values()),c.inventory,c.proof,c.access_context,**args,tick=lambda:1,checkpoint=count_check)
    final=count[0];count[0]=0;clock=[1]
    def final_check():
        count[0]+=1
        if count[0]==final:
            if fault=='expiry':clock[0]=1000
            elif fault=='reversal':clock[0]=0
            elif fault=='source-change':_choose(rows,'oauth-quota').data['count']=2
            else:raise AuthHistoryHeld('synthetic cancellation')
    with pytest.raises(AuthHistoryHeld):
        derive(tuple(rows.values()),c.inventory,c.proof,c.access_context,**args,tick=lambda:clock[0],checkpoint=final_check)
    assert owner.wait_for_drain(0)


def test_shared_access_event_namespace_does_not_make_non_auth_operation_an_auth_family(monkeypatch):
    from proofpack.evidence.repository import Write
    reader,owner,repo,rows=history(monkeypatch,'bootstrap')
    service=AccessService(repo,AuthConfig(DEPLOYMENT,'https://identity.example.test',b'x'*32),clock_ms=lambda:10)
    cookie=_choose(rows,'cookie').key;actor=service._resolve_key(cookie)
    operation='synthetic-non-auth-operation'
    key,body_hash,_=service._idempotency(actor,operation,'non-auth',{'fixture':True})
    service._record(actor,operation,key,body_hash,{'fixture':True},
        (Write(Key('state','synthetic-non-auth-output#'+uid(702)),None,{'fixture':True}),))
    before=deepcopy(rows);result=read(reader)
    event=next(r for r in rows.values() if r.key.table=='events' and r.data.get('kind')==operation)
    assert {key,event.key}.isdisjoint({r.reference.key for r in result.corpus.auth_history.records})
    assert all(e.disposition=='UNRESOLVED' for e in result.accounting.entries if e.reference.key in {key,event.key})
    assert rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('field,limit', [('payload_bytes','max_payload_bytes'),('dependencies','max_dependencies'),('work','max_work')])
def test_reader_independently_rejects_validly_hashed_over_budget_phase_output(monkeypatch,field,limit):
    import hashlib
    from proofpack.evidence import held_corpus
    from proofpack.evidence.auth_history import _projection
    from proofpack.evidence.inventory import _encoded
    reader,owner,_,rows=history(monkeypatch);before=deepcopy(rows);original=held_corpus.auth_derive
    def forge(*a,**k):
        result=replace(original(*a,**k),**{field:getattr(k['limits'],limit)+1})
        encoded=_encoded(_projection(result))
        return replace(result,summary_bytes=len(encoded),summary_sha256=hashlib.sha256(encoded).hexdigest())
    monkeypatch.setattr(held_corpus,'auth_derive',forge)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('consumed,held',[(9,True),(10,False),(500,False),(501,True)])
def test_consumed_oauth_time_is_between_creation_and_trusted_review(monkeypatch,consumed,held):
    reader,owner,_,rows=history(monkeypatch)
    flow=_choose(rows,'oauth-flow');flow.data['consumed_at_ms']=consumed;before=deepcopy(rows)
    if held:
        with pytest.raises(HeldCorpusHeld):read(reader)
    else:
        assert read(reader).corpus.auth_history.policy_resolved is False
    assert rows==before and owner.wait_for_drain(0)
