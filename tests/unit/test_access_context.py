"""Synthetic access writers and original capture; no provider or human proof."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID
import pytest
from test_held_corpus import world, INV, BOUNDS, REQUEST, no_sdk
from test_capture_lineage import family, uid, DEPLOYMENT
from test_corpus_accounting import LIMITS
from test_runtime_context import limits as runtime_limits
from proofpack.auth.service import AccessService, AuthConfig, IdentityProof, BootstrapApproval, digest
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionLimits
from proofpack.evidence.held_corpus import HeldCorpusReader, HeldCorpusHeld, inspection_scope, scope_sha256
from proofpack.runtime.control import RuntimeControl
from proofpack.runtime.ownership import ResourceOwner


def complete(monkeypatch):
    _, _, _, repo, data, *_ = world(monkeypatch, held=False)
    data.clear()  # New isolated model, not deletion of a stored business corpus.
    clock = SimpleNamespace(value=1)
    issuer = 'https://identity.example.test'
    config = AuthConfig(DEPLOYMENT, issuer, b'x'*32, initial_owner_subject='synthetic-origin', bootstrap_receipt_sha256='f'*64)
    access = AccessService(repo, config, clock_ms=lambda: clock.value)
    proof = IdentityProof(issuer, 'synthetic-origin', 'origin@example.test', True, True, 1, 400, 'Synthetic origin')
    import proofpack.auth.service as writer
    values = iter((UUID(uid(6)), UUID(uid(100)), UUID(uid(5))))
    with monkeypatch.context() as m:
        m.setattr(writer, 'uuid4', lambda: next(values))
        assert access.bootstrap(BootstrapApproval(issuer, proof.subject, 'f'*64), proof) == uid(6)
        clock.value = 2
        credentials = access.login(proof)
    clock.value = 3
    runtime = RuntimeControl(access, instance_id=uid(4), artifact_sha256='e'*64, controls_sha256='b'*64, environment='test')
    runtime.start()
    root, records = family()
    data[root.key] = root
    data.update((r.key, r) for r in records)
    admission = PersistentAdmission(runtime, limits=AdmissionLimits(8, 1000), clock_ms=lambda: 500)
    admission.initialize('a'*64)
    scope = inspection_scope(DEPLOYMENT, (uid(1),), max_inspections=30)
    admission.hold(request_id=REQUEST, scope_sha256=scope_sha256(scope))
    owner = ResourceOwner()
    reader = HeldCorpusReader(admission, owner, inventory_limits=INV, limits=BOUNDS, tick=lambda: 1)
    return reader, owner, repo, data, Key('state', 'cookie#'+digest(credentials.cookie))


def limits(**changes):
    from proofpack.evidence.access_context import AccessContextLimits
    return AccessContextLimits(**(dict(max_records=1000, max_payload_bytes=4_000_000, max_work=400_000, max_summary_bytes=4_000_000)|changes))


def read(reader, **changes):
    return reader.read_access_accounting(**(dict(request_id=REQUEST, inspection_ids=(uid(1),), deadline_ns=1000,
        accounting_limits=LIMITS, runtime_context_limits=runtime_limits(), access_context_limits=limits())|changes))


def test_actual_access_writers_select_only_exact_origin_records_without_mutation(monkeypatch):
    reader, owner, repo, data, cookie = complete(monkeypatch)
    old = reader.read_runtime_accounting(request_id=REQUEST, inspection_ids=(uid(1),), deadline_ns=1000,
        accounting_limits=LIMITS, runtime_context_limits=runtime_limits())
    before = deepcopy(data)
    monkeypatch.setattr(repo, 'transact', lambda *a, **k: pytest.fail('context read wrote metadata'))
    result = read(reader)
    context = result.corpus.access_context
    assert context.policy == 'inspection-origin-access-context-v1'
    assert {r.key for r in context.records} == {Key('state','user#'+uid(6)), Key('state','session#'+uid(5)), cookie,
        Key('state','identity#'+digest('https://identity.example.test\0synthetic-origin'))}
    assert result.accounting.policy == 'conservative-family-accounting-v4'
    assert dict(result.accounting.counts)['UNRESOLVED'] == dict(old.accounting.counts)['UNRESOLVED']-4
    assert dict(result.accounting.counts)['UNRESOLVED'] > 0
    assert old.accounting.policy == 'conservative-family-accounting-v2' and old.corpus.access_context is None
    assert context.read_only is True and context.can_confirm_cleanup is False
    assert uid(1) not in repr(context) and uid(6) not in repr(context)
    assert data == before and owner.wait_for_drain(0)
    assert read(reader) == result
    with pytest.raises(FrozenInstanceError): context.work = 0


def test_supported_context_does_not_accept_unknown_remaining_business_records(monkeypatch):
    reader, owner, _, data, _ = complete(monkeypatch)
    before = deepcopy(data)
    from test_ownership_classification import bounds
    with pytest.raises(HeldCorpusHeld):
        reader.read_access_classification(request_id=REQUEST, inspection_ids=(uid(1),), deadline_ns=1000,
            accounting_limits=LIMITS, classification_limits=bounds(), runtime_context_limits=runtime_limits(), access_context_limits=limits())
    assert data == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('operation', ['accounting', 'classification'])
def test_access_entrypoint_cannot_silently_fall_back_when_required_limits_are_none(monkeypatch, operation):
    reader, owner, _, _, _ = complete(monkeypatch)
    arguments = dict(request_id=REQUEST, inspection_ids=(uid(1),), deadline_ns=1000,
        accounting_limits=LIMITS, runtime_context_limits=runtime_limits(), access_context_limits=None)
    if operation == 'classification':
        from test_ownership_classification import bounds
        arguments['classification_limits'] = bounds()
    with pytest.raises(ValueError): getattr(reader, 'read_access_'+operation)(**arguments)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('field', ['max_records','max_payload_bytes','max_work','max_summary_bytes'])
@pytest.mark.parametrize('invalid', [None, True, 0, -1, 1.5, 2**63])
def test_independent_finite_limits_cannot_be_disabled(field, invalid):
    with pytest.raises(ValueError): limits(**{field: invalid})


@pytest.mark.parametrize('field,measurement', [('max_records','source_records'), ('max_payload_bytes','payload_bytes'),
    ('max_work','work'), ('max_summary_bytes','summary_bytes')])
def test_exact_independent_limit_passes_and_one_less_holds(monkeypatch, field, measurement):
    reader, owner, _, data, _ = complete(monkeypatch)
    context = read(reader).corpus.access_context
    actual = getattr(context, measurement)
    assert read(reader, access_context_limits=limits(**{field: actual})).corpus.access_context == context
    before = deepcopy(data)
    with pytest.raises(HeldCorpusHeld): read(reader, access_context_limits=limits(**{field: actual-1}))
    assert data == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('target,change', [
    ('user', {'inspection_id':uid(1)}), ('user', {'enabled':1}), ('user', {'invited':False}),
    ('user', {'access_version':True}), ('user', {'session_epoch':0}), ('user', {'roles':['operator','operator']}),
    ('user', {'created_at_ms':11}), ('user', {'last_mfa_ms':501}), ('user', {'subject':'other-identity'}),
    ('session', {'inspection_id':uid(1)}), ('session', {'user_id':uid(999)}),
    ('session', {'access_version':2}), ('session', {'session_epoch':2}), ('session', {'active':1}),
    ('session', {'created_at_ms':11}), ('session', {'auth_time_ms':3}), ('session', {'expires_at_ms':2}),
    ('session', {'restricted_invitation_id':uid(999)}), ('session', {'email_hash':'0'*64}),
    ('cookie', {'user_id':uid(999)}), ('cookie', {'inspection_id':uid(1)}),
    ('identity', {'user_id':uid(999)}), ('identity', {'inspection_id':uid(1)}),
])
def test_selected_identity_conflicts_and_copied_content_hold(monkeypatch, target, change):
    reader, owner, _, data, cookie = complete(monkeypatch)
    key = cookie if target == 'cookie' else Key('state', target+'#'+(uid(6) if target=='user' else uid(5)))
    if target == 'identity': key = Key('state','identity#'+digest('https://identity.example.test\0synthetic-origin'))
    data[key] = replace(data[key], data={**data[key].data, **change})
    before = deepcopy(data)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert data == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('target', ['user','session','identity'])
def test_missing_required_original_cannot_be_replaced_by_prefix_or_email(monkeypatch, target):
    reader, owner, _, data, _ = complete(monkeypatch)
    key = Key('state', target+'#'+(uid(6) if target=='user' else uid(5)))
    if target == 'identity': key = Key('state','identity#'+digest('https://identity.example.test\0synthetic-origin'))
    source = data.pop(key)
    unrelated = Key('state',target+'#'+('0'*64 if target=='identity' else uid(999)))
    data[unrelated] = replace(source, key=unrelated)
    before = deepcopy(data)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert data == before and owner.wait_for_drain(0)


def test_disabled_revoked_and_expired_history_is_context_without_reenablement(monkeypatch):
    reader, owner, _, data, _ = complete(monkeypatch)
    member, session = Key('state','user#'+uid(6)), Key('state','session#'+uid(5))
    data[member] = replace(data[member], revision=2, data={**data[member].data,'enabled':False,'access_version':2,'session_epoch':2,'last_mfa_ms':400})
    data[session] = replace(data[session], revision=2, data={**data[session].data,'active':False})
    # Stored-shape adverse history, not a claim that a sole owner can disable itself.
    before = deepcopy(data)
    context = read(reader).corpus.access_context
    assert len(context.records) == 4 and context.can_confirm_cleanup is False
    assert data == before and data[member].data['enabled'] is False and data[session].data['active'] is False
    assert owner.wait_for_drain(0)


def test_unmatched_users_sessions_cookies_and_access_history_stay_unresolved(monkeypatch):
    reader, owner, _, data, cookie = complete(monkeypatch)
    source = data[Key('state','session#'+uid(5))]
    other = Key('state','session#'+uid(999))
    data[other] = replace(source,key=other,data={**source.data,'id':uid(999)})
    other_cookie = Key('state','cookie#'+'0'*64)
    data[other_cookie] = Row(other_cookie,1,{'session_id':uid(999),'user_id':uid(6)})
    result = read(reader); selected = {r.key for r in result.corpus.access_context.records}
    assert cookie in selected and other not in selected and other_cookie not in selected
    for entry in result.accounting.entries:
        if entry.reference.key in {other, other_cookie, Key('state','access-head')}:
            assert entry.disposition == 'UNRESOLVED'
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('change', [
    {'policy':'unknown'}, {'proof_sha256':'0'*64}, {'scope_sha256':'0'*64}, {'inventory_sha256':'0'*64},
    {'summary_sha256':'0'*64}, {'read_only':False}, {'can_confirm_cleanup':True}, {'source_records':True},
    {'work':True}, {'payload_bytes':False}, {'origins':[]}, {'records':[]}, {'requested_inspections':(uid(999),)},
])
def test_forged_context_return_is_rejected_under_original_resource_owner(monkeypatch, change):
    import proofpack.evidence.held_corpus as held
    original = held.access_derive
    reader, owner, _, data, _ = complete(monkeypatch)
    def altered(*args, **kwargs):
        assert not owner.wait_for_drain(0)
        return replace(original(*args, **kwargs), **change)
    monkeypatch.setattr(held, 'access_derive', altered)
    before = deepcopy(data)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert data == before and owner.wait_for_drain(0)


def test_rehashed_incomplete_records_cannot_discard_required_identity(monkeypatch):
    import hashlib
    import proofpack.evidence.access_context as access
    import proofpack.evidence.held_corpus as held
    original = held.access_derive
    reader, owner, _, _, _ = complete(monkeypatch)
    def altered(*args, **kwargs):
        result = original(*args, **kwargs)
        result = replace(result, records=result.records[:-1])
        payload = access._encoded(access._projection(result))
        return replace(result, summary_bytes=len(payload), summary_sha256=hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(held, 'access_derive', altered)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('change', ['phantom','configuration','drain'])
def test_final_source_configuration_and_drain_changes_hold_without_renewing_work(monkeypatch, change):
    import proofpack.evidence.held_corpus as held
    from proofpack.evidence.privacy_admission import GATE
    original = held.access_derive
    reader, owner, _, data, _ = complete(monkeypatch)
    def altered(*args, **kwargs):
        result = original(*args, **kwargs)
        assert not owner.wait_for_drain(0)
        if change == 'phantom':
            key=Key('state','late-access-phantom');data[key]=Row(key,1,{'unresolved':True})
        elif change == 'configuration': reader.tick=lambda:1
        else: data[GATE]=replace(data[GATE],revision=data[GATE].revision+1)
        return result
    monkeypatch.setattr(held,'access_derive',altered)
    with pytest.raises(HeldCorpusHeld): read(reader)
    assert owner.wait_for_drain(0)


def test_classification_charges_access_context_before_remaining_accounting_work(monkeypatch):
    import proofpack.evidence.held_corpus as held
    from test_ownership_classification import bounds
    reader, owner, _, _, _ = complete(monkeypatch)
    result=read(reader)
    runtime_work=result.corpus.runtime_context.work;access_work=result.corpus.access_context.work
    observed=[];original=held.access_derive
    def record(*args,**kwargs):
        observed.append(kwargs['limits'].max_work)
        return original(*args,**kwargs)
    monkeypatch.setattr(held,'access_derive',record)
    with pytest.raises(HeldCorpusHeld):
        reader.read_access_classification(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,
            accounting_limits=LIMITS,classification_limits=replace(bounds(),max_work=runtime_work+access_work),
            runtime_context_limits=runtime_limits(),access_context_limits=limits())
    assert observed == [access_work] and owner.wait_for_drain(0)


@pytest.mark.parametrize('deadline', [True,0,-1,1])
def test_original_expired_or_invalid_deadline_never_starts_new_allowance(monkeypatch,deadline):
    reader,owner,_,data,_=complete(monkeypatch);before=deepcopy(data)
    with pytest.raises((ValueError,HeldCorpusHeld)):read(reader,deadline_ns=deadline)
    assert data==before and owner.wait_for_drain(0)
