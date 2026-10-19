"""Synthetic complete permission-history selection; never evidence of actual rights."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import pytest
from botocore.client import BaseClient

from test_capture_lineage import uid, DEPLOYMENT
from test_label_lineage import labels
from test_improvement_lineage import family as preview_template, committed as grant_template
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Row, Key, Write, ErasureMarker
from proofpack.evidence.resource_bindings import prepare_linked, _payload_sha256
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence import improvement_corpus
from proofpack.evidence.improvement_corpus import derive, ImprovementCorpusHeld
from proofpack.runtime.control import DATA, RUNTIME


LIMITS = InspectionCorpusLimits(3000, 12_000_000, 20, 60_000)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args, **kwargs): raise AssertionError('pure permission selection invoked SDK')
    monkeypatch.setattr(BaseClient, '_make_api_call', deny)


def event(kind, details, writes, checks, number, at):
    key = Key('events', 'access#'+uid(number))
    data = {'kind': kind, 'actor_scope': 'a'*64, 'session_id': uid(3), 'at_ms': at, 'details': details}
    prepared, _ = prepare_linked(DEPLOYMENT, kind, (*writes, Write(key, None, data)), checks)
    return Row(key, 1, next(w.data for w in prepared if w.key == key))


def corpus(*, committed=True, withdrawn=False, repeat=False, reference=False,
           kind_override=None, other_rows=()):
    root, capture, recipe, purposes, lr = labels(epoch_start=2 if committed else 1)
    raw = [root, *capture, recipe, *purposes, *lr, *other_rows]
    asset = next(r for r in capture if r.key.resource.startswith('asset#'))
    selected = [(asset, purposes[0], 'frame')]
    if reference:
        asset = Row(Key('state', 'asset#'+uid(900)), 1,
            {'id': uid(900), 'kind': 'reference', 'sha256': 'b'*64, 'purpose_id': purposes[0].key.resource.split('#')[1]})
        raw.append(asset); selected = [(asset, purposes[0], 'reference')]
    for row in other_rows:
        if row.key.resource.startswith('asset#'):
            purpose = next(r for r in other_rows if r.key == Key('state', 'purpose#'+row.data['purpose_id']))
            selected.append((row, purpose, 'frame'))
    template, _ = preview_template(); data = deepcopy(template.data)
    scope = deepcopy(data['scope']); scope['assets'] = []
    for asset, purpose, kind in selected:
        scope['assets'].append({'id': asset.data['id'], 'kind': kind_override or kind,
            'asset_revision': asset.revision, 'asset_record_sha256': _payload_sha256(asset.data),
            'sha256': asset.data['sha256'], 'data_origin': 'synthetic',
            'purpose_id': purpose.key.resource.split('#')[1], 'purpose_revision': purpose.revision,
            'purpose_record_sha256': _payload_sha256(purpose.data),
            'source_permission_reference': 'synthetic-rights', 'expires_at_ms': 1000})
    scope['assets'].sort(key=lambda s: s['id'])
    data.update(scope=scope, scope_sha256=digest(scope), source_expires_at_ms=1000)
    preview = Row(template.key, 1, data)
    actors = (Row(Key('state', 'user#'+uid(2)), 1, {'id': uid(2)}),
        Row(Key('state', 'session#'+uid(3)), 1, {'id': uid(3)}))
    contexts = (Row(DATA, 1, {'epoch': 1, 'changed_at_ms': 90}), Row(RUNTIME, 1, {'epoch': 1}))
    checks = tuple({r.key: r for r in (*actors, *contexts, *(r for pair in selected for r in pair[:2]))}.values())
    created = event('improvement-preview', {'preview_id': data['id'], 'scope_sha256': data['scope_sha256']},
        (Write(preview.key, None, data), Write(Key('state', 'improvement-preview-quota#'+'a'*64), None, {'minute': 0, 'count': 1})),
        checks, 520, 100)
    if not committed: return tuple((*raw, preview, created))
    _, original_history = grant_template()
    grant_data = deepcopy(next(r.data for r in original_history if r.key.resource.startswith('improvement-grant#')))
    grant_data.update(scope=scope, scope_sha256=data['scope_sha256'], created_at_ms=105)
    grant_data['sha256'] = digest({k:v for k,v in grant_data.items() if k!='sha256'})
    grant = Row(Key('state', 'improvement-grant#'+uid(9)), 1, grant_data)
    head = Row(Key('state', 'improvement-permission#'+uid(9)), 1,
        {'id': uid(9), 'grant_sha256': grant_data['sha256'], 'withdrawn': False})
    current = Row(preview.key, 2, {**data, 'status': 'committed', 'permission_id': uid(9)})
    confirmed = event('improvement-confirm', {'permission_id': uid(9), 'scope_sha256': data['scope_sha256'],
        'grant_sha256': grant_data['sha256']},
        (Write(current.key, 1, current.data), Write(grant.key, None, grant.data), Write(head.key, None, head.data),
         Write(DATA, 1, {'epoch': 2, 'changed_at_ms': 105}),
         Write(Key('state', 'improvement-confirm-quota#'+'a'*64), None, {'minute': 0, 'count': 1})),
        (*checks, preview), 521, 105)
    history = [current, created, grant, head, confirmed]
    if withdrawn:
        latest = Row(head.key, 2, {**head.data, 'withdrawn': True, 'withdrawn_at_ms': 400})
        quota = Key('state', 'improvement-withdraw-quota#'+'a'*64)
        wc = (*actors, Row(DATA, 4, {'epoch': 4, 'changed_at_ms': 112}), contexts[1], head, grant)
        revoked = event('improvement-withdraw:'+uid(9), {'permission_id': uid(9), 'withdrawn': True},
            (Write(head.key, 1, latest.data), Write(DATA, 4, {'epoch': 5, 'changed_at_ms': 400}),
             Write(quota, None, {'minute': 0, 'count': 1})), wc, 522, 400)
        history[3] = latest; history.append(revoked)
        if repeat:
            history.append(event('improvement-withdraw:'+uid(9), {'permission_id': uid(9), 'withdrawn': True},
                (Write(quota, 1, {'minute': 0, 'count': 2}),),
                (*actors, Row(DATA, 5, {'epoch': 5, 'changed_at_ms': 400}), contexts[1], latest, grant), 523, 450))
    return tuple((*raw, *history))


def run(rows, **changes):
    return derive(rows, **(dict(deployment=DEPLOYMENT, requested_inspections=(uid(1),),
        limits=LIMITS, now_ms=5000, deadline_ns=1000, tick=lambda: 1,
        checkpoint=lambda: None) | changes))


@pytest.mark.parametrize('committed,withdrawn,repeat', [(False,False,False),(True,False,False),(True,True,False),(True,True,True)])
def test_derives_preview_grant_head_and_all_expired_withdrawal_history(committed,withdrawn,repeat):
    result = run(corpus(committed=committed, withdrawn=withdrawn, repeat=repeat))
    assert len(result.families)==1
    family=result.families[0]
    assert family.inspection_ids==family.requested_inspection_ids==(uid(1),)
    assert family.unresolved_reference_sources==()
    assert (family.history.permission is not None)==committed
    if withdrawn: assert family.history.permission.revision==2
    assert len(result.source_inputs)==2 and len(result.residual)==2
    assert not hasattr(family,'usable') and 'separate-rights' not in repr(result)


@pytest.mark.parametrize('prefix', ['improvement-preview','improvement-grant','improvement-permission'])
def test_missing_supported_permission_state_cannot_be_omitted(prefix):
    rows=corpus()
    with pytest.raises(ImprovementCorpusHeld):run(tuple(r for r in rows if not r.key.resource.startswith(prefix+'#')))


@pytest.mark.parametrize('kind', ['improvement-preview','improvement-confirm','improvement-withdraw:'+uid(9)])
def test_missing_required_permission_audit_holds(kind):
    rows=corpus(withdrawn=True)
    with pytest.raises(ImprovementCorpusHeld):run(tuple(r for r in rows if r.data.get('kind')!=kind))


@pytest.mark.parametrize('prefix', ['asset','purpose'])
def test_missing_actual_source_is_not_replaced_by_historical_hash(prefix):
    rows=corpus()
    with pytest.raises(ImprovementCorpusHeld):run(tuple(r for r in rows if not r.key.resource.startswith(prefix+'#')))


def test_reference_scope_stays_unresolved_without_inventing_inspection_ownership():
    result=run(corpus(reference=True));family=result.families[0]
    assert family.inspection_ids==family.requested_inspection_ids==()
    assert family.unresolved_reference_sources==(Key('state','asset#'+uid(900)),)
    assert family.unresolved_reference_sources[0] in {r.key for r in result.residual}


def test_reference_cannot_be_relabelled_as_frame_in_permission_scope():
    with pytest.raises(ImprovementCorpusHeld):run(corpus(reference=True,kind_override='frame'))


def test_shared_preview_records_both_inspections_without_expanding_requested_scope(monkeypatch):
    import test_capture_lineage as capture_fixture
    import test_label_lineage as label_fixture
    with monkeypatch.context() as patch:
        offset=lambda n:uid(n+1000)
        patch.setattr(capture_fixture,'uid',offset);patch.setattr(label_fixture,'uid',offset)
        root,capture,recipe,_,_=label_fixture.labels(0)
    purpose=Row(Key('state','purpose#'+uid(1012)),1,
        {'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':1000})
    result=run(corpus(other_rows=(root,*capture,recipe,purpose)))
    family=result.families[0]
    assert family.inspection_ids==(uid(1),uid(1001))
    assert family.requested_inspection_ids==(uid(1),)
    assert len(result.source_inputs)==4


def test_unknown_nested_copy_and_marker_stay_residual():
    unknown=Row(Key('state','future#opaque'),1,{'copy':{'inspection_id':uid(1)},'private':'UNKNOWN_COPY'})
    marker=ErasureMarker(Key('state','old#opaque'),2,'a'*64,'b'*64)
    result=run((*corpus(),unknown,marker))
    assert {unknown.key,marker.key}<={r.key for r in result.residual}
    assert 'UNKNOWN_COPY' not in repr(result)


@pytest.mark.parametrize('phase',['label','permission'])
def test_unknown_row_revision_cannot_change_from_integer_to_boolean_between_phases(monkeypatch,phase):
    from proofpack.evidence import label_corpus
    unknown=Row(Key('state','future#typed-source'),1,{'copy':'unknown retained metadata'})
    rows=(*corpus(),unknown)
    module=label_corpus if phase=='label' else improvement_corpus
    name='inspection_derive' if phase=='label' else 'label_derive'
    original=getattr(module,name)
    def first(*args,**kwargs):
        result=original(*args,**kwargs)
        object.__setattr__(unknown,'revision',True)
        return result
    monkeypatch.setattr(module,name,first)
    with pytest.raises(ImprovementCorpusHeld):run(rows)


def test_orphan_confirmation_event_holds():
    rows=list(corpus());index=next(i for i,r in enumerate(rows) if r.data.get('kind')=='improvement-confirm')
    data=deepcopy(rows[index].data);data['details']['permission_id']=uid(999)
    rows[index]=replace(rows[index],data=data)
    with pytest.raises(ImprovementCorpusHeld):run(tuple(rows))


def test_order_independent_reference_only_immutable_result():
    rows=corpus(withdrawn=True,repeat=True);result=run(rows)
    assert run(tuple(reversed(rows)))==result
    assert run(rows[10:]+rows[:10])==result
    with pytest.raises(FrozenInstanceError):result.work=0


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_work'])
def test_exact_and_one_below_cumulative_bounds(field):
    rows=corpus();result=run(rows)
    exact={'max_records':len(rows),'max_payload_bytes':result.labels.inspections.payload_bytes,'max_work':result.work}[field]
    assert run(rows,limits=replace(LIMITS,**{field:exact}))==result
    with pytest.raises(ImprovementCorpusHeld):run(rows,limits=replace(LIMITS,**{field:exact-1}))


@pytest.mark.parametrize('fault',['mutation','clock','deadline'])
def test_phase_boundary_preserves_original_inputs_clock_and_deadline(monkeypatch,fault):
    rows=corpus();original=improvement_corpus.label_derive;after=False
    def first(*args,**kwargs):
        nonlocal after
        result=original(*args,**kwargs);after=True
        if fault=='mutation':rows[8].data['withdrawn']=True
        return result
    monkeypatch.setattr(improvement_corpus,'label_derive',first)
    def clock():return (1000 if fault=='deadline' else 99) if after else 100
    with pytest.raises(ImprovementCorpusHeld):run(rows,tick=clock if fault!='mutation' else lambda:1)


def test_final_checkpoint_failure_returns_no_partial_permission():
    rows=corpus();count=0
    def count_it():
        nonlocal count
        count+=1
    run(rows,checkpoint=count_it);final=count;count=0
    def fail():
        nonlocal count
        count+=1
        if count==final:raise RuntimeError('final permission checkpoint failed')
    with pytest.raises(RuntimeError,match='final permission'):run(rows,checkpoint=fail)


def test_no_permission_records_invents_no_grant():
    from test_label_corpus import corpus as label_rows
    result=run(label_rows())
    assert result.families==result.source_inputs==()
    assert len(result.residual)==2
