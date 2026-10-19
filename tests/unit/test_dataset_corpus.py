"""Synthetic complete-corpus dataset/group selection, not actual transaction authority."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import pytest
from botocore.client import BaseClient

from test_capture_lineage import uid, DEPLOYMENT
from test_dataset_lineage import family, completed, cancel, failed, reserved, checks
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key, Row, Write, ErasureMarker
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence import dataset_corpus
from proofpack.evidence.dataset_corpus import derive, DatasetCorpusLimits, DatasetCorpusHeld
from proofpack.review.datasets import Split
from proofpack.runtime.control import DATA


LIMITS=DatasetCorpusLimits(InspectionCorpusLimits(5000,16_000_000,30,200_000),15000,32_000_000,30,100)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('pure dataset selection invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def flatten(job,rows,sources):
    incoming=[job,*rows,*sources['group_rows']]
    for label in sources['label_families']:
        incoming.extend((label.inspection,*label.rows,*label.capture_rows,label.recipe,*label.purpose_rows))
    for permission in sources['permission_families']:incoming.extend((permission.preview,*permission.rows))
    unique={}
    for row in incoming:
        if row.key in unique:assert unique[row.key]==row
        unique[row.key]=row
    return tuple(unique.values())


def corpus(**options):return flatten(*completed(**options))


def changed_groups():
    job,rows,sources=completed(split=Split.FROZEN_TEST,declassified=True)
    raw=list(flatten(job,rows,sources));actors=checks()
    for index,group in enumerate(sources['group_rows']):
        ident=group.data['id'];reason=group.data['reason']
        first={k:group.data[k] for k in ('id','category','original_split','created_at_ms')}
        first.update(split=first['original_split'],generation=1);first['sha256']=digest(first)
        old=Row(group.key,1,first)
        outer_key=Key('events','access#'+uid(4100+index));detail_key=Key('events','dataset-declassification#'+uid(4000+index))
        operation='dataset-declassify:'+ident
        outer={'kind':operation,'actor_scope':'e'*64,'session_id':uid(3),'at_ms':500,
            'details':{'group_id':ident,'to_split':'DEVELOPMENT','reason':reason}}
        detail={'group_id':ident,'from_split':'FROZEN_TEST','to_split':'DEVELOPMENT','at_ms':500,'reason':reason}
        writes=(Write(group.key,1,group.data),Write(DATA,3+index,{'epoch':4+index,'changed_at_ms':500}),
            Write(Key('state','dataset-end-quota#'+'e'*64),None if index==0 else index,{'minute':0,'count':index+1}),
            Write(outer_key,None,outer),Write(detail_key,None,detail))
        dependencies=(*actors[:2],actors[3],Row(DATA,3+index,{'epoch':3+index,'changed_at_ms':150 if index==0 else 500}),old)
        prepared,_=prepare_linked(DEPLOYMENT,operation,writes,dependencies)
        raw.extend(Row(w.key,1,w.data) for w in prepared if w.key.table=='events')
    return tuple(raw)


def run(rows,**changes):
    return derive(rows,**(dict(deployment=DEPLOYMENT,requested_inspections=(uid(1),),limits=LIMITS,
        now_ms=5000,deadline_ns=1000,tick=lambda:1,checkpoint=lambda:None)|changes))


def test_complete_copies_and_shared_groups_come_from_validated_sources():
    rows=corpus();result=run(rows)
    assert len(result.families)==1 and len(result.groups)==3
    family=result.families[0]
    assert family.inspection_ids==family.copied_inspection_ids==family.requested_inspection_ids==(uid(1),)
    assert family.unresolved_intents==()
    assert all(g.dataset_ids==(uid(1),) and g.copied_inspection_ids==(uid(1),) for g in result.groups)
    retained={r.key for r in result.residual}
    assert {g.history.group.key for g in result.groups}<=retained
    assert not hasattr(family,'usable') and 'Synthetic label note' not in repr(result)


@pytest.mark.parametrize('index',range(len(corpus())))
def test_omitting_each_required_copy_source_or_history_input_holds(index):
    rows=corpus()
    with pytest.raises(DatasetCorpusHeld):run(rows[:index]+rows[index+1:])


@pytest.mark.parametrize('options',[{'retired':True},{'withdrawn':True},{'count':2},{'count':2,'restarted':True}])
def test_retired_withdrawn_and_partial_copy_histories_preserve_intents(options):
    result=run(corpus(**options));family=result.families[0]
    assert family.copied_inspection_ids==(uid(1),)
    if options.get('count')==2:
        assert family.status==('failed' if options.get('restarted') else 'queued')
        assert any(i.kind=='requested_label' for i in family.unresolved_intents)


def test_mixed_inspection_intents_never_expand_requested_or_copied_scope(monkeypatch):
    import test_capture_lineage as capture_fixture
    import test_label_lineage as label_fixture
    with monkeypatch.context() as patch:
        offset=lambda n:uid(n+1000)
        patch.setattr(capture_fixture,'uid',offset);patch.setattr(label_fixture,'uid',offset)
        root,capture,recipe,purposes,history=label_fixture.labels(1,ident=uid(20),epoch_start=4)
    rows=(*corpus(count=2),root,*capture,recipe,*purposes,*history)
    result=run(rows);family=result.families[0]
    assert family.status=='queued'
    assert family.inspection_ids==(uid(1),uid(1001))
    assert family.copied_inspection_ids==family.requested_inspection_ids==(uid(1),)
    assert all(g.copied_inspection_ids==(uid(1),) for g in result.groups)


def test_group_declassification_is_complete_and_retained_as_shared_obligation():
    result=run(changed_groups())
    assert len(result.groups)==3 and all(len(g.history.versions)==2 for g in result.groups)
    assert all(len(g.history.history)>=3 for g in result.groups)
    retained={r.key for r in result.residual}
    assert all(any(r.key.resource.startswith('dataset-declassification#') and r.key in retained
        for r in g.history.history) for g in result.groups)


def test_missing_declassification_peer_does_not_certify_current_group_head():
    rows=changed_groups();removed=False;changed=[]
    for row in rows:
        if not removed and row.key.resource.startswith('dataset-declassification#'):removed=True;continue
        changed.append(row)
    with pytest.raises(DatasetCorpusHeld):run(tuple(changed))


def beta_base(monkeypatch):
    import test_capture_lineage as capture_fixture
    import test_label_lineage as label_fixture
    with monkeypatch.context() as patch:
        patch.setattr(capture_fixture,'DEPLOYMENT','beta');patch.setattr(label_fixture,'DEPLOYMENT','beta')
        root,capture,recipe,purposes,labels=label_fixture.labels()
    return (root,*capture,recipe,*purposes,*labels)


@pytest.mark.parametrize('state',['queued','cancelled','source-failed','budget-failed'])
def test_unmaterialized_terminal_jobs_do_not_invent_source_copies(monkeypatch,state):
    if state=='queued':job,rows=family()
    elif state=='cancelled':job,rows=cancel(*family())
    else:job,rows=failed(budget=state=='budget-failed')
    result=run((*beta_base(monkeypatch),job,*rows),deployment='beta')
    selected=result.families[0]
    assert selected.copied_inspection_ids==selected.inspection_ids==()
    assert len(selected.unresolved_intents)==2 and result.groups==()


def test_processing_job_is_not_drained_by_expiry(monkeypatch):
    job,rows=reserved()
    with pytest.raises(DatasetCorpusHeld):run((*beta_base(monkeypatch),job,*rows),deployment='beta')


def test_other_maintenance_kind_and_unknown_nested_copy_remain_residual():
    future=Row(Key('state','maintenance-job#'+uid(999)),1,{'id':uid(999),'kind':'other_job','private':'NOT_DATASET_AUTHORITY'})
    marker=ErasureMarker(Key('state','old#opaque'),2,'a'*64,'b'*64)
    result=run((*corpus(),future,marker))
    assert {future.key,marker.key}<={r.key for r in result.residual}
    assert 'NOT_DATASET_AUTHORITY' not in repr(result)


def test_orphan_example_cannot_be_left_out_of_dataset_selection():
    rows=list(corpus());index=next(i for i,r in enumerate(rows) if r.key.resource.startswith('dataset-example#'))
    rows[index]=replace(rows[index],data={**rows[index].data,'dataset_id':uid(999)})
    with pytest.raises(DatasetCorpusHeld):run(tuple(rows))


def test_group_without_creator_dataset_history_holds():
    rows=corpus();only=tuple(r for r in rows if not (r.key.resource.startswith(('maintenance-job#','dataset-catalog#',
        'dataset-example#','dataset-manifest#','dataset-transition#')) or r.data.get('kind','').startswith(('dataset-create','dataset-step:'))))
    with pytest.raises(DatasetCorpusHeld):run(only)


def test_original_entry_limit_and_expanded_family_limits_are_independent():
    rows=corpus();result=run(rows)
    assert result.max_family_records_used>len(rows)
    exact=replace(LIMITS,corpus=replace(LIMITS.corpus,max_records=len(rows)),
        family_max_records=result.max_family_records_used,family_max_payload_bytes=result.max_family_payload_bytes_used)
    assert run(rows,limits=exact)==result
    with pytest.raises(DatasetCorpusHeld):run(rows,limits=replace(exact,family_max_records=result.max_family_records_used-1))
    with pytest.raises(DatasetCorpusHeld):run(rows,limits=replace(exact,family_max_payload_bytes=result.max_family_payload_bytes_used-1))


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_work'])
def test_exact_and_one_below_original_corpus_bounds(field):
    rows=corpus();result=run(rows)
    exact={'max_records':len(rows),'max_payload_bytes':result.permissions.labels.inspections.payload_bytes,'max_work':result.work}[field]
    assert run(rows,limits=replace(LIMITS,corpus=replace(LIMITS.corpus,**{field:exact})))==result
    with pytest.raises(DatasetCorpusHeld):run(rows,limits=replace(LIMITS,corpus=replace(LIMITS.corpus,**{field:exact-1})))


def test_group_root_bound_is_checked_without_partial_result():
    with pytest.raises(DatasetCorpusHeld):run(corpus(),limits=replace(LIMITS,max_groups=2))


def test_dataset_root_bound_precedes_parsing_another_root():
    other=Row(Key('state','maintenance-job#'+uid(999)),1,{'id':uid(999),'kind':'dataset_manifest'})
    with pytest.raises(DatasetCorpusHeld,match='dataset root bound'):
        run((*corpus(),other),limits=replace(LIMITS,max_datasets=1))


@pytest.mark.parametrize('bad',[True,0,-1,2**63,1.5,None])
def test_explicit_family_and_root_limits_reject_ambiguous_values(bad):
    for field in ['family_max_records','family_max_payload_bytes','max_datasets','max_groups']:
        with pytest.raises(ValueError):replace(LIMITS,**{field:bad})


@pytest.mark.parametrize('fault',['mutation','clock','deadline','revision-type'])
def test_phase_boundary_preserves_original_snapshot_and_monotonic_deadline(monkeypatch,fault):
    unknown=Row(Key('state','future#snapshot'),1,{'private':'retained unknown'})
    rows=(*corpus(),unknown);original=dataset_corpus.permission_derive;after=False
    def first(*args,**kwargs):
        nonlocal after
        result=original(*args,**kwargs);after=True
        if fault=='mutation':unknown.data['private']='changed'
        if fault=='revision-type':object.__setattr__(unknown,'revision',True)
        return result
    monkeypatch.setattr(dataset_corpus,'permission_derive',first)
    def clock():return (1000 if fault=='deadline' else 99) if after else 100
    with pytest.raises(DatasetCorpusHeld):run(rows,tick=clock if fault in {'clock','deadline'} else lambda:1)


def test_order_independent_frozen_result():
    rows=corpus();result=run(rows)
    assert run(tuple(reversed(rows)))==result and run(rows[10:]+rows[:10])==result
    with pytest.raises(FrozenInstanceError):result.work=0


def test_final_checkpoint_failure_returns_no_partial_dataset():
    rows=corpus();count=0
    def count_it():
        nonlocal count
        count+=1
    run(rows,checkpoint=count_it);final=count;count=0
    def fail():
        nonlocal count
        count+=1
        if count==final:raise RuntimeError('final dataset checkpoint failed')
    with pytest.raises(RuntimeError,match='final dataset'):run(rows,checkpoint=fail)
