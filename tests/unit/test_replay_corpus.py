"""Saved result copies and complete transaction peers; no current capabilities."""
from copy import deepcopy
from dataclasses import replace,FrozenInstanceError
import pytest
from botocore.client import BaseClient

from test_capture_lineage import uid,DEPLOYMENT,action_family
from test_dataset_corpus import corpus as dataset_rows,changed_groups,LIMITS as DATASET_LIMITS
from test_inspection_corpus import corpus as human_rows
from test_improvement_corpus import corpus as permission_rows
from proofpack.evidence.repository import Key,Row
from proofpack.evidence import replay_corpus
from proofpack.evidence.replay_corpus import derive,ReplayCorpusLimits,ReplayCorpusHeld
from proofpack.evidence.replay_lineage import discover as peer_discover,ReplayHistoryHeld
from proofpack.review.labels import label_revision_key


LIMITS=ReplayCorpusLimits(DATASET_LIMITS,100,10)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('pure replay corpus invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def saved(event,result,number):
    return Row(Key('state','idempotency#'+format(number,'064x')),1,{'body_hash':'f'*64,
        'result':deepcopy(result),'at_ms':event.data['at_ms']+1,
        'resource_bindings':deepcopy(event.data['resource_bindings'])})


def find(rows,operation):
    return next(r for r in rows if r.key.table=='events' and r.data.get('kind')==operation)


def corpus():
    rows=dataset_rows();operations=[
        ('observation_admitted',{'inspection_id':uid(1),'observation_id':uid(8),'sequence':1}),
        ('label-create',{'id':uid(10),'revision':1}),
        ('improvement-preview',{'id':uid(1000)}),
        ('improvement-confirm',{'id':uid(11)}),
        ('dataset-create',{'id':uid(1)}),
        ('dataset-step:'+uid(1),{'id':uid(1),'attempt':uid(700)})]
    return (*rows,*(saved(find(rows,operation),result,100+n) for n,(operation,result) in enumerate(operations)))


def run(rows,**changes):
    return derive(rows,**(dict(deployment=DEPLOYMENT,requested_inspections=(uid(1),),limits=LIMITS,
        now_ms=5000,deadline_ns=1000,tick=lambda:1,checkpoint=lambda:None)|changes))


def test_supported_results_bind_exact_peers_and_business_ids_without_payload_copy():
    rows=corpus();result=run(rows)
    assert len(result.families)==6 and result.obligations==()
    assert all(f.inspection_ids==f.requested_inspection_ids==(uid(1),) for f in result.families)
    assert all(f.history.replay.key not in {r.key for r in result.residual} for f in result.families)
    assert any(f.validation=='EXACT_ID_TYPED_HISTORICAL_ATTEMPT' for f in result.families)
    assert not hasattr(result.families[-1],'attempt')
    assert all(value not in repr(result) for value in ['Synthetic label note','separate-rights','body_hash','result_json'])


def test_every_dataset_transaction_retains_the_same_unresolved_intents():
    rows=dataset_rows(count=2)
    roots=tuple(saved(find(rows,op),{'id':uid(1)},200+n)
        for n,op in enumerate(['dataset-create','dataset-step:'+uid(1)]))
    result=run((*rows,*roots));expected=label_revision_key(uid(20),1)
    assert len(result.families)==2 and len(result.obligations)==2
    assert all(expected in f.unresolved_source_keys for f in result.families)
    assert {r.key for r in roots}<={r.key for r in result.residual}


def test_group_detail_peer_without_kind_has_exact_supported_schema_and_stays_shared():
    rows=changed_groups();events=[r for r in rows if r.key.table=='events'
        and r.key.resource.startswith('access#') and r.data.get('kind','').startswith('dataset-declassify:')]
    roots=tuple(saved(event,{'id':event.data['details']['group_id']},300+n) for n,event in enumerate(events))
    result=run((*rows,*roots))
    assert len(result.families)==3 and len(result.obligations)==3
    assert all(len(f.history.events)==2 and len(f.unresolved_source_keys)==1 for f in result.families)
    assert {r.key for r in roots}<={r.key for r in result.residual}


@pytest.mark.parametrize('fault',['extra','group','reason','reason-control','from-split','to-split',
    'bool-time','future-time','missing-time','kind-field','unknown-prefix','no-access-details'])
def test_explicit_generic_group_peer_variant_rejects_unknown_or_inconsistent_fields(fault):
    rows=changed_groups()
    access=next(r for r in rows if r.key.table=='events' and r.key.resource.startswith('access#')
        and r.data.get('kind','').startswith('dataset-declassify:'))
    detail=next(r for r in rows if r.key.resource.startswith('dataset-declassification#')
        and r.data['resource_bindings']==access.data['resource_bindings'])
    root=saved(access,{'id':access.data['details']['group_id']},390)
    data=deepcopy(detail.data);outer=deepcopy(access.data);key=detail.key
    if fault=='extra':data['private-extra']='PRIVATE_GROUP_COPY'
    elif fault=='group':data['group_id']='f'*64
    elif fault=='reason':data['reason']='different-reason'
    elif fault=='reason-control':data['reason']=outer['details']['reason']='bad\nreason'
    elif fault=='from-split':data['from_split']='UNKNOWN'
    elif fault=='to-split':data['to_split']=outer['details']['to_split']='FROZEN_TEST'
    elif fault=='bool-time':data['at_ms']=True
    elif fault=='future-time':data['at_ms']=outer['at_ms']+1
    elif fault=='missing-time':data.pop('at_ms')
    elif fault=='kind-field':data['kind']='not-an-escape-hatch'
    elif fault=='unknown-prefix':key=Key('events','future-detail#'+uid(999))
    else:outer.pop('details')
    with pytest.raises(ReplayHistoryHeld):
        peer_discover(root,(replace(access,data=outer),replace(detail,key=key,data=data)),
            deployment=DEPLOYMENT,max_records=100,max_payload_bytes=1_000_000)


@pytest.mark.parametrize('index',range(6))
def test_extra_private_fields_in_any_supported_result_are_rejected(index):
    rows=list(corpus());target=len(rows)-6+index;data=deepcopy(rows[target].data)
    data['result']['private_extra']='MUST_NOT_BECOME_SUPPORTED_COPY'
    rows[target]=replace(rows[target],data=data)
    with pytest.raises(ReplayCorpusHeld):run(tuple(rows))


@pytest.mark.parametrize('index',range(1,6))
def test_wrong_result_identity_cannot_borrow_transaction_scope(index):
    rows=list(corpus());target=len(rows)-6+index;data=deepcopy(rows[target].data);data['result']['id']=uid(999)
    rows[target]=replace(rows[target],data=data)
    with pytest.raises(ReplayCorpusHeld):run(tuple(rows))


def test_bool_label_revision_is_not_integer_one():
    rows=list(corpus());target=len(rows)-5;data=deepcopy(rows[target].data);data['result']['revision']=True
    rows[target]=replace(rows[target],data=data)
    with pytest.raises(ReplayCorpusHeld):run(tuple(rows))


@pytest.mark.parametrize('token',['not-a-uuid','cookie#'+'f'*64,True,{'secret':'hidden'}])
def test_historical_attempt_requires_uuid_encoding_and_never_arbitrary_content(token):
    rows=list(corpus());data=deepcopy(rows[-1].data);data['result']['attempt']=token;rows[-1]=replace(rows[-1],data=data)
    with pytest.raises(ReplayCorpusHeld):run(tuple(rows))


def test_historical_disposition_copies_exact_immutable_decision_and_write_version():
    rows=human_rows();event=next(r for r in rows if r.key.table=='events' and r.data.get('kind','').startswith('inspection-disposition:'))
    ident=event.data['details']['decision_id'];decision=next(r for r in rows if r.key.resource.endswith('#'+ident) and r.key.resource.startswith('human-disposition#'))
    version=next(r['revision'] for r in event.data['resource_bindings']['writes'] if r['resource']=='inspection#'+uid(1))
    body={'id':ident,'inspection_id':uid(1),'inspection_state_version':version,'decision':decision.data}
    root=saved(event,body,400);result=run((*rows,root))
    assert result.families[0].codec=='human-disposition/v1' and result.obligations==()
    bad=deepcopy(root.data);bad['result']['inspection_state_version']=rows[0].revision
    assert version!=rows[0].revision
    with pytest.raises(ReplayCorpusHeld):run((*rows,replace(root,data=bad)))


def test_action_ack_uses_its_business_ids_and_does_not_return_authority():
    root,capture=action_family(True);rows=(root,*capture)
    event=find(rows,'action-ack:'+uid(1)+':'+uid(13))
    result=run((*rows,saved(event,{'inspection_id':uid(1),'action_id':uid(13)},401)))
    assert result.families[0].codec=='action-ack/v1'
    assert not hasattr(result.families[0],'current_action')


def test_withdrawal_and_repeat_receipts_bind_the_original_permission_id():
    rows=permission_rows(withdrawn=True,repeat=True)
    events=[r for r in rows if r.key.table=='events' and r.data.get('kind')=='improvement-withdraw:'+uid(9)]
    result=run((*rows,*(saved(event,{'id':uid(9)},410+n) for n,event in enumerate(events))))
    assert len(result.families)==2 and result.obligations==()


def test_retired_dataset_id_receipt_does_not_erase_shared_group_obligations():
    rows=dataset_rows(retired=True);event=find(rows,'dataset-retire:'+uid(1))
    result=run((*rows,saved(event,{'id':uid(1)},420)))
    assert len(result.families)==1 and result.obligations==()
    assert all(g.history.group.key in {r.key for r in result.residual} for g in result.datasets.groups)


def test_legacy_and_unsupported_business_wrappers_are_explicit_private_obligations():
    rows=dataset_rows()
    legacy=Row(Key('state','idempotency#'+'e'*64),1,{'body_hash':'d'*64,'result':{'private':'LEGACY_PRIVATE'},'at_ms':50})
    unsupported=saved(find(rows,'observation_completed'),{'private':'UNSUPPORTED_PRIVATE'},430)
    result=run((*rows,legacy,unsupported))
    assert {o.reason for o in result.obligations}=={'LEGACY_PROVENANCE_UNRESOLVED','BUSINESS_CODEC_UNSUPPORTED'}
    assert {legacy.key,unsupported.key}<={r.key for r in result.residual}
    assert all(v not in repr(result) for v in ['LEGACY_PRIVATE','UNSUPPORTED_PRIVATE'])


def test_unknown_transaction_peer_is_included_and_cannot_borrow_scope():
    rows=dataset_rows();event=find(rows,'observation_admitted')
    unknown=replace(event,key=Key('events','future-event#'+uid(999)))
    root=saved(event,{'inspection_id':uid(1),'observation_id':uid(8),'sequence':1},440)
    result=run((*rows,unknown,root))
    assert len(result.obligations)==1 and result.obligations[0].reason=='PEER_POLICY_UNRESOLVED'
    assert root.key in {r.key for r in result.residual}


def test_digest_alone_never_merges_different_envelopes(monkeypatch):
    monkeypatch.setattr(replay_corpus,'_binding_key',lambda _: 'forced-collision')
    with pytest.raises(ReplayCorpusHeld):run(corpus())


def test_replay_and_complete_peer_bounds_are_independent():
    rows=corpus();assert len(run(rows,limits=replace(LIMITS,max_replays=6)).families)==6
    with pytest.raises(ReplayCorpusHeld):run(rows,limits=replace(LIMITS,max_replays=5))
    with pytest.raises(ReplayCorpusHeld,match='transaction event bound'):
        run(changed_groups(),limits=replace(LIMITS,max_transaction_events=1))


@pytest.mark.parametrize('bad',[True,0,-1,2**63,1.5,None])
def test_replay_limits_are_explicit_finite_integers(bad):
    for field in ['max_replays','max_transaction_events']:
        with pytest.raises(ValueError):replace(LIMITS,**{field:bad})


def test_exact_and_one_below_cumulative_work_and_expansion_bounds():
    rows=corpus();result=run(rows)
    exact=replace(LIMITS,dataset=replace(DATASET_LIMITS,
        corpus=replace(DATASET_LIMITS.corpus,max_records=len(rows),max_work=result.work),
        family_max_records=result.max_family_records_used,family_max_payload_bytes=result.max_family_payload_bytes_used))
    assert run(rows,limits=exact)==result
    with pytest.raises(ReplayCorpusHeld):run(rows,limits=replace(exact,dataset=replace(exact.dataset,
        corpus=replace(exact.dataset.corpus,max_work=result.work-1))))


@pytest.mark.parametrize('fault',['mutation','clock','deadline','revision-type'])
def test_last_phase_keeps_original_sources_clock_and_deadline(monkeypatch,fault):
    unknown=Row(Key('state','future#phase'),1,{'private':'retained'})
    rows=(*corpus(),unknown);original=replay_corpus.dataset_derive;after=False
    def first(*args,**kwargs):
        nonlocal after
        result=original(*args,**kwargs);after=True
        if fault=='mutation':unknown.data['private']='changed'
        if fault=='revision-type':object.__setattr__(unknown,'revision',True)
        return result
    monkeypatch.setattr(replay_corpus,'dataset_derive',first)
    def clock():return (1000 if fault=='deadline' else 99) if after else 100
    with pytest.raises(ReplayCorpusHeld):run(rows,tick=clock if fault in {'clock','deadline'} else lambda:1)


def test_deterministic_frozen_metadata_result():
    rows=corpus();result=run(rows)
    assert run(tuple(reversed(rows)))==result and run(rows[15:]+rows[:15])==result
    with pytest.raises(FrozenInstanceError):result.work=0
