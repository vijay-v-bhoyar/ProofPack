"""Pure export contract checks, independent of database and service construction."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from proofpack.evidence.handoff_export import summary,lineage,source,copies
from proofpack.evidence.repository import Key,Row,StoreUnavailable
from proofpack.stations.handoffs import INSPECTION_METADATA_MAX_MS

A='10000000-0000-4000-8000-000000000001'
B='10000000-0000-4000-8000-000000000002'
C='10000000-0000-4000-8000-000000000003'

def fixture():
    request={'sender_user_id':A,'recipient_user_id':B,'sender_role':'operator','reason_code':'support_needed','station_id':C,'station_epoch':1,'station_name':'Station','kit_reference':'kit-1',
      'source_inspection_revision':1,'post_request_inspection_revision':2,'source_observation_id':None,'previous_accepted_handoff_id':None,'created_at_ms':1000,'expires_at_ms':2000,
      'metadata_expires_at_ms':3000,'parent_metadata_expires_at_ms':1000+INSPECTION_METADATA_MAX_MS,'stop_acknowledged':True,
      'sender_cookie_resource':'NEVER_EXPORT_THIS','sender_session_id':'NEVER_EXPORT_THIS','future_private_locator':'NEVER_EXPORT_THIS'}
    raw=Row(Key('state','inspection-handoff#'+A+'#'+B),1,{'id':B,'request':request,'decision':None,'status':'pending','request_sha256':'a'*64,'decision_sha256':None,'private':'NEVER_EXPORT_THIS'})
    work=Row(Key('state','inspection#'+A),3,{'id':A,'station_id':C,'station_epoch':1,'kit_id':'kit-1','created_at_ms':1000,'handoff_count':1,'latest_handoff_id':B})
    events=[{'id':C,'kind':'handoff-request:'+A,'handoff_id':B,'machine_approval':False}]
    return raw,work,events

def test_summary_is_a_whitelist_even_when_future_private_fields_are_added():
    raw,_,_=fixture();value=summary(raw)
    assert 'NEVER_EXPORT_THIS' not in str(value) and 'sender_session_id' not in str(value)
    raw.data['decision']={'kind':'cancelled','actor_user_id':A,'actor_role':'operator','at_ms':1500,'capability':'NEVER_EXPORT_THIS'}
    assert summary(raw)['decision']=={'kind':'cancelled','actor_user_id':A,'actor_role':'operator','at_ms':1500}

def test_lineage_retains_exact_historical_count_and_no_live_authority():
    raw,work,events=fixture();records,state=lineage(work,[summary(raw)],events)
    assert len(records)==1 and state['request_count']==1 and state['accepted_handoff_id'] is None
    assert state['historical'] is True and state['machine_approval'] is False and state['capture_transferred'] is False

@pytest.mark.parametrize('fault',['duplicate-id','duplicate-version','extra-event','missing-event','approval-event','foreign-station','invented-predecessor','wrong-accepted-recipient'])
def test_semantic_lineage_rejects_history_that_passes_superficial_count_checks(fault):
    raw,work,events=fixture();records=[summary(raw)]
    if fault in {'duplicate-id','duplicate-version'}:
        work.data['handoff_count']=2;other=deepcopy(records[0]);records.append(other)
        if fault=='duplicate-id':other['request']['source_inspection_revision']=2;other['request']['post_request_inspection_revision']=3
        else:other['id']=C;work.data['latest_handoff_id']=C
    elif fault=='extra-event':events.append(dict(events[0]))
    elif fault=='missing-event':events.clear()
    elif fault=='approval-event':events[0]['machine_approval']=True
    elif fault=='foreign-station':records[0]['request']['station_id']=B
    elif fault=='invented-predecessor':records[0]['request']['previous_accepted_handoff_id']=C
    else:work.data.update(accepted_handoff_id=B,accepted_recipient_user_id=C)
    with pytest.raises(StoreUnavailable):lineage(work,records,events)

@pytest.mark.parametrize('ident',[None,False,'not-a-uuid'])
def test_corrupt_storage_identity_is_not_reported_as_a_user_input_error(ident):
    with pytest.raises(StoreUnavailable):source(None,None,SimpleNamespace(data={'id':ident}),A,A)

@pytest.mark.parametrize('fault',['reason','extra','missing','duplicate'])
def test_self_consistent_saved_copies_are_compared_with_actual_source_projection(fault):
    row,_,_=fixture();saved=summary(row);data={'handoffs':[saved]}
    assert copies(data,[row])==[row]
    if fault=='reason':saved['request']['reason_code']='capture_interrupted'
    elif fault=='extra':saved['private']='NEVER_EXPORT_THIS'
    elif fault=='missing':data['handoffs']=[]
    else:data['handoffs']=[saved,deepcopy(saved)]
    with pytest.raises(StoreUnavailable):copies(data,[row])
