from dataclasses import replace
from test_capture_lineage import family,DEPLOYMENT
from test_capture_lineage import uid, key
from copy import deepcopy
from dataclasses import FrozenInstanceError
import pytest
from proofpack.evidence.repository import Key, Row, Write, ErasureMarker
from proofpack.evidence.resource_bindings import prepare_linked, _payload_sha256
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.human_lineage import discover, HumanHistoryHeld


def history(count=2):
    root,capture=family()
    root=replace(root,revision=max(10,8+count),data={**root.data,'disposition':'cancelled',
        'latest_disposition_id':None if not count else uid(40+count-1),'closed_at_ms':max(100,100+count*1000)})
    rows=[];previous=None
    for number in range(count):
        rid=uid(40+number);source_version=7+number;at=60+number*1000
        data={'id':rid,'inspection_id':root.data['id'],'station_id':root.data['station_id'],'station_epoch':1,
            'source_inspection_revision':source_version,'source_state':'OBSERVING','source_observation_id':uid(8),
            'previous_id':None if previous is None else previous.data['id'],'disposition':'rework' if number==0 else 'human_accepted',
            'reason':'Recorded manual decision','human_check_confirmed':bool(number),'actor_user_id':uid(6),
            'actor_session_id':uid(5),'at_ms':at,'machine_approval':False,'independent_truth_verified':False}
        data['sha256']=digest(data);record=Row(Key('state','human-disposition#'+uid(1)+'#'+rid),1,data)
        old={k:v for k,v in root.data.items() if k not in {'closed_at_ms'}}
        old.update(state='OBSERVING',disposition=None if previous is None else previous.data['disposition'],
            latest_disposition_id=None if previous is None else previous.data['id'])
        current={**old,'disposition':data['disposition'],'latest_disposition_id':rid}
        event_key=key('access',3000+number,'events')
        event_data={'kind':'inspection-disposition:'+uid(1),'actor_scope':'f'*64,'at_ms':at,'session_id':uid(5),
            'details':{'inspection_id':uid(1),'decision_id':rid,'disposition':data['disposition'],'sha256':data['sha256']}}
        checked=(Row(root.key,source_version,old),Row(key('user',6),1,{'id':uid(6)}))
        if previous is not None:checked=(*checked,previous)
        writes,_=prepare_linked(DEPLOYMENT,event_data['kind'],
            (Write(root.key,source_version,current),Write(record.key,None,data),Write(event_key,None,event_data)),checked)
        event=Row(event_key,1,next(w.data for w in writes if w.key==event_key))
        rows.extend((record,event));previous=record
    return root,capture,tuple(rows)


def run(root,capture,rows,**changes):
    return discover(root,rows,capture_rows=capture,**({'deployment':DEPLOYMENT,'max_records':10000,'max_payload_bytes':16000000}|changes))


def changed(rows,ident,changes,*,resign=True):
    rows=deepcopy(rows);target=next(r for r in rows if r.key.table=='state' and r.data['id']==ident)
    data={**target.data,**changes}
    if resign:data['sha256']=digest({k:v for k,v in data.items() if k!='sha256'})
    payload=_payload_sha256(data);result=[]
    for row in rows:
        if row.key==target.key:result.append(replace(row,data=data));continue
        if row.key.table=='events':
            event=deepcopy(row.data)
            if event['details']['decision_id']==ident:
                event['details'].update(sha256=data['sha256'],disposition=data['disposition'])
            for reference in (*event['resource_bindings']['writes'],*event['resource_bindings']['checks']):
                if reference['table']==target.key.table and reference['resource']==target.key.resource:reference['sha256']=payload
            row=replace(row,data=event)
        result.append(row)
    return tuple(result)


def test_empty_closed_human_history_is_valid_without_converting_close_choice_to_verified_truth():
    from proofpack.evidence.human_lineage import discover
    root,_=family()
    root=replace(root,data={**root.data,'latest_input_sequence':0,'verified_sequence':0,'latest_observation_id':None,'disposition':'cancelled'})
    result=discover(root,(),capture_rows=(),deployment=DEPLOYMENT,max_records=20,max_payload_bytes=100000)
    assert result.records==() and result.capture.records==()
    assert not hasattr(result,'machine_pass')


def test_complete_append_history_is_detached_and_final_close_choice_does_not_replace_it():
    root,capture,rows=history();before=deepcopy((root,capture,rows));result=run(root,capture,rows)
    assert len(result.records)==4 and root.data['disposition']=='cancelled'
    assert rows[-2].data['disposition']=='human_accepted' and len(result.capture.records)==6
    assert result==run(root,tuple(reversed(capture)),tuple(reversed(rows))) and (root,capture,rows)==before
    assert all(not hasattr(record,'data') for record in result.records)
    assert 'Recorded manual decision' not in repr(result)
    with pytest.raises(FrozenInstanceError):result.payload_bytes=0


def test_bounds_include_root_capture_and_human_payloads_independently():
    root,capture,rows=history();result=run(root,capture,rows);count=1+len(capture)+len(rows)
    assert run(root,capture,rows,max_records=count,max_payload_bytes=result.payload_bytes)==result
    for limits in ({'max_records':count-1},{'max_payload_bytes':result.payload_bytes-1}):
        with pytest.raises(HumanHistoryHeld):run(root,capture,rows,**limits)


@pytest.mark.parametrize('name',['max_records','max_payload_bytes'])
@pytest.mark.parametrize('value',[None,0,-1,True,1.0,'10',2**63])
def test_bounds_require_explicit_positive_exact_storage_integers(name,value):
    with pytest.raises(ValueError):run(*history(),**{name:value})


@pytest.mark.parametrize('changes',[
    {'inspection_id':uid(99)},{'station_id':uid(99)},{'station_epoch':True},{'station_epoch':2},
    {'source_inspection_revision':0},{'source_inspection_revision':9},{'source_inspection_revision':2**63},
    {'source_state':'CLOSED'},{'source_state':'unsupported'},{'source_observation_id':uid(99)},
    {'source_observation_id':None},{'previous_id':uid(99)},{'previous_id':uid(41)},
    {'disposition':'approved_by_machine'},{'human_check_confirmed':False},{'human_check_confirmed':1},
    {'machine_approval':True},{'independent_truth_verified':True},{'actor_user_id':uid(99)},
    {'actor_session_id':uid(99)},{'at_ms':-1},{'at_ms':5000},{'at_ms':True},
    {'reason':' '},{'reason':'bad\nreason'},{'reason':'x'*121},{'schema_version':99},
])
def test_resigned_but_unsupported_record_semantics_do_not_become_valid_history(changes):
    root,capture,rows=history()
    with pytest.raises(HumanHistoryHeld):run(root,capture,changed(rows,uid(41),changes))


@pytest.mark.parametrize('fault',['body_hash','missing_record','missing_event','empty_family','duplicate',
    'erased','wrong_table','revision_two','revision_bool','missing_latest','foreign_latest','cycle',
    'event_session','event_details','event_operation','missing_binding','foreign_binding','missing_user_check','stray_write'])
def test_incomplete_corrupt_or_unsupported_history_holds_without_partial_result(fault):
    root,capture,rows=history();rows=deepcopy(rows)
    if fault=='body_hash':rows=changed(rows,uid(41),{'reason':'modified'},resign=False)
    elif fault=='missing_record':rows=tuple(r for r in rows if r.key!=rows[0].key)
    elif fault=='missing_event':rows=tuple(r for r in rows if r.key!=rows[1].key)
    elif fault=='empty_family':rows=()
    elif fault=='duplicate':rows=(*rows,rows[0])
    elif fault=='erased':rows=(ErasureMarker(rows[0].key,2,'a'*64,'b'*64),*rows[1:])
    elif fault=='wrong_table':rows=(replace(rows[0],key=Key('events',rows[0].key.resource)),*rows[1:])
    elif fault=='revision_two':rows=(replace(rows[0],revision=2),*rows[1:])
    elif fault=='revision_bool':rows=(replace(rows[0],revision=True),*rows[1:])
    elif fault=='missing_latest':root=replace(root,data={**root.data,'latest_disposition_id':None})
    elif fault=='foreign_latest':root=replace(root,data={**root.data,'latest_disposition_id':uid(99)})
    elif fault=='cycle':rows=changed(rows,uid(40),{'previous_id':uid(41)})
    else:
        event=rows[-1];data=deepcopy(event.data)
        if fault=='event_session':data['session_id']=uid(99)
        elif fault=='event_details':data['details']['sha256']='0'*64
        elif fault=='event_operation':data['kind']='label-create'
        elif fault=='missing_binding':data.pop('resource_bindings')
        elif fault=='foreign_binding':data['resource_bindings']['deployment']='foreign'
        elif fault=='missing_user_check':data['resource_bindings']['checks']=[r for r in data['resource_bindings']['checks'] if not r['resource'].startswith('user#')]
        elif fault=='stray_write':data['resource_bindings']['writes'].append({'table':'state','resource':'foreign#'+uid(99),'previous_revision':None,'revision':1,'sha256':'0'*64});data['resource_bindings']['writes'].sort(key=lambda r:(r['table'],r['resource']))
        rows=(*rows[:-1],replace(event,data=data))
    with pytest.raises(HumanHistoryHeld):run(root,capture,rows)


@pytest.mark.parametrize('fault',['capture_missing','capture_changed','capture_duplicate','capture_unknown','root_changed'])
def test_capture_dependency_is_revalidated_instead_of_accepting_a_claimed_success(fault):
    root,capture,rows=history()
    if fault=='capture_missing':capture=()
    elif fault=='capture_changed':capture=(replace(capture[0],data={**capture[0].data,'station_epoch':9}),*capture[1:])
    elif fault=='capture_duplicate':capture=(*capture,capture[0])
    elif fault=='capture_unknown':capture=(*capture,Row(Key('state','foreign#'+uid(99)),1,{}))
    elif fault=='root_changed':root=replace(root,data={**root.data,'state':'OBSERVING'})
    with pytest.raises(HumanHistoryHeld):run(root,capture,rows)


def test_nonrecursive_history_can_exceed_python_recursion_depth_with_finite_limits():
    root,capture,rows=history(1050);result=run(root,capture,rows)
    assert len(result.records)==2100

@pytest.mark.parametrize('value',[None,'','../foreign','foreign target'])
def test_deployment_is_explicit_valid_configuration(value):
    with pytest.raises(ValueError):run(*history(),deployment=value)
