"""Actual local decision/capture records; no actual people, provider or truth proof."""
from dataclasses import replace
import pytest
from test_access_lifecycle import world, repository_factory, publication_case
from test_dispositions import decision_case
from test_capture_family_store import capture_rows
from proofpack.evidence.human_lineage import discover, HumanHistoryHeld
from proofpack.stations.service import inspection_key, station_key


def gather(repo, ident):
    selected=[]
    for table in ('state','events'):
        cursor=None
        for _ in range(100):
            page,cursor=repo.partition_page(table=table,limit=100,start_resource=cursor)
            for row in page:
                if row.key.resource.startswith('human-disposition#'+ident+'#') or (row.key.table=='events' and row.data.get('kind')=='inspection-disposition:'+ident):selected.append(row)
            if cursor is None:break
        else:raise AssertionError('bounded fixture history inventory exhausted')
    return tuple(selected)


def closed(repo,service,operator,ident):
    root=repo.snapshot((inspection_key(ident),))[inspection_key(ident)]
    station=repo.snapshot((station_key(root.data['station_id']),))[station_key(root.data['station_id'])]
    service.close(operator,inspection_id=ident,expected_version=root.revision,expected_epoch=int(station.data['epoch']),
        reason='History fixture close',disposition='cancelled',idempotency_key='history-close')
    return repo.snapshot((root.key,))[root.key]


def checked(repo,root):
    rows=gather(repo,root.data['id']);capture=capture_rows(repo,root.data['id'])
    result=discover(root,rows,capture_rows=capture,deployment=repo.deployment,max_records=1000,max_payload_bytes=2000000)
    assert {r.key for r in result.records}=={r.key for r in rows}
    assert not any(r.key.resource.startswith(('user#','cookie#','station#')) for r in result.records)
    return result,rows,capture


def test_actual_append_revisions_preserve_manual_history_after_different_close_choice(world,decision_case):
    service,operator,credentials,args=decision_case
    first=service.record_disposition(operator,**args)
    second=service.record_disposition(operator,**{**args,'expected_version':2,'disposition':'human_accepted','human_check_confirmed':True,'idempotency_key':'history-second'})
    root=closed(world[1],service,operator,args['inspection_id']);result,rows,capture=checked(world[1],root)
    assert len(result.records)==4 and second['decision']['previous_id']==first['id']
    assert root.data['disposition']=='cancelled' and second['decision']['disposition']=='human_accepted'
    assert not result.capture.media and not hasattr(result,'machine_approval')


def test_close_choice_without_append_record_is_not_invented_as_human_history(world,decision_case):
    service,operator,credentials,args=decision_case
    result,_,_=checked(world[1],closed(world[1],service,operator,args['inspection_id']))
    assert not result.records and not result.links


@pytest.mark.parametrize('missing',['whole','event','record'])
def test_actual_missing_history_or_peer_holds_instead_of_partial_success(world,decision_case,missing):
    service,operator,credentials,args=decision_case;service.record_disposition(operator,**args)
    root=closed(world[1],service,operator,args['inspection_id']);rows=gather(world[1],root.data['id'])
    rows=() if missing=='whole' else tuple(r for r in rows if r.key.table!=('events' if missing=='event' else 'state'))
    with pytest.raises(HumanHistoryHeld):discover(root,rows,capture_rows=(),deployment=world[1].deployment,max_records=1000,max_payload_bytes=2000000)


def record(world,case,key,choice='rework'):
    _,capture,started,operator=case[:4];root=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    return capture.stations.record_disposition(operator,inspection_id=started['inspection_id'],expected_version=root.revision,
        expected_epoch=int(root.data['station_epoch']),disposition=choice,reason='Synthetic manual fixture record',
        human_check_confirmed=choice=='human_accepted',idempotency_key=key)


def test_actual_observed_source_is_bound_to_its_historical_inspection_transition(world,publication_case):
    publication_case[-1]()
    decision=record(world,publication_case,'observed-decision','human_accepted')
    root=closed(world[1],publication_case[1].stations,publication_case[3],publication_case[2]['inspection_id'])
    result,_,_=checked(world[1],root)
    assert len(result.capture.media)==2
    assert any(link.target.resource=='observation#'+decision['decision']['source_observation_id'] for link in result.links)


def test_decision_before_first_image_keeps_no_source_after_later_capture(world,publication_case):
    decision=record(world,publication_case,'before-observation')
    assert decision['decision']['source_observation_id'] is None
    publication_case[-1]()
    root=closed(world[1],publication_case[1].stations,publication_case[3],publication_case[2]['inspection_id'])
    result,_,_=checked(world[1],root)
    assert result.capture.media and not any(link.kind=='historical_decision_source' for link in result.links)


def test_two_decisions_retain_distinct_sources_after_another_completed_observation(world,publication_case):
    publication_case[-1]();first=record(world,publication_case,'first-source')
    publication_case[-1]();second=record(world,publication_case,'second-source','human_accepted')
    assert first['decision']['source_observation_id']!=second['decision']['source_observation_id']
    root=closed(world[1],publication_case[1].stations,publication_case[3],publication_case[2]['inspection_id'])
    result,_,_=checked(world[1],root)
    assert sum(link.kind=='historical_decision_source' for link in result.links)==2
