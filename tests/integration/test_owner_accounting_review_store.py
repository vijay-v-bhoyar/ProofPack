"""Owned local DynamoDB, actual CV publication, synthetic auth and intercepted S3."""
from dataclasses import replace
from time import monotonic_ns
from uuid import uuid4
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_privacy_admission_store import setup
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import Key,Write,StoreConflict
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.held_inventory import HeldInventoryLimits
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence.dataset_corpus import DatasetCorpusLimits
from proofpack.evidence.replay_corpus import ReplayCorpusLimits
from proofpack.evidence.reference_corpus import ReferenceCorpusLimits
from proofpack.evidence.reference_lineage import ReferenceLimits
from proofpack.evidence.held_corpus import HeldCorpusReader,HeldCorpusLimits,HeldCorpusHeld
from proofpack.evidence.corpus_accounting import AccountingLimits
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
from proofpack.evidence.privacy_admission import AdmissionHeld
from proofpack.runtime.ownership import ResourceOwner


def prepared(world,publication_case):
    _,capture,started,operator,_,_,_,_,_,observe=publication_case
    observe();ident=started['inspection_id'];repository=world[1]
    key=Key('state','inspection#'+ident);row=repository.snapshot((key,))[key]
    capture.stations.close(operator,inspection_id=ident,expected_version=row.revision,
        expected_epoch=int(row.data['station_epoch']),reason='synthetic owner review preparation',
        disposition='cancelled',idempotency_key='close-for-owner-review')
    admission,_=setup(world);owner=ResourceOwner()
    requests=OwnerMetadataRequests(world[0],admission,owner,
        limits=OwnerMetadataLimits(10,20,100,20000),tick_ns=monotonic_ns)
    context=requests.context(world[5])
    request=requests.create(world[5],inspection_ids=(ident,),expected_gate_version=context['gate_version'],
        expected_control_version=context['control_version'],interruption_acknowledged=True,idempotency_key='native-owner-review')
    inv=HeldInventoryLimits(InventoryLimits(100,50,2000,2_000_000),20,4_000_000)
    analysis=ReplayCorpusLimits(DatasetCorpusLimits(InspectionCorpusLimits(2000,4_000_000,30,200_000),
        10000,16_000_000,100,100),500,20)
    limits=HeldCorpusLimits(analysis,40,8_000_000,4_000_000,
        ReferenceCorpusLimits(100,ReferenceLimits(32,1_000_000,64,10000),200_000,2_000_000))
    reader=HeldCorpusReader(admission,owner,inventory_limits=inv,limits=limits,tick=monotonic_ns)
    service=OwnerMetadataReview(requests,reader,
        accounting_limits=AccountingLimits(2000,30,10000,200000,4_000_000),max_response_bytes=8192)
    return service,requests,reader,owner,request,ident


def read(p,actor,**changes):
    r=p[4]
    return p[0].read(actor,ident=r['id'],**(dict(expected_request_version=r['state_version'],
        expected_gate_version=r['gate_version'],expected_control_version=r['control_version'])|changes))


def inventory(repository):
    result=[]
    for table in repository.tables:
        cursor=None
        for _ in range(50):
            rows,cursor=repository.partition_page(table=table,limit=100,start_resource=cursor)
            result.extend(rows)
            if cursor is None:break
        else:pytest.fail('test inventory exceeded its declared page bound')
    return sorted(result,key=lambda r:(r.key.table,r.key.resource))


def test_actual_owner_review_covers_complete_published_inventory_without_writes(world,publication_case,monkeypatch):
    p=prepared(world,publication_case);before=inventory(world[1])
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('owner review wrote metadata'))
    result=read(p,world[5])
    assert result['id']==p[4]['id'] and result['scope_sha256']==p[4]['scope_sha256']
    assert result['total_records']==sum(result['counts'].values())==len(before)
    assert result['counts']['AFFECTED']>0 and result['counts']['UNRESOLVED']>0
    assert result['historical'] is True and result['read_only'] is True
    assert all(result[k] is False for k in ['can_confirm_cleanup','erasure_complete','request_fulfilled'])
    assert inventory(world[1])==before and p[3].wait_for_drain(0)
    assert all(text not in repr(result) for text in ['deployments/','session#','idempotency#','result_json','example.invalid'])


def test_actual_stale_review_versions_deny_before_private_inventory(world,publication_case,monkeypatch):
    p=prepared(world,publication_case)
    monkeypatch.setattr(p[2],'read_accounting',lambda **k:pytest.fail('stale owner review read private inventory'))
    with pytest.raises(StoreConflict):read(p,world[5],expected_gate_version=p[4]['gate_version']+1)
    assert p[3].wait_for_drain(0)


def test_actual_operator_cannot_read_owner_inventory(world,publication_case,monkeypatch):
    p=prepared(world,publication_case)
    monkeypatch.setattr(p[2],'read_accounting',lambda **k:pytest.fail('operator reached owner inventory'))
    with pytest.raises(Denied):read(p,publication_case[3])
    assert p[3].wait_for_drain(0)


@pytest.mark.parametrize('change',['phantom','payload'])
def test_actual_post_reader_source_change_is_held(world,publication_case,monkeypatch,change):
    p=prepared(world,publication_case);original=p[2].read_accounting;changed=[]
    def race(**kw):
        result=original(**kw)
        if change=='phantom':
            world[1].transact((Write(Key('state','unknown-owner-review#'+str(uuid4())),None,{'private':'DO_NOT_DISCLOSE'}),))
        else:
            key=Key('state','inspection#'+p[5]);row=world[1].snapshot((key,))[key]
            world[1].transact((Write(key,row.revision,{**row.data,'synthetic_private':'DO_NOT_DISCLOSE'}),))
        changed.append(True);return result
    monkeypatch.setattr(p[2],'read_accounting',race)
    with pytest.raises(HeldCorpusHeld):read(p,world[5])
    assert changed==[True] and p[3].wait_for_drain(0)


def test_actual_owner_loss_after_private_read_cannot_deliver_review(world,publication_case,monkeypatch):
    p=prepared(world,publication_case);original=p[2].read_accounting;changed=[]
    def revoke(**kw):
        result=original(**kw);row=world[1].snapshot((world[5].member.key,))[world[5].member.key]
        world[1].transact((Write(row.key,row.revision,{**row.data,'enabled':False}),));changed.append(True)
        return result
    monkeypatch.setattr(p[2],'read_accounting',revoke)
    with pytest.raises((Denied,StoreConflict,AdmissionHeld,HeldCorpusHeld)):read(p,world[5])
    assert changed==[True] and p[3].wait_for_drain(0)


def test_actual_client_cleanup_waits_through_outer_final_inventory_and_authority(world,publication_case,monkeypatch):
    p=prepared(world,publication_case);original=p[2].read_accounting;client=world[1].client
    close=client.close;call=client._make_api_call;closed=[];after=[];post_calls=[]
    def guarded(*a,**k):
        assert not closed,'SDK call after premature owner-review cleanup'
        if after:post_calls.append(True)
        return call(*a,**k)
    def close_client():closed.append(True);close()
    def stop_after_inner(**kw):
        result=original(**kw);assert not p[3].wait_for_drain(0)
        p[3].stop_accepting();p[3].after_drain(close_client);after.append(True)
        assert not closed;return result
    monkeypatch.setattr(client,'_make_api_call',guarded);monkeypatch.setattr(p[2],'read_accounting',stop_after_inner)
    result=read(p,world[5])
    assert result['total_records']>0 and after==[True] and post_calls
    assert closed==[True] and p[3].wait_for_drain(0)


def test_actual_spent_capacity_performs_no_final_inventory_io(world,publication_case,monkeypatch):
    p=prepared(world,publication_case);original=p[2].read_accounting;after=[];extra=[]
    snapshot=world[1].inventory_snapshot;page=world[1].partition_page
    def observe_snapshot(*a,**k):
        if after:extra.append('snapshot')
        return snapshot(*a,**k)
    def observe_page(*a,**k):
        if after:extra.append('page')
        return page(*a,**k)
    def exhaust(**kw):
        result=original(**kw);after.append(True)
        return replace(result,corpus=replace(result.corpus,snapshot_batches=p[2].limits.max_total_snapshot_batches))
    monkeypatch.setattr(world[1],'inventory_snapshot',observe_snapshot);monkeypatch.setattr(world[1],'partition_page',observe_page)
    monkeypatch.setattr(p[2],'read_accounting',exhaust)
    with pytest.raises(HeldCorpusHeld):read(p,world[5])
    assert after==[True] and extra==[] and p[3].wait_for_drain(0)
