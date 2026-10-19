"""Genuine local reference producer/CV and stored history; S3 intercepted."""
from time import monotonic_ns
import pytest

from test_references import reference_case, upload
from test_access_lifecycle import world, repository_factory
from proofpack.evidence.repository import Key, StoreUnavailable, Write
from proofpack.evidence.reference_lineage import discover, ReferenceLimits, ReferenceHistoryHeld
from proofpack.vision.worker import WorkerUnavailable


def records(repo):
    result=[]
    for table in ['state','events']:
        cursor=None
        for _ in range(20):
            page,cursor=repo.partition_page(table=table,limit=100,start_resource=cursor)
            result.extend(page)
            if cursor is None:break
        else:pytest.fail('native fixture enumeration bound exhausted')
    roots=[r for r in result if r.key.resource.startswith('reference-intent#')]
    assert len(roots)==1
    root=roots[0];ident=root.data['id'];selected=[]
    for row in result:
        if row.key==Key('state','asset#'+ident):selected.append(row)
        elif row.key.table=='state' and row.key.resource.startswith('idempotency#') and row.data.get('result',{}).get('id')==ident:selected.append(row)
        elif row.key.table=='events' and row.data.get('kind')=='reference-upload':selected.append(row)
        elif row.key.table=='events' and row.data.get('kind')=='reference_committed' and row.data.get('asset_id')==ident:selected.append(row)
    return root,tuple(selected)


def parse(repo):
    root,rows=records(repo)
    return discover(root,rows,deployment=repo.deployment,limits=ReferenceLimits(32,1_000_000,64,1000),
        deadline_ns=monotonic_ns()+20_000_000_000,tick=monotonic_ns,checkpoint=lambda:None)


def test_actual_committed_reference_history_is_complete_private_and_non_authorizing(world,reference_case,monkeypatch):
    result=upload(world,reference_case);repo=world[1]
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('history reader wrote store'))
    family=parse(repo)
    assert family.state=='linked' and family.asset.key==Key('state','asset#'+result['id'])
    assert len(family.records)==4 and len(family.media)==1
    assert family.media[0].version_id==reference_case[2].heads[result['id']]['VersionId']
    assert 'INSPECTION_ORIGIN_NOT_RECORDED' in family.obligations
    assert result['id'] not in repr(family) and 'deployments/' not in repr(family)


def test_actual_failure_before_normalization_retains_reserved_reconciliation_history(world,reference_case,monkeypatch):
    _,references,_,request,payload=reference_case;ticket=references.begin(world[5])
    def fail(*a,**k):raise WorkerUnavailable('synthetic failed reference normalization')
    monkeypatch.setattr(ticket.worker,'reference',fail)
    try:
        with pytest.raises(StoreUnavailable):references.upload(world[5],ticket=ticket,request=request,payload=payload,
            content_type='image/png',idempotency_key='reference-history-before')
    finally:references.end(ticket)
    family=parse(world[1]);assert family.state=='needs_reconciliation' and not family.asset and not family.media
    assert 'STORAGE_RECONCILIATION_REQUIRED' in family.obligations
    assert records(world[1])[0].revision==2


def test_actual_uploaded_but_unacknowledged_output_remains_storage_obligation(world,reference_case):
    objects=reference_case[2]
    def fail():raise StoreUnavailable('synthetic interruption after reference put/head')
    objects.after_put=fail
    with pytest.raises(StoreUnavailable):upload(world,reference_case,key='reference-history-after-put')
    family=parse(world[1]);assert family.state=='needs_reconciliation' and not family.asset and not family.media
    assert objects.payloads and records(world[1])[0].revision==3
    assert 'STORAGE_RECONCILIATION_REQUIRED' in family.obligations


def test_actual_later_asset_mutation_does_not_reuse_old_upload_acceptance(world,reference_case):
    result=upload(world,reference_case);repo=world[1];key=Key('state','asset#'+result['id'])
    row=repo.snapshot((key,))[key]
    repo.transact((Write(key,row.revision,{**row.data,'read_denied':True}),))
    with pytest.raises(ReferenceHistoryHeld):parse(repo)
