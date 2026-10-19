"""Actual local purpose/access storage; trusted synthetic identity, not Cognito."""
from time import monotonic_ns
from uuid import uuid4
import pytest
from test_access_lifecycle import world,repository_factory
from test_owner_accounting_review_store import inventory
from proofpack.evidence.purposes import DataPurposes,PurposeRequest,purpose_key
from proofpack.evidence.purpose_history import discover,PurposeHistoryLimits,PurposeHistoryHeld
from proofpack.evidence.originals import ORIGINAL_NOTICE_SHA256
from proofpack.runtime.control import RuntimeControl

LIMITS=PurposeHistoryLimits(100,1_000_000,1000,10000,1_000_000)


def prepare(world,mode,original):
    access,repo,clock,uid,credentials,actor=world
    runtime=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='test')
    runtime.start();service=DataPurposes(access,runtime,max_lifetime_ms=100000)
    notice=access.operational_notice(actor)
    request=PurposeRequest(notice_version=notice['version'],notice_sha256=notice['sha256'],
        source_permission_reference='synthetic-store-source',operational_use_acknowledged=True,
        expires_at_ms=clock()+50000,**({'original_capture_retention_acknowledged':True,
        'original_capture_notice_sha256':ORIGINAL_NOTICE_SHA256} if original else {}))
    created=service.create(actor,request=request,idempotency_key='create-purpose')
    if mode!='created':service.withdraw(actor,ident=created['id'],expected_version=1,idempotency_key='withdraw-purpose')
    if mode=='noop':service.withdraw(actor,ident=created['id'],expected_version=2,idempotency_key='noop-purpose')
    return service,actor,created['id']


def selected(repo,ident):
    root=repo.snapshot((purpose_key(ident),))[purpose_key(ident)]
    rows=tuple(r for r in inventory(repo) if r.data.get('resource_bindings',{}).get('operation') in {'purpose-create','purpose-withdraw'}
        and ((r.key.table=='events' and r.data.get('details',{}).get('purpose_id')==ident)
             or (r.key.table=='state' and r.data.get('result')=={'id':ident})))
    return root,rows


@pytest.mark.parametrize('mode',['created','withdrawn','noop'])
@pytest.mark.parametrize('original',[False,True])
def test_actual_store_history_matches_writer_and_never_mutates_business_data(world,mode,original,monkeypatch):
    _,_,ident=prepare(world,mode,original);repo=world[1];root,rows=selected(repo,ident);before=inventory(repo)
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('history parser wrote business data'))
    result=discover(root,rows,deployment=repo.deployment,limits=LIMITS,
        deadline_ns=monotonic_ns()+5_000_000_000,tick=monotonic_ns,checkpoint=lambda:None)
    assert len(result.records)==len(rows)+1 and result.state==('ACTIVE_HISTORY' if mode=='created' else 'WITHDRAWN_HISTORY')
    assert result.historical is True and result.rights_independently_verified is False and result.can_confirm_cleanup is False
    assert ident not in repr(result) and inventory(repo)==before


def test_actual_ambiguous_noop_output_set_cannot_be_paired_by_guessing(world):
    service,actor,ident=prepare(world,'noop',False)
    service.withdraw(actor,ident=ident,expected_version=2,idempotency_key='another-noop-purpose')
    root,rows=selected(world[1],ident);before=inventory(world[1])
    with pytest.raises(PurposeHistoryHeld):discover(root,rows,deployment=world[1].deployment,
        limits=LIMITS,deadline_ns=monotonic_ns()+5_000_000_000,tick=monotonic_ns,checkpoint=lambda:None)
    assert inventory(world[1])==before
