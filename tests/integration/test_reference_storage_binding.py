"""Original target at actual local producer boundaries; S3 is intercepted."""
from dataclasses import asdict,replace
import pytest
from test_references import reference_case,upload
from test_access_lifecycle import world,repository_factory
from test_reference_lineage_store import records,parse
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key,StoreUnavailable,StoreConflict,Write


def test_committed_reference_uses_reserved_target_and_version(world,reference_case):
    expected=digest(asdict(reference_case[2].config));result=upload(world,reference_case)
    root,_=records(world[1]);asset=world[1].snapshot((Key('state','asset#'+result['id']),))[Key('state','asset#'+result['id'])]
    assert root.data['history_version']==2
    assert root.data['storage_binding_sha256']==asset.data['storage_binding_sha256']==expected
    assert 'STORAGE_TARGET_NOT_RECORDED' not in parse(world[1]).obligations
    assert 'storage_binding_sha256' not in result and 'history_version' not in result


@pytest.mark.parametrize('boundary',['reservation','writing','final'])
def test_target_change_cannot_publish_reference(world,reference_case,monkeypatch,boundary):
    _,references,objects,*_=reference_case;expected=digest(asdict(objects.config));changed=False
    if boundary=='final':
        original=references.access._prepare_linked
        def repoint(operation,writes,checks=()):
            nonlocal changed
            result=original(operation,writes,checks)
            if operation=='reference_committed':
                changed=True;objects.config=replace(objects.config,bucket='proofpack-other-synthetic')
            return result
        monkeypatch.setattr(references.access,'_prepare_linked',repoint)
    else:
        original=world[1].transact
        def repoint(writes,checks=()):
            nonlocal changed
            result=original(writes,checks)
            if not changed and any(w.key.resource.startswith('reference-intent#') and
                    w.data.get('status')==('reserved' if boundary=='reservation' else 'writing') for w in writes):
                changed=True;objects.config=replace(objects.config,bucket='proofpack-other-synthetic')
            return result
        monkeypatch.setattr(world[1],'transact',repoint)
    with pytest.raises(StoreUnavailable):upload(world,reference_case,key='target-'+boundary)
    root,_=records(world[1]);assert changed and root.data['status']=='needs_reconciliation'
    assert root.data['storage_binding_sha256']==expected
    assert objects.calls==(1 if boundary=='final' else 0)
    assert world[1].snapshot((Key('state','asset#'+root.data['id']),))[Key('state','asset#'+root.data['id'])] is None
    assert 'STORAGE_RECONCILIATION_REQUIRED' in parse(world[1]).obligations


def test_target_change_after_actual_put_keeps_original_uncertainty(world,reference_case):
    objects=reference_case[2];expected=digest(asdict(objects.config))
    objects.after_put=lambda:setattr(objects,'config',replace(objects.config,bucket='proofpack-other-synthetic'))
    with pytest.raises(StoreUnavailable):upload(world,reference_case,key='after-put-target')
    root,_=records(world[1]);assert root.data['storage_binding_sha256']==expected
    assert root.data['status']=='needs_reconciliation' and 'object_receipt' not in root.data
    assert objects.payloads and not parse(world[1]).media


def test_tampered_reserved_intent_is_never_uploaded(world,reference_case,monkeypatch):
    repo=world[1];original=repo.transact;changed=False
    def tamper(writes,checks=()):
        nonlocal changed
        result=original(writes,checks)
        if not changed:
            for w in writes:
                if w.key.resource.startswith('reference-intent#') and w.expected_revision is None:
                    changed=True;row=repo.snapshot((w.key,))[w.key]
                    original((Write(w.key,row.revision,{**row.data,'storage_binding_sha256':'f'*64}),))
        return result
    monkeypatch.setattr(repo,'transact',tamper)
    with pytest.raises(StoreConflict):upload(world,reference_case,key='tampered-intent')
    assert changed and reference_case[2].calls==0
    root,_=records(repo);assert root.data['status']=='needs_reconciliation' and 'object_receipt' not in root.data
