"""Public boot protocol on modeled state; no hosted or browser/user acceptance."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import anyio
import pytest
from test_privacy_admission import world,hold,intent,ident
from proofpack.evidence.privacy_admission import AdmissionHeld,REGISTRY
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
from proofpack.runtime.ownership import ResourceOwner


def asset(service,number=31):return service._prepare_public_asset(work_id=ident(number),lease_ms=500)


@pytest.mark.parametrize('held',[False,True])
def test_public_assets_are_registered_while_open_or_held_without_control_privilege(held):
    service,repo,runtime,clock=world()
    if held:hold(service)
    work=asset(service);service._admit_public_asset(work)
    assert repo.rows[REGISTRY].data['active'][work.work_id]['kind']=='public_asset'
    service._checkpoint_public_asset(work)
    for method in [service.admit,service.checkpoint,service.release,service._admit_control,service._checkpoint_control,service._release_control]:
        with pytest.raises(AdmissionHeld):method(work)
    assert service._release_public_asset(work) and not repo.rows[REGISTRY].data['active']


def test_assets_can_overlap_with_control_but_never_get_drain_exclusion():
    from proofpack.evidence.privacy_admission import _bind_control
    service,repo,runtime,clock=world();work=asset(service);service._admit_public_asset(work)
    own=service._prepare_control(work_id=ident(41),lease_ms=500);service._admit_control(own);hold(service)
    with _bind_control(service,own):
        with pytest.raises(AdmissionHeld):service.drained(request_id=ident(90),scope_sha256='b'*64)
        service._release_public_asset(work)
        service.assert_drained(service.drained(request_id=ident(90),scope_sha256='b'*64))
    service._release_control(own)


def test_expired_asset_is_never_removed_by_lease_or_capacity_pressure():
    service,repo,runtime,clock=world(capacity=1);work=asset(service);service._admit_public_asset(work)
    clock.value=work.expires_at_ms
    with pytest.raises(AdmissionHeld):service._checkpoint_public_asset(work)
    with pytest.raises(AdmissionHeld):service._admit_public_asset(asset(service,32))
    assert set(repo.rows[REGISTRY].data['active'])=={work.work_id}
    assert service._release_public_asset(work)


@pytest.mark.parametrize('change',['epoch','runtime','clock','intent'])
def test_original_asset_fencing_and_exact_actual_release(change):
    from proofpack.evidence.privacy_admission import GATE
    service,repo,runtime,clock=world();work=asset(service);service._admit_public_asset(work)
    if change=='clock':clock.value-=1
    elif change=='intent':work=replace(work,expires_at_ms=work.expires_at_ms+1)
    elif change=='runtime':runtime.instance_id=ident(2)
    else:
        for key in [GATE,REGISTRY]:
            row=repo.rows[key];name='epoch' if key==GATE else 'gate_epoch';repo.rows[key]=replace(row,revision=row.revision+1,data={**row.data,name:2})
    with pytest.raises(AdmissionHeld):service._checkpoint_public_asset(work)


def test_unknown_asset_admission_and_release_reconcile_exact_original():
    service,repo,runtime,clock=world();work=asset(service);repo.lose_reply=True
    assert service._admit_public_asset(work)==work
    before=deepcopy(repo.rows);assert service._admit_public_asset(work)==work and repo.rows==before
    repo.lose_reply=True;assert service._release_public_asset(work) is False
    assert not repo.rows[REGISTRY].data['active']
