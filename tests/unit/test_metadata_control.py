"""Modeled registry/control protocol; not HTTP or provider authentication proof."""
import pytest
from test_owner_metadata import world as owner_world,no_sdk
from proofpack.evidence.owner_metadata import OwnerMetadataRequests


def test_factory_validated_access_clock_is_an_exact_supported_owner_clock():
    old,actor,repo,clock,owner,_=owner_world()
    old.admission.clock_ms=old.access.now
    service=OwnerMetadataRequests(old.access,old.admission,owner,limits=old.limits,tick_ns=old.tick_ns)
    assert service.context(actor)['gate_phase']=='OPEN' and owner.wait_for_drain(0)
