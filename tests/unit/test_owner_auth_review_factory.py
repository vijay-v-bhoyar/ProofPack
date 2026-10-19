"""Actual factory wiring on modeled store; no SDK, provider or startup proof."""
from dataclasses import replace
from test_host import host_files
from test_admission_factory_wiring import factory_model,build,prohibit_sdk
from test_owner_auth_review_host import bounds
from test_owner_review_host import configuration
from proofpack.evidence.owner_metadata import OwnerMetadataLimits


def test_factory_passes_exact_auth_group_to_shared_owner_reader(factory_model):
    settings,clients,repo,closed=factory_model
    group=bounds();review=replace(configuration(),auth_review=group)
    settings=replace(settings,owner_metadata=OwnerMetadataLimits(10,20,100,20000),owner_metadata_review=review)
    app=build((settings,clients,repo,closed))
    service=app.state.owner_metadata_review_service
    assert service.auth_review is group
    assert service.reader.admission is app.state.metadata_admission
    assert service.reader.resource_owner is app.state.resource_owner
    assert service.requests is app.state.owner_metadata_service
    assert not repo.rows and not closed
