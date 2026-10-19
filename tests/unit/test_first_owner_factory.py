"""Configured factory wiring with original no-SDK model admission fixture."""
from dataclasses import replace

from test_host import host_files
from test_admission_factory_wiring import factory_model, build, prohibit_sdk
from proofpack.auth.owner_setup import OwnerSetupSignIn


def close(app):
    app.state.reference_service.close()
    app.state.reference_service.registry.close()


def test_configured_factory_has_no_setup_without_paired_owner_approval(factory_model):
    app=build(factory_model)
    try:
        assert app.state.owner_setup_service is None
        assert not factory_model[2].rows and not factory_model[3]
    finally:close(app)


def test_configured_factory_shares_fixed_owner_setup_dependencies_without_io(factory_model):
    settings,clients,repo,closed=factory_model
    config=replace(settings,auth=replace(settings.auth,initial_owner_subject='approved-owner',bootstrap_receipt_sha256='a'*64))
    app=build((config,clients,repo,closed))
    try:
        setup=app.state.owner_setup_service
        assert type(setup) is OwnerSetupSignIn
        assert setup.ordinary is app.state.signin_service
        assert setup.access is app.state.access_service
        assert setup.flows.repository is setup.access.repository is repo
        assert setup.flows.config.redirect_uri==settings.app_origin+'/api/v1/auth/callback'
        assert setup.flows.config.private_key!=settings.oauth.private_key
        assert setup.provider.tokens is app.state.signin_service.provider.tokens
        assert not repo.rows and not closed
    finally:close(app)
