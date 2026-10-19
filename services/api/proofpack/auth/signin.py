"""One-use OAuth completion to durable membership session.

This service is not an HTTP endpoint or bootstrap route. Only verified provider
proofs reach AccessService; neither claims nor application roles come from a
callback body. A failed/ambiguous completion always requires a fresh flow.
"""
from proofpack.auth.policy import Denied


class SignInService:
    def __init__(self, flows, provider, access):
        if (flows.config != provider.oauth
                or flows.config.deployment != access.config.deployment
                or provider.tokens.config.issuer != access.config.issuer
                or flows.config.native_totp_acr != provider.tokens.config.native_totp_acr
                or flows.config.mfa_max_age_seconds > access.config.mfa_grant_max_age_seconds):
            raise ValueError('sign-in dependencies must share fixed deployment/provider configuration')
        self.flows = flows
        self.provider = provider
        self.access = access

    def complete(self, *, state: str, browser_cookie: str, code: str | None = None,
                 provider_error: str | None = None):
        material = self.flows.consume(state=state, browser_cookie=browser_cookie)
        if provider_error is not None or code is None:
            raise Denied('provider sign-in failed; start again')
        proof = self.provider.exchange(code, material)
        if self.access.now() >= material.expires_at_ms:
            raise Denied('provider sign-in expired; start again')
        if material.require_mfa and (not proof.mfa_verified
                or not 0 <= self.access.now() - proof.auth_time_ms <= self.flows.config.mfa_max_age_seconds * 1000):
            raise Denied('recent verified MFA required; start again')
        return self.access.login(proof, invitation_id=material.invitation_id)
