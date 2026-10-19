"""Explicit configured first-owner sign-in; never ordinary signup or role input."""
from dataclasses import replace
import hashlib
import hmac
import json
import re

from proofpack.auth.cognito import CognitoProvider
from proofpack.auth.oauth import OAuthFlows
from proofpack.auth.policy import Denied
from proofpack.auth.service import AccessService, BootstrapApproval
from proofpack.auth.signin import SignInService


class OwnerSetupSignIn:
    def __init__(self, ordinary: SignInService):
        if (type(ordinary) is not SignInService or type(ordinary.flows) is not OAuthFlows
                or type(ordinary.provider) is not CognitoProvider or type(ordinary.access) is not AccessService):
            raise ValueError('configured provider sign-in required for owner setup')
        access = ordinary.access
        subject, receipt = access.config.initial_owner_subject, access.config.bootstrap_receipt_sha256
        if (type(subject) is not str or not 1 <= len(subject) <= 256
                or any(ord(c) < 33 for c in subject) or type(receipt) is not str
                or re.fullmatch('[a-f0-9]{64}', receipt) is None):
            raise ValueError('explicit initial owner and approval reference required')
        # No extra row fields or quota bucket: only the private flow realm changes.
        message = json.dumps(['proofpack-owner-setup/v1', access.config.deployment,
            access.config.issuer, subject, receipt], separators=(',', ':')).encode()
        key = hmac.new(ordinary.flows.config.private_key, message, hashlib.sha256).digest()
        config = replace(ordinary.flows.config, private_key=key)
        flows = OAuthFlows(ordinary.flows.repository, config, clock_ms=ordinary.flows.clock_ms)
        provider = CognitoProvider(config, ordinary.provider.tokens, transport=ordinary.provider.transport)
        # Reuse ordinary dependency compatibility validation, without doing I/O.
        SignInService(flows, provider, access)
        if flows.repository is not access.repository:
            raise ValueError('owner setup must share the exact access repository')
        self.ordinary, self.flows, self.provider, self.access = ordinary, flows, provider, access
        self._approval = BootstrapApproval(access.config.issuer, subject, receipt)
        self._pinned = self._dependencies()

    def _dependencies(self):
        normal = self.ordinary
        return (normal, normal.flows, normal.provider, normal.access, normal.flows.config,
            normal.flows.repository, normal.flows.clock_ms, normal.provider.oauth,
            normal.provider.tokens, normal.provider.tokens.config, normal.provider.tokens.clock_ms,
            normal.provider.transport, normal.access.config, normal.access.repository, normal.access.clock_ms,
            self.flows, self.flows.config, self.flows.repository, self.flows.clock_ms,
            self.provider, self.provider.oauth, self.provider.tokens, self.provider.transport, self.access,
            self._approval)

    def _check(self):
        current = self._dependencies()
        if any(actual is not expected for actual, expected in zip(current, self._pinned)):
            raise Denied('owner setup configuration changed; start again')

    def begin(self):
        self._check()
        result = self.flows.begin(require_mfa=True)
        self._check()
        return result

    def complete(self, *, state: str, browser_cookie: str, code: str | None = None,
                 provider_error: str | None = None):
        self._check()
        binding = self.flows._configuration_binding()
        material = self.flows.consume(state=state, browser_cookie=browser_cookie)
        if provider_error is not None or code is None:
            raise Denied('provider sign-in failed; start again')
        if material.require_mfa is not True or material.invitation_id is not None:
            raise Denied('dedicated owner setup with verified MFA required')
        previous = self.access.now()
        proof = self.provider.exchange(code, material)
        self._check()
        # AccessService rechecks this shortened proof immediately before its
        # atomic bootstrap transaction, including time spent reading the store.
        proof = replace(proof, expires_at_ms=min(proof.expires_at_ms, material.expires_at_ms,
            proof.auth_time_ms + self.flows.config.mfa_max_age_seconds * 1000 + 1))

        def validate():
            nonlocal previous
            self._check()
            self.flows._check_binding(binding)
            current = self.access.now()
            if current < previous or current >= material.expires_at_ms:
                raise Denied('owner setup expired; start again')
            previous = current
            self.access._identity(proof, mfa=True)
            if (proof.issuer != self._approval.issuer or proof.subject != self._approval.subject):
                raise Denied('configured initial owner identity required')
            self._check()

        validate()
        # No automatic effect retry after an uncertain reply. A new verified flow
        # can reconcile AccessService's original immutable bootstrap result.
        self.access.bootstrap(self._approval, proof, before_commit=validate)
        validate()
        credential = self.access.login(proof)
        validate()
        return credential
