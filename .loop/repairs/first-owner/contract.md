# First-owner setup repair contract

Mode: IMPLEMENT. Parent goal remains the complete ProofPack workflow build.

Reported before implementation: fresh metadata enrollment leaves no member, ordinary verified sign-in only calls AccessService.login, and no production caller reaches AccessService.bootstrap. P01 cannot complete first access. This is an observed source gap, not evidence of a customer incident.

Scope: existing P01/P05/P06, W02/W04/W17/W19 and T04/T23/T24/T28/T47/T54/T58. Reuse the configured exact initial_owner_subject and bootstrap_receipt_sha256; neither a browser field nor a model chooses the owner. No new persona or role. Local implementation and synthetic testing only; no AWS/provider/business mutation.

FO01: a distinct explicit first-owner OAuth start, fixed callback URI and secure browser cookie, requires native provider-verified fresh MFA and exact configured issuer/subject/approval. Ordinary sign-in cannot provision users without invitation or consume setup flows. Setup cannot consume ordinary flows, accept an invitation, client owner identity, approval override or role input.

FO02: derive a domain-separated private flow key bound to deployment, issuer, subject and approval. Reuse the existing closed OAuth row schema, generation fence, lifetime and fixed shared login/callback quota keys. Changing approval, key, issuer, deployment or generation invalidates pending flows. Constructors perform no I/O.

FO03: existing AccessService.bootstrap owns the atomic owner-only membership/head/index/audit transaction. Constrain verified proof expiry to the original flow expiry and stricter MFA deadline so its final identity check rejects a slow precommit. A late/unknown result never returns a session or automatically repeats bootstrap. A fresh flow may reconcile the exact original bootstrap; historical owner identity cannot regain revoked membership or transferred authority. No operator/reviewer privilege, consent/purpose grant, readiness or inspection enablement.

FO04: pin constructed service dependencies, validate again after provider work and before/after effects/output. Reject swapped configuration, provider, repository or access objects. Existing protected repository conditions remain mandatory. No claimed protection from an attacker controlling process memory/kernel or an untrusted deployment.

FO05: start accepts no query fields; callback rejects ambiguous cookies and never falls back between realms. Share callback admission exactly once, clear both flow cookies on completion/error, retain no-store/referrer/query-redaction defenses and fixed origin. Render explicit setup help; unavailable/unapproved setup must fail closed. Public discoverability is not access authority.

FO06: verify source and installed code, signed synthetic provider protocol, bootstrap state effects and negative cases; regress existing ordinary auth/OAuth/restore/factory behavior and check HTTP/cookie/log boundaries. Browser/human/provider/operational acceptance remains separate and NOT_RUN until actually exercised. Preserve baseline oracles/failures and finite run bounds. No force input, timeout widening or weakened assertions.

Assurance handoff: run_id first-owner; scope_id FO01-FO06; primary codex-product-build-loop; support agentic-product-assurance Change then Verify. P01-P10 applicable: fixed deterministic flow, explicit entry/recovery, configured sources, closed completion, owner-only grant, exact approval, bootstrap reconciliation, independent state assertions, full handoff and shared quotas. API graph2374 nodes was consulted with bounded truncated output and legacy IDs; verify in source, no UI/test graph coverage. Baseline and postchange subjects must be captured by the guarded runner; no invented commit.

Plan: preserve prechange sources and frozen acceptance probes; observe baseline; implement service/HTTP/factory/entry; execute original probes and affected regressions; record installed/build/journey limitations and update runbook/evidence. D11, actual approval/provider/target/IAM/quarantine and human A01-A09 remain unresolved; beta NO_GO.
