# Decisions and unresolved dependencies

## D11 operating-policy inputs remain required

October18 follow-up: actual business purposes, retention periods and approver for packing evidence/account/sign-in records were requested asynchronously. No reply or approval has been received or inferred in this checkpoint. D11 remains OWNER_INPUT_REQUIRED; no real-data cleanup is enabled.

PO01–PO08 supplies an owner-only explanation, not a decision. For reviewed supported access control, initial-owner setup, account/identity/session references, invitation/transfer/access receipts and sign-in records, P01/P07 must specify the authorized business purpose and policy version, retention period/trigger, applicable requester relationship/rights, permitted conditional action/collateral scope and actual approver. Explain why any context is retained; do not infer ownership or permission from counts, expiry or schema validity. Shared content, external copies and preservation/restore duties remain obligations. Optional improvement/publication permissions remain separate and off absent actual permission.

No actual D11 values/approvers were supplied or accepted by implementing the screen. Zero categories cannot close the decision, and a structural history review is not historical identity attestation. Existing proposed defaults elsewhere remain proposals, not consent or safe cleanup policy. Real collection/cleanup/fulfillment stays held pending actual decisions and complete implementation/evidence. D07 paid/target authority and D08/D09 actual kit/operator access remain unresolved. [Implemented explanation](STATE-DATA-API.md#owner-explanation-of-unresolved-authentication-policy--po01po08).

Updated October 13, 2026. Confirmed user replies supersede earlier pilot-access assumptions.

| ID | Decision | State | Consequence |
|---|---|---|---|
| D01 | One business, invited operators, desktop webcam first | CONFIRMED_USER | Separate installation/data/identity; no public multi-tenant UI |
| D02 | User has AWS account; US East or cheapest suitable region preferred | CONFIRMED_USER | Provisional us-east-1; compare us-east-2 total cost/availability |
| D03 | No access to hardware kits or packing operators | CONFIRMED_USER | Use labeled synthetic/printable fixtures locally; block physical/beta claims |
| D04 | All five features; Overall/Agentic priority; COOL optional | DESIGN_ACCEPTED_FOR_PLANNING | Preserve scope; no robot/platform expansion |
| D05 | Modular monolith; bounded planner; deterministic verifier | PROPOSED | Limits complexity and separates authority |
| D06 | EC2 Graviton, DynamoDB, S3, Cognito BFF, ALB/ACM | PROPOSED | Confirm actual cost/quota/AMI/license before provisioning |
| D07 | Account ID, region selection, spend ceiling, domain and change-set authority | OWNER_INPUT_REQUIRED | Blocks paid deployment; does not block local build |
| D08 | Actual kit specimen and camera access/qualification | EXTERNAL_DEPENDENCY | Blocks physical validation; substitutes must be disclosed |
| D09 | Two actual packing operators and permitted pilot data | EXTERNAL_DEPENDENCY | Blocks B04; no invented customer/partner |
| D10 | Release/support owner and supervised support hours | OWNER_INPUT_REQUIRED | Blocks beta invitations |
| D11 | Retention, improvement-data/publication permissions | OWNER_INPUT_REQUIRED | Proposed defaults documented; actual consent before collection |
| D12 | Optional Bedrock model, region, price and terms | NOT_SELECTED | Deterministic planner remains baseline; no model account/credentials assumed |
| D13 | Contest age/team/geographic eligibility and any reused-work policy | CHECK_BEFORE_SUBMISSION | Participant facts unknown; organizer clarifications only when applicable |
| D14 | Runtime/vision/freshness, worker/job record/time/resource/lease bounds and quota configuration | PROPOSED_NOT_VALIDATED | Validate on the actual target; required missing bounds deny admission; cannot widen silently |

D11 includes separately agreed identity/configuration/reference/evaluation purposes and retention, not only inspection defaults. D12 also requires an approved deployment inference request/token allowance, expiry and cost basis before any paid call; those fields are unset in controls. No budget or hardware validation is fabricated by completing the coverage map.

## ADRs

ADR-01: qualify one business per deployment. This removes shared-tenant UI complexity while preserving object-level authorization and environment isolation.

ADR-02: short-lived observation results rather than permanent shipping approvals. Any future warehouse/shipping integration is a separate safety/authority decision.

ADR-03: choose classic controlled-scene OpenCV first; model-based perception only if measured failure justifies it. No unverified "any part" promise.

ADR-04: use DynamoDB conditional transactions for current state; keep S3 bytes outside. Avoid event sourcing infrastructure beyond a bounded durable event trail.

ADR-05: optional LLM action selection must use the same schema and safe fallback. Model access is not an agentic claim or moat by itself.

ADR-06: no cross-customer learning, online autonomous policy tuning or certification claims. Capture permissions and lineage now; evaluate any broader use later.

## Risk register

| Risk | Mitigation | Owner role | Trigger |
|---|---|---|---|
| No physical/user access before deadline | Controlled demo with explicit limitations; beta remains no-go | Product owner | Access unavailable at M4 |
| Perception fails on similar reflective parts | Restrict qualified catalog/envelope; abstain | Vision implementer | False pass or unstable measurement |
| Stale approval race | Fence/version/lease invariants and concurrency tests | Backend implementer | Any R09/R10 violation |
| Cost exceeds expectations | Total-cost estimate, quotas, schedule and alerts | AWS owner | Budget headroom low |
| Claim exceeds evidence | Trace every claim to same revision/context | Release reviewer | Synthetic/local proof presented as live/physical |
| Pilot creates worker surveillance | Crop, purpose limitation, no employee scoring | Data owner | New data purpose proposed |

No names, approvals, contacts or partner commitments are fabricated. Open items have a gate and owner role so they do not silently become assumptions.

Reference intake requires explicit `max_lifetime_ms` and `max_uploads_per_minute` configuration. Local test values are synthetic configuration, not accepted product defaults. D11/D14 must resolve the real lifetime/allowance and D07 the actual storage target/authority before a deployment factory enables intake. Reference and inspection-frame namespaces require separate verified retention/IAM policy; prefix separation alone is not policy evidence.

## Calibration configuration and physical authority follow-up

D11 remains unresolved for actual collection: local operational-purpose attestations do not establish rights, consent or independently verified physical reference truth. D14 requires explicit calibration `max_runs_per_minute` and `max_diagnostic_ms` configuration; local test values are not approved production defaults or physical tolerances. The authorized physical-assurance creation/import process, named qualified reviewer and real print/ruler/lens/source evidence remain unassigned prerequisites. No client declaration or synthetic fixture can close those decisions.

## Operational review limits and evidence authority

D14 now also requires explicit `writes_per_minute`, `max_duration_ms` and `review_validity_ms` for operational labels. Constructor limits are at most 100 writes/minute per stable reviewer identity, one-hour declared duration and 60-second source-review window; test configuration (8/60000/30000) is development evidence, not approved operational defaults. Actual review burden, privacy-retention/cleanup, staffing and acceptable configured limits remain unvalidated. D11's operational purpose does not grant optional improvement/publicity reuse. P03/P08 must establish independent physical truth and disclose conflicts; app declarations cannot replace that process.

## Retained-evidence limits and delivery evidence

D14 now requires `evidence_reads_per_minute`, `evidence_max_concurrent`, `evidence_read_window_ms` explicitly; maximums are 120/identity/minute, two concurrent requests and a 5000 ms acceptance window, with 2 MiB maximum bodies. There is no silent private-config migration. D11's current operational purpose/notice is rechecked for each new read; metadata alone is not permission or durability, and optional improvement/publicity remains off. Actual configuration/latency/load/privacy and recipient-copy handling remain owner/steward decisions. A source-bound ready audit is not a receipt of human delivery or understanding.

D14 also requires explicit recipe-qualification run/window bounds (at most 100 runs/minute per stable owner and a 1000–60000 ms acceptance window). No silent default is assigned to a real installation. The same shared two-worker/750 ms frame/5-second startup/512 MiB/30 CPU-second ceilings remain unchanged. D11's operational notice/version/hash and source permissions bind persisted reports and approval; a changed notice holds stale qualifications. Physical approval still needs independent assurance beyond a declared origin or matching diagnostics.


## Selected-asset erasure continuation

The next W20 implementation stage is explicit owner review and bounded cleanup of known committed assets; full subject-wide discovery and metadata/export/orphan/restore/backup duties remain in scope. No selected-asset receipt can satisfy full erasure acceptance. The private host schema now requires explicit deletion review, admission, lease and page-size bounds; owners must supply approved values before any target configuration. Existing assets without a verified original storage binding remain held for a controlled provenance/migration design; never backfill from whichever bucket is configured today. Unknown browser outcomes preserve exact request/key/version and recover via preview/job readback. This is a local implementation decision within the existing scope, not authorization to alter an AWS policy, deploy, spend or invite users.


## Inspection export delivery and remaining driver

The reviewed local implementation keeps canonical manifests in DynamoDB and constructs archives ephemerally from newly authorized pinned sources. It does not add stored S3 ZIP copies. This refines the earlier S3 resource-purpose table while preserving private image storage and all export/retention obligations. Current exporter bounds are explicit mandatory configuration, never owner-approved defaults; old/incompatible notices, keys or settings do not silently migrate a job.

The original separate same-host maintenance-worker requirement remains open. Current leased step execution and manual UI advances are intermediate support, not an alternative completion criterion. Before building its driver, define trusted originating session/grant linkage, discovery/admission and shared runtime/capacity/shutdown; do not construct authority from a requestor user ID. No real provider/deployment/spend/communication authority follows from these local decisions.
