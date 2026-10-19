# Security, privacy and data lifecycle requirements

Threat model scope: invited users of one business, ordinary desktops, application/API, AWS stores, optional model and build chain. Product records may reveal supplier SKUs and work practices; use opaque kit IDs, crop workspace and exclude faces/shipping labels. No employee surveillance, productivity ranking or recording of unrelated activity.

## Trust boundaries and required tests

Current shared-writer provenance: event/idempotency `resource_bindings` contain bounded typed references, versions and digests, not copies of business payloads. They remain private, inherit the parent records' retention/purpose obligations and must themselves be included in complete cleanup discovery. The strengthened delivered-archive test proves a bound event exists and is exported while its private binding envelope is omitted; both native and installed checks pass at the BUILD-STATUS subject. SHA digests/opaque identifiers are not anonymization or deletion authority. Shared `_record` writes now link atomically, but direct writers, consumers/legacy reconciliation, denial barrier, cleanup/restore lifecycle and actual-store acceptance remain incomplete.

Current storage prerequisite: `DynamoRepository` can replace an exact live revision's payload with an empty map and a minimal top-level erasure marker. Marker validation, ordinary-read withholding and conditional resurrection denial have selected local evidence in BUILD-STATUS. This is neither a provider deletion policy nor a complete cleanup workflow. Privileged raw writes, old incompatible writers and restored pre-erasure backups need an independent replay/compatibility gate before exposure. Complete scoped discovery, coordinated read/write/worker denial, leased processing, object authority preservation, requester communication and actual-store acceptance remain unfinished. No new deletion endpoint or legal-erasure claim follows from the adapter.

| Threat | Control to implement | Proof |
|---|---|---|
| Uninvited or disabled account accesses evidence | Server membership/role checks on every route and download; short session lifetime/revocation | T20; E09 |
| Operator approves recipe or forged org/resource ID | Server-derived deployment scope and operation-specific RBAC | T20 |
| Cookie theft/CSRF/XSS | HttpOnly Secure cookies; Origin/CSRF; CSP; escaping; no raw HTML from labels/model | T20–T21 |
| Replay, stale result, concurrent tabs | One-time permits, version checks, station fencing, lease-derived status | T11–T14 |
| Prompt injection on printed labels/tool data | Allowlist, schema validation and no state-changing model tools | T10 |
| Oversized/malformed image or decoder issue | Byte/pixel/type limits, restricted worker and memory/time/concurrency budgets | T21 |
| Arbitrary URL, path or object key | No remote image-fetch endpoint; server-generated keys and validated IDs | T21 |
| Sensitive records in logs/model | Redaction tests; numeric model inputs; role-filtered exports | T22 |
| Evidence modified or missing | Version/hash manifests, write restrictions, missing-object reconciliation | T16 |
| Loss of data/failed deletion | Restore test, deletion jobs, version cleanup and tombstone replay | T23; T28 |
| Dependency or credential exposure | Pinned artifacts, SBOM, secret/dependency scans, scoped IAM role | T26 |

No browser technique establishes adversarial camera authenticity. Do not claim anti-fraud protection or physical interlocking. A printout or injected video can fool visual measurements; include a spoof-limit disclosure and a test showing protocol replay rejection without claiming to solve pixel spoofing.

## Roles and consent

The [workflow coverage map](WORKFLOW-COVERAGE.md) and T31–T58 specify account/owner recovery, commit-time revocation, private download denial, purpose withdrawal, bounded jobs/inference and stop/resume. Those are required controls, not executed findings. No public/anonymous owner bootstrap is permitted; owner role changes and last-owner transfer are guarded, MFA-qualified and audited.

Owner manages users/configuration and release. Operator captures and records disposition. Reviewer labels/evaluates. Any approval by the same person who built/labeled a case is marked non-independent. Permissions to operate, retain evidence, use data for improvement, and publish demo media are separate. Improvement/publicity permissions default off. Store consent/version references without exposing personal contact details in exported benchmarks.

## Proposed retention defaults

See [controls](controls.yaml). Transient inspection frames remain in memory <=10 seconds and are not logged; selected inspection frames 7 days; inspection metadata 30 days; authenticated export tickets <=60 seconds. These are proposed defaults awaiting owner acceptance. Active identity/configuration records and reference/evaluation assets have explicit separately agreed purposes and retention; they do not inherit indefinite life or the inspection-frame deadline silently. Missing/expired required references invalidate dependent qualification. Withdrawal denies future optional use and affected export/replay/promotion inputs; disclose limits on existing downloaded copies or derived artifacts rather than promising automatic remote erasure or model unlearning.

Delete workflow: authorize and identify the exact subject/inspection/assets; immediately deny further reads; enqueue a durable deletion job; remove source/derivative/export objects including versions and remove/redact dependent labels; preserve only minimal non-identifying tombstones; report completion/errors. Target live deletion within 24 hours; backups expire within 35 days and are inaccessible for routine processing. Restores must reapply deletion tombstones before any access is enabled. Explain backup delay honestly in onboarding.

No S3 Object Lock in beta unless its retention semantics are explicitly reconciled with deletion commitments. Application append-only history does not override user data rights or deletion policy. Logs must not contain raw frames, cookies, tokens, presigned URLs or free-text personal data. Automated redaction tests must inspect real outputs.

## AI Red Team evaluation

The `ai-red-team` skill informs the evaluation scope below. Full application Red Team probe status: **NOT_RUN**; [build status](BUILD-STATUS.md) records separate local component tests during implementation. The controls remain acceptance requirements; no full runtime vulnerability finding is closed by this documentation review.

Run adversarial evaluation only on an authorized sandbox after the application exists. Keep side effects simulated, use test identities and synthetic assets, and set explicit request/time/token/cost caps before sending probes. Abort on an unauthorized proposed action, disclosure, uncontrolled budget use or unexpected effect. Store sanitized probe/correlation IDs and assertions, not secrets or sensitive extracted text.

| Attack surface | Required assertion | Test/evidence |
|---|---|---|
| Direct/indirect injection, jailbreak or prompt-extraction attempts in images, findings or optional model output | No new tool, instruction, recipe change or verifier pass authority; numeric-only input excludes label text, and raw model text is never displayed/exported | T10; E04/E09 |
| Multi-step tool misuse and role impersonation | Selection, acknowledgment and reinspection remain bound to the authorized user, station, scene and action | T09/T10/T12/T20; E05/E09 |
| Memory or label poisoning | Unreviewed outcomes cannot update the active policy; contaminated test data cannot pass promotion | T17/T19; E08/E09 |
| Evidence/credential extraction | Wrong-role/disabled users and forged IDs cannot obtain assets, tokens or unrestricted exports | T20/T22; E09 |
| Runaway retries or cost | Retry/reload cannot reset correction budgets; bounded failures escalate without additional model calls | T09/T21/T25; E04/E09/E14 |
| Fabricated measurements or persuasive approval requests | Unsupported findings remain unobservable; human disposition never becomes a machine pass | T06/T10/T15; E05/E09 |

Use multi-turn trajectories and adaptive variations of failed cases; a static single-shot corpus is insufficient. Test the deterministic mode and any enabled model mode separately, recording the actual policy/model/build. Single-agent topology has no inter-agent channel, and this release has no RAG or cross-business retrieval; reopen coverage if those surfaces are introduced. The oracle must assert the protected state/data/action boundary, rather than treating an HTTP error or refusal sentence as success.

Each actual finding needs severity, sanitized reproduction ID, failed control, affected revision, remediation owner and candidate-bound retest. A critical finding blocks release. Re-run relevant probes after changes to models, prompts, tool schemas, memory, permissions or verifier behavior. Preserve unresolved findings in E09 instead of overwriting them with a passing summary.

## Release security acceptance

No unresolved critical/high exploitable issue; all auth/role/object-boundary negative tests pass; known pass-state defects are zero; uploaded-content limits observed at runtime; unauthorized public access denied; secrets absent from repo/artifacts/logs; deletion and restore verified on the deployed target. Accepted lower risks require a written owner rationale and scope/expiry, never silent suppression of scanner findings.

Access credentials are a deployment input and will not be requested in chat. Use the host's approved AWS authentication path when deployment is authorized. No credentials were read or created during planning.


## Reference intake implementation boundary

Owner/MFA reference intake now has operational-use attestation records with exact notice/version, explicit expiry and optional purposes off, plus a bounded multipart parser, shared resource-limited decoder and private encrypted/checksummed object intent/linking path. Declared physical origin is recorded as an owner declaration with physical-truth verification false; it does not certify consent, rights, specimens or calibration. Every new intake consumes a configured allowance, shares the at-most-two-process pool and checks current grants/purpose/data/runtime before publication. No remote URL/path/key input is accepted.

The child rejects unsupported orientation/multiple frames/type/pixel bounds and emits a metadata-free JPEG. Input and stored hashes stay separate; image bytes/base64 never enter DynamoDB. Local SDK interception exercises conditional PUT/version/HEAD/encryption/checksum semantics; no live AWS policy/durability conclusion follows. Unknown writes keep private reconciliation intents and do not publish assets or passes. Original pending/failed retries do not reprocess. Cancellation holds intake capacity until actual owned work ends. Purpose withdrawal synchronously advances data authority and denies future dependency use; deletion/backup/downloaded-copy duties remain separate unfinished work.

Content Security Policy allows `'self'` and `blob:` only for images so an explicit local selected-file preview can load. Default/script/connect restrictions remain same-origin; objects, embedding and base overrides stay denied. A browser regression reproduced the original blocked blob preview; its traces are retained. The preview is local source imagery, not proof that stored bytes or physical truth were independently inspected. Object URLs are revoked on selection change/unmount, and the page never opens a camera for reference intake. Reference storage has a separate owned prefix so its retention cannot silently inherit the inspection-frame rule; actual IAM/lifecycle/cleanup verification remains required before deployment.


## Selected-asset deletion boundary

The local erasure service admits only current owner/MFA, reviewed distinct asset UUIDs, exact current source revisions/receipts, original storage binding and data authority. Final transaction checks revalidate current access and review expiry before atomically denying reads, writing opaque asset tombstones, consuming the preview and reserving a durable job/idempotency/audit record. Source/config changes or missing legacy storage provenance cannot redirect cleanup.

One leased step lists one exact owned key with bounded results and expected bucket owner; every delete names an explicit listed version, including markers and legacy null versions. Foreign/malformed outcomes stop confirmation of absence. Old/expired/superseded leases cannot publish progress; ambiguous effects remain denied and resumable. Owner workbench responses are schema/digest/scope checked, approvals expire from request start and hidden/offline transitions, and uncertain requests retain original intent. UI role hiding supplements server authorization.

Local coverage is in TEST-PLAN. Selected live-version absence is a point-in-time observation, not full erasure: dependent metadata and labels, exports/orphans, backups/restored data and downloaded copies remain outstanding. Subject-wide discovery, complete privacy-request fulfillment and actual AWS/restore validation remain open. No legal compliance, real consent or production data deletion is certified by local checks.


## Inspection export authority and integrity

Support-history addition: every included request also needs its existing sender-role/designated-reviewer/originating-operator detail scope. Generic reviewer export access grants no broader support permission. Validate exact retained sources, complete count/latest/predecessor/accepted/supersession pointers and request/decision write events. Bind saved sanitized copies back to actual source projections, not merely mutually matching job/manifest hashes. Conditional-check mutable support rows through progress/ticket/delivery; shorten validity to the earliest included metadata expiry. Export only pseudonymous historical context and outcome/digests, excluding cookie/session/access-version/inbox internals and current-eligibility claims. Acceptance remains distinct from capture, kit approval and independent truth.

Cleanup inventory now includes main `inspection-handoff#` records, recipient `handoff-inbox#` references, their copied fields in export `maintenance-job#` and `export-manifest#` records, tickets, audit/idempotency links and any permitted downloaded copies. These require the complete scoped metadata/retention/offboarding/restore workflow; a local export pass or logical expiry is not erasure. Actual fulfillment, owner acceptance and hosted privacy proof remain open.

Creation and binary delivery require an explicit reviewer grant or originating operator scope, plus requestor identity; owner-only status/cancellation does not broaden media access. Every selected frame uses the existing binary purpose/receipt/retention checks. Job leases, source/root/data/runtime fences, nonrefundable scan reservations, immutable references and final conditional ready audit mediate preparation and output. Operational notice, capability key, object/read/export settings and build/environment bind compatibility.

Prepared manifests require terminal observation lineage, matching completion events, intact human content hashes/correction chains and matching canonical manifest bytes. Unknown input remains unavailable. Sanitized exports omit cookie/provider/session capabilities, internal object keys and actor scopes; source record digests may refer to non-exported private fields and are not capture authentication. Server-generated UUID entry names prevent client-selected archive paths. Headers and browser bounded streamed-byte/SHA checks precede the local save link. Rejected/abandoned fetches are aborted; local capabilities/blob URLs clear on expiry/hidden/offline/navigation/forget. No local-storage or URL capability is used.

Tickets are current-session bound, expire within 60 seconds, are consumed before archive construction and cannot silently repeat a binary fetch. New tickets require current authorization and explicit scope acknowledgment. Revocation/cancellation/withdrawal/expiry/corruption blocks new output; delivered copies cannot be recalled. In-memory ZIP assembly avoids extra S3 output copies, but manifests, jobs, tickets, audits and idempotency metadata still need real retention/deletion/restore treatment. No legal compliance or hosted privacy assurance is established by these local checks.


Maintenance dispatch references are private job data, not bearer credentials. The server HMAC binds the original hashed cookie-row locator, session/user/access/session-epoch/role/time and exact immutable job scope. Resolve through current access state; no principal may be created from a requestor ID. Missing legacy references require an explicit authorized manual rebind; idempotent readback cannot renew one. Owner MFA remains bounded, revoked/export-changed scope remains held, and executors still enforce current purposes/runtime/leases/budgets. Do not expose references in job JSON, archive, audit details or diagnostics. Include these private session locators in the still-required metadata retention/redaction lifecycle. The separate driver now composes this prerequisite for bounded export/selected cleanup; full erasure remains unfinished.


Configured maintenance cleanup has one resource owner. Stop checkpoints prohibit subsequent logical phases after observed stop/runtime replacement; an already admitted bounded phase may finish. Drain timeout is a failed shutdown, with resources deferred until processing exits rather than closed beneath the active step. Current local barrier/runtime/cancel/authority tests cover these boundaries; real-host/SDK shutdown/restore and full privacy retention still require evidence. Read-only owner diagnostics exclude job IDs, locators, signatures and raw exceptions.


Optional improvement use has separate scoped owner-attested grants, not a mutation of operational permission or label truth. A recent-MFA owner reviews exact current source hashes/versions and the separately configured notice, provides a documented authorization reference and two acknowledgments, and confirms an expiry no later than source/operational retention. A grant advances DATA, invalidating previous dependent receipts/current results until revalidated. Reviewer-only internal authorization requires exact current head/scope/notice/expiry and no denial/withdrawal; it grants no new media endpoint or policy activation. Every source remains required, with no operation-only fallback. Any current authorized owner can withdraw after source deletion/expiry; received copies are not recalled. Retain the original notice and immutable grant hash; notices do not independently prove rights, physical truth, observer independence or publicity. Complete grant/head/preview/audit/idempotency/backup retention and actual data-rights handling remain required.


Dataset preparation is original-reviewer-scoped and leased, with current DATA/runtime/label/grant conditions and nonrefundable attempts. It validates all sources and explicit derived-review-metadata rights before writing immutable examples; image-only or legacy grants are not upgraded. Label counts/outcome/method/duration may appear in permitted examples, but free-form notes/reviewer identity/media locations do not. Hashed kit/session/operator group assignments prevent cross-manifest split conflicts without publishing raw grouping identities. DATA changes, retirement and owner declassification hold old receipts; known development groups cannot be upgraded to stronger test splits.

Dataset request/example deliveries record authorized actor, range and bindings before output; these logs do not prove absence of earlier access through label/media channels. All manifests/requests/examples/group assignments/catalog/maintenance/access/declassification/idempotency records extend the required privacy inventory. Failed/cancelled preparation can leave conservative group assignments and partial immutable metadata; no cleanup/untouched guarantee is claimed. Full source/derivative/backup/restore retention and actual privacy/independent holdout proof remain unfinished.

Policy candidates add source-free metadata records policy-candidate, policy-revision, policy-catalog, durable stable-identity allowance/idempotency records and minimized policy-read/access events in existing state/events tables. Revisions retain creator, build/config/environment identity, timestamp, strict name/order and lineage hashes. They contain no pixels, capabilities, arbitrary code/URLs, source permissions or truth certification. Owner/reviewer metadata rights do not grant image access or activation; owner-only reads require recent MFA. Include these records in the already-open metadata retention/erasure/backup inventory; an immutable local record is not a retention exemption or full privacy-fulfillment receipt.

Historical comparisons add maintenance jobs with private signed original-reviewer authority, immutable requests/result entries/reports, evaluation catalog/quota/idempotency and evaluation-access records. Requests bind candidate and manifest IDs/revisions/hashes; derived examples retain permitted label references, counts/classifications, split/origin, reasons and declared method/duration, without free-form notes, raw staff/session group identity, media locations or pixels. Reviewer example delivery also records dataset-access with the trusted consumer evaluation ID; admission can remain logged when a final authority/expiry fence withholds output. Owner-only aggregate review is explicitly minimized and depends on valid originating processing authority and current sources, without granting reviewer examples or actions.

All these derived records, private authority locators and failed/canceled partial rows belong in the open source/derivative/metadata/backup retention and restore inventory. Retirement retains history and advances DATA; it is not erasure or recall of delivered copies. Runtime replacement holds the old evaluation and does not renew inputs, permission or budget. Local authority checks do not establish actual consent, lawful source rights, independent truth, employee agreement or a complete privacy fulfillment process. Those evidence and lifecycle duties remain required before external use.
