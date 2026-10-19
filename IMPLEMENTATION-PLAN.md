# Detailed implementation plan

Planning baseline: October 13, 2026. Build is in progress; [implementation status](docs/BUILD-STATUS.md) records actual component coverage and remaining work. The complete first release contains all five features; phases sequence delivery rather than reduce the product direction. [Backlog](BACKLOG.md) identifies dependencies, tests and evidence; [PRD](PRD.md) owns requirement traceability.

## Milestones and acceptance

| Milestone | Target window | Work | Exit evidence |
|---|---|---|---|
| M0 — reproducible foundation | Oct 13–14 | Lock stack, initialize modules/CI, prove OpenCV 5, generate tagged synthetic/printable fixtures | Local build/runtime manifest; no product claims |
| M1 — deterministic inspection | Oct 14–17 | Recipe/calibration, geometry/quality, state machine and atomic freshness | F1/F2/F4 component tests; synthetic end-to-end finding |
| M2 — complete workflow | Oct 17–20 | Auth, operator UI, bounded actions, durable evidence and outcome workbench | F1–F5 fixture journeys and failure tests |
| M3 — authorized AWS proof | Oct 19–22, authority-dependent | Costed infrastructure, real auth/storage, deployed runtime and integration tests | Same-request desktop-to-AWS OpenCV trace |
| M4 — qualification/evaluation | Oct 21–24, access-dependent | Physical specimens, independent operators, strong baselines, security/UX/recovery | Honest datasets/results and beta gate evidence |
| M5 — submission candidate | Oct 24–25 | Report, diagram, clean judge setup and video; access check | Complete package and actual receipt after explicit submission authority |
| M6 — supervised beta | After all B01–B09 pass | Owner-targeted launch decision and authorized invitations | Beta launch receipt; no fixed date promised |

Dates are a best-case sequence, not a guarantee. One developer with AI assistance is the planning assumption. The backlog totals 124–194 focused hours, including 2–4 optional COOL hours, plus external waiting and pilot access; estimates are not commitments. The expanded lifecycle/test scope is included. Date windows must be replanned against actual availability at PP01; do not promise the full release by the contest deadline. If time/access is insufficient, drop optional COOL/model work first and disclose a controlled demonstration. Never weaken verification or call the demonstration beta-ready to meet the deadline.

## Critical path

PP01 -> PP02/PP04 -> PP05 -> PP06 -> PP07/PP08 -> PP09/PP10 -> PP11; auth PP03 feeds the integrated surfaces. AWS PP12 -> PP13 depends on account/region/budget/domain authority and the stable application. Beta additionally requires PP14/PP15/PP18, actual physical evidence and assigned operations. COOL PP16 is optional and cannot block overall/agentic delivery.

## Build order within the five features

### F1: recipe/calibration

Implement schema/repository first, then immutable revisions and qualification linkage, then owner UI. Use three demonstration recipes over four broad classes, not an arbitrary catalog. Qualification distinguishes synthetic from physical evidence. Add approval/revision race tests before enabling activation.

### F2: measurement

Prove OpenCV version/import/functions, create pure image-to-finding pipeline, establish synthetic ground truth and quality abstention, then wrap bounded decoding/worker execution. Build real-camera calibration after fixture flow is stable. Record measurement-error intervals from actual specimens rather than choosing flattering thresholds.

### F4: verifier before planner

Implement pure state transition/verifier logic with generated event-sequence tests before any agent can request actions. Add DynamoDB conditional commits, station fences and idempotency; implement lease-derived read status and conservative client expiry. Fault-inject stale writes and storage failures. Only then expose pass state in UI.

### F3: bounded actions

Start with deterministic candidate filtering/ranking and explicit action trace. Add action completion/reinspection and persisted attempt limits. An optional Bedrock adapter uses the identical contracts and is compared against the rule baseline. If the LLM offers no benefit, use the simpler policy and report its actual mode.

### F5: outcome/replay

Capture provenance and permissions from the first fixture. Add reviewed labels and group-based splits before tuning. Implement replay manifests, promotion/rollback and a separate independent validation register. Dataset quality and operator evidence determine whether a learning advantage is claimable.

## Integration sequence

PP11 completes controlled evaluation only. PP15 owns physical recipe qualification and the actual-operator pilot, and remains blocked without access. PP17 may prepare a transparently controlled hackathon submission before PP15; PP18 cannot approve beta without PP15.

Local integration uses temporary DynamoDB Local/asset-store fixtures and generated camera videos. Never embed local auth bypass into cloud configuration. A cloud-ready candidate adds Cognito BFF sessions, private S3, scoped IAM and restore/deletion jobs. CloudFormation, install scripts and release artifacts must be reviewable before target provisioning. The first live integration proves one browser request, OpenCV 5 execution and a correctly linked durable event on the same AWS target.

## Decision checkpoints

- End of PP01: If OpenCV 5 cannot be installed on ARM with required modules, fix/build upstream or narrow supported primitives; do not silently run version 4.
- End of PP05: If classes or variants cannot be separated reliably, mark them unsupported and keep the affected requirements incomplete. Any proposed change to R05 needs explicit scope review; preserve all five features.
- Before PP12 apply: choose actual AWS account/region/budget/domain and authorize the concrete change set. Compare us-east-1/us-east-2 total cost; no paid resource assumption.
- By Oct 18 target: establish a realistic route to actual specimens/operators. If absent, mark M4/B03/B04 blocked and prepare an explicitly controlled demonstration.
- Before PP16: timebox compatibility investigation to two hours; retain plain OpenCV path if it becomes a distraction. Benchmark only if real workload integration succeeds.
- Before submission: freeze candidate code/config and evidence; changes invalidate relevant claims. Actual final submission is a separate authorized external action.
- Before beta: no open core state/security blocker, physical/user validation, restore/rollback/deletion proof and owner receipt.

## Definition of done for each change

Requirement/test/evidence IDs linked; implementation uses existing patterns; reviewed diff and targeted tests pass; failure diagnostics/exit status preserved; no unrelated files changed; updated user/help docs; current source graph refreshed when one exists; claims and ledger updated against the same build/config. A missing environment is BLOCKED, not SKIPPED-to-PASS. Re-run broader tests only where changes or unresolved risks justify them.

## Agentic Product Loop artifacts

The `agentic-product-loop` skill informs delivery and evidence review. Execution status: **NOT_INITIALIZED**. Its non-mutating discovery check on October 13, 2026 returned DISCOVERY_ONLY, admission NOT_EVALUATED and init_required. The canonical reference hash matched; no STOP file was present, and no `.loop` state exists. The installed command exited 1, despite the skill describing a discovery exit of 2; neither value represents admitted execution or acceptance.

The backlog and this plan are delivery specifications. No cycle, command registry, application build, security probe or release has been executed by the loop. Its governed initialization is a separate implementation task; it is not installed during document consolidation.

During implementation, select a bounded backlog task, define its touched files and acceptance IDs, implement it, run its checks, inspect failures and record the actual result in the evidence ledger. Update the owning document when a decision changes. After measured results, review whether another change is warranted. If a governed product-loop runner is later requested, its admission/configuration/receipt must be established separately; a documentation check cannot substitute for it.

## Implementation handoff

The first admitted build slice is PP01: scaffolding, locked runtime and OpenCV proof. Local foundation/component work has started; AWS runtime has not been provisioned. Continue the full documented sequence from [build status](docs/BUILD-STATUS.md). Missing external inputs remain in [decisions](docs/DECISIONS.md); spending, publication and beta invitations require exact target/authority.
