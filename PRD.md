# Product requirements

All requirements are planned. Acceptance tests and evidence IDs resolve through the requirement traceability table below. Numerical defaults in [controls](docs/controls.yaml) are proposed engineering targets; real-camera validation may tighten them. A weaker boundary requires documented review and new evidence.

## Users and environments

One organization, at most five invited accounts and two simultaneous stations for the first supervised beta. Desktop Chrome/Edge on Windows is the initial qualification matrix. Phone capture is deferred. Roles: owner (recipe/policy administration and release decisions), operator (capture and disposition), reviewer (labels/evaluation); owner may also review, but independence of a trial must then be reported honestly. No public sign-up or anonymous data access.

[User personas and end-to-end operations](docs/PERSONAS-OPERATIONS.md) defines nine human responsibility profiles and their onboarding, work, escalation, recovery and offboarding. They map to these three explicitly granted app roles or separately authorized operational/evaluation access. They do not add roles, accounts, product surfaces or features. One person may hold several roles; owner status alone does not bypass an operator/reviewer endpoint's role check.

Development starts with explicitly synthetic scenes and printable non-hardware fixtures. Qualification on actual supported parts is mandatory before inviting external beta operators. No actual kits/operators are available today. Availability is an open dependency, not a fictional partner agreement.

## Functional acceptance

The [experience contracts](docs/USER-NEEDS-ADOPTION.md) refine existing requirements through finding → need → workflow/control → scenario → outcome. N08 remains research-first rather than a new product requirement. Implement applicable EX contracts in PP08 and evaluate A01–A09 alongside linked Txx cases. Functional correctness, rendered mechanisms, human understanding and demonstrated value require separate results. Participant preferences, task importance and purchasing conditions remain unvalidated.

| ID | Feature | Acceptance requirement |
|---|---|---|
| R01 | F1 | Draft recipes specify counts, allowed visible variants, measurement intervals and cannot-verify rules; activation requires a reviewer-visible qualification result and owner approval. |
| R02 | F1 | Approved recipe/calibration versions are immutable. New versions invalidate affected current results; historical evidence retains original references. |
| R03 | F1 | Enroll camera geometry and operating conditions; reject incomplete markers, moved camera, unsupported frame shape or failed calibration checks. |
| R04 | F2 | Actual runtime loads an upstream OpenCV 5 build; measurement executes substantively on AWS for the deployed demonstration. |
| R05 | F2 | Correctly measure/count four enrolled broad part classes under qualified conditions; missing, extra, wrong visible variant and unknown object produce distinct findings. No hidden-property inference. |
| R06 | F2 | Glare, overlap, inadequate resolution, blur and calibration failure yield uncertainty/review, not invented precision. |
| R07 | F3 | Visual findings change a recorded next action; action request refers to a specific unresolved constraint and current observation. |
| R08 | F3 | At most two corrective requests per inspection; optional provider attempts are durably reserved and bounded by controls. Unavailable/invalid planner output or unresolved attempts lead to deterministic safe review. |
| R09 | F4 | Only the deterministic verifier can issue PASSED_CURRENT, based on current bound evidence and all constraints. |
| R10 | F4 | Result expires or invalidates on observation loss, detected change, binding changes, originating grant/session loss, global stop or runtime restart; replayed/out-of-order/concurrent requests cannot restore an obsolete pass. |
| R11 | F4 | Evidence links every result to recipe, calibration, policy, software, station epoch and observation; export includes failures and separately labeled overrides. |
| R12 | F5 | Store permissioned before/action/after/outcome/time tuples; reviewed labels remain versioned and linked to their source. |
| R13 | F5 | Frozen splits prevent leakage; replay and approval precede policy promotion; rollback invalidates live sessions and preserves old records. |
| R14 | Cross-cutting | Auth and role checks apply to every resource/action and sensitive commit; browser input cannot choose organization, storage keys, arbitrary tools or pass state. |
| R15 | Cross-cutting | Data minimization, bounded retention, complete export/deletion and permission separation work with real storage. |
| R16 | Cross-cutting | Keyboard-accessible operator flow, non-color status, readable overlays and interruption recovery pass rendered-device checks. |
| R17 | Cross-cutting | Repeatable setup/build/deploy, runtime identity and cost/latency/error traces are recorded for the actual target. |
| R18 | Cross-cutting | Durable state, backup restore, rollback and incident kill switch are tested before beta. |
| R19 | Cross-cutting | Judge-access package and special-award evidence faithfully represent tested capabilities. |
| R20 | Cross-cutting | Actual-object/operator evidence and named operational ownership precede beta release; synthetic tests cannot satisfy this requirement. |

## Nonfunctional targets

- At two stations, target p95 accepted-frame-to-finding latency <=500 ms and no backlog longer than one pending frame per station. Drop superseded frames; never process them later as current.
- Target two analyzed frames/second/station. A current result expires at the earlier of 1,500 ms from server observation acceptance and the 1,000 ms permit-age bound; three consistent valid observations spanning >=1,000 ms are required to first pass. Stability uses prior observations of the same scene; the latest supporting observation must remain fresh. These are upper bounds, not a guaranteed green-display duration or continuous-visibility guarantee.
- UI closes the pass display on local capture failure or result deadline independently of successful server polling. Tab return always starts non-current.
- Target planner response <=3 seconds only for ambiguous cases; the measurement/verifier path never waits on an LLM. A model failure cannot create a pass.
- Provisional operating limits: JPEG/PNG <=2 MiB, <=2 megapixels, three observation uploads and eight control requests/second/station, two concurrent inspections/deployment. Separate quotas let permit issuance and result reads coexist with two-frame/second capture. Account/job/global inference allowances and strict decoding/resource/time limits also apply.
- No unresolved critical/high security defects for beta; no known R09/R10 violation. Accessibility, performance and vision metrics are measured, not inferred from code.

## Required result language

Use "Visible checks passed — current observation" while the lease is valid; "Recheck required" after invalidation; "Cannot verify" for unsupported conditions; "Human disposition recorded" for overrides. Exports describe historical observations. Never claim safe-to-ship, tamper-proof, certified complete or production accuracy without additional evidence.


## Requirement traceability

All application checks remain NOT_RUN. [BACKLOG](BACKLOG.md) owns task-specific work, [test plan](docs/TEST-PLAN.md) specifies T01–T58, and [workflow coverage](docs/WORKFLOW-COVERAGE.md) covers all personas/operations. Required child-case results must bind current target/build/config; partial tests do not close a requirement.

| Requirement | Feature | Tasks | Tests | Evidence | Status |
|---|---|---|---|---|---|
| R01 | F1 | PP04 PP06 PP09 PP10 PP14 PP15 | T01 T02 T03 T29 T35 T36 T41 | E01 E05 E08 E09 E13 | NOT_RUN |
| R02 | F1 | PP04 PP06 PP15 | T02 T12 T36 | E01 E05 E13 | NOT_RUN |
| R03 | F1 | PP04 PP05 PP06 PP08 PP09 PP14 PP15 | T03 T06 T29 T35 T36 T37 | E01 E05 E09 E13 | NOT_RUN |
| R04 | F2 | PP01 PP05 PP13 PP16 | T04 T24 | E02 E03 | NOT_RUN |
| R05 | F2 | PP02 PP05 PP11 PP14 PP15 PP18 | T05 T07 T18 T29 T44 T56 | E05 E07 E11 E13 | NOT_RUN |
| R06 | F2 | PP02 PP05 PP11 PP14 PP15 PP18 | T03 T06 T29 T44 T56 | E01 E05 E07 E11 E13 | NOT_RUN |
| R07 | F3 | PP06 PP07 PP08 PP11 PP14 | T08 T18 T45 | E04 E05 E07 | NOT_RUN |
| R08 | F3 | PP06 PP07 PP08 PP12 PP13 PP14 PP15 | T09 T10 T45 T49 T50 T51 | E04 E05 E06 E11 E12 E13 E14 | NOT_RUN |
| R09 | F4 | PP02 PP03 PP05 PP06 PP08 PP09 PP11 PP13 PP14 PP15 PP18 | T11 T14 T15 T44 T46 T47 T48 T53 | E03 E05 E07 E09 E12 E13 | NOT_RUN |
| R10 | F4 | PP03 PP04 PP06 PP07 PP08 PP09 PP12 PP13 PP14 PP15 PP18 | T11 T12 T13 T14 T34 T36 T37 T38 T45 T46 T47 T48 T51 T53 T54 | E01 E03 E04 E05 E06 E09 E12 E13 | NOT_RUN |
| R11 | F4 | PP06 PP08 PP09 PP10 PP13 PP14 PP15 | T15 T16 T39 T40 T50 T51 T52 | E04 E05 E06 E09 E11 E12 E13 | NOT_RUN |
| R12 | F5 | PP02 PP04 PP09 PP10 PP11 PP14 PP15 | T17 T18 T41 T42 | E01 E07 E08 E09 E13 | NOT_RUN |
| R13 | F5 | PP02 PP04 PP09 PP10 PP11 PP13 PP14 PP15 | T17 T19 T41 T42 T43 | E01 E07 E08 E09 E12 E13 | NOT_RUN |
| R14 | CROSS | PP03 PP04 PP06 PP08 PP09 PP10 PP12 PP13 PP14 PP15 PP17 PP18 | T20 T21 T26 T31 T32 T33 T34 T35 T37 T39 T40 T43 T48 T53 T55 T57 T58 | E01 E03 E05 E06 E08 E09 E11 E12 E13 E14 E15 E16 | NOT_RUN |
| R15 | CROSS | PP03 PP04 PP06 PP09 PP10 PP12 PP13 PP14 PP17 PP18 | T22 T23 T35 T39 T40 T41 T48 T52 T54 T55 T57 | E01 E03 E05 E06 E08 E09 E12 E14 E15 E16 | NOT_RUN |
| R16 | CROSS | PP08 PP11 PP14 PP15 PP18 | T27 T50 T56 T58 | E04 E06 E07 E09 E11 E13 | NOT_RUN |
| R17 | CROSS | PP01 PP03 PP06 PP07 PP08 PP12 PP13 PP14 PP16 PP18 | T04 T24 T25 T26 T31 T38 T46 T49 T54 | E02 E03 E04 E05 E09 E12 E14 | NOT_RUN |
| R18 | CROSS | PP03 PP06 PP07 PP09 PP10 PP12 PP13 PP14 PP18 | T23 T28 T33 T38 T40 T43 T47 T49 T53 T54 T55 | E03 E04 E05 E06 E08 E09 E12 E14 | NOT_RUN |
| R19 | CROSS | PP03 PP09 PP13 PP17 | T30 T57 | E09 E15 E16 | NOT_RUN |
| R20 | CROSS | PP02 PP08 PP10 PP11 PP14 PP15 PP18 | T29 T42 T50 T56 T58 | E04 E06 E07 E08 E09 E11 E13 | NOT_RUN |
