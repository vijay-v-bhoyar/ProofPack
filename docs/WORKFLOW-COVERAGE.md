# Workflow coverage and acceptance

Documentation baseline: October 13, 2026. Complete workflow acceptance remains NOT_RUN. Selected local components have scoped execution evidence in BUILD-STATUS; that does not accept whole workflows or human tasks. This is the canonical normal-path, exception and persona-step coverage map; it does not prove runtime completeness. Scope remains nine personas, three explicit app roles and five features. Domain interviews, actual hardware/operators and implementation can expose additional requirements.

## Workflow contracts

Persona/adoption Improve overlay: W20/W25/W26 also cover the account-free concern journey for an incidentally recorded person, defined in PERSONAS-OPERATIONS and tested by A07-P1. W01/W11/W17/W18/W21/W25 must preserve explicit duty/grant, support availability and independence boundaries when one person holds several responsibilities; A06-P1 supplies that combined scenario. These refinements reuse the 78 mapped persona operations and existing technical scopes. They add no portal, app role or accepted runtime capability; combined acceptance remains NOT_RUN. The canonical scenarios are in TEST-PLAN and blank evidence fields in templates/BETA-SESSION-RECORD.

Each workflow requires recorded prerequisites, actor/role/target, inputs, normal result, negative/fault/retry outcomes, handoff and exit evidence. The named contracts in [state/data/API](STATE-DATA-API.md) and [test plan](TEST-PLAN.md) govern implementation; [persona operations](PERSONAS-OPERATIONS.md) governs human responsibility.

| Workflow | Operation and completion rule | Personas | Tests | Evidence | Status |
|---|---|---|---|---|---|
| W01 — Fit, scope and accountable decisions | Record the actual manual workflow and missing commercial/physical inputs; owner accepts scope or stops. | P01 P06 | T29 T56 | E13 E07 | NOT_RUN |
| W02 — Deployment bootstrap | Authorize target/change set, provision first approved owner and prove actual runtime; failed readiness remains disabled. | P01 P05 P06 | T04 T20 T24 T26 T31 T54 | E02 E03 E09 E12 E14 | NOT_RUN |
| W03 — Invitation and role enrollment | Reserve an account slot, deliver/accept scoped invitation and assign explicit roles; expiry/revocation/duplicates cannot activate membership. | P01 P02 P03 P04 P07 P08 | T20 T32 T33 | E09 | NOT_RUN |
| W04 — Sign-in, recovery and logout | Validate provider flow and server session; use authorized factor recovery; revoke sessions and originating inspection authority on logout/disable. | P01 P02 P03 P04 P05 P07 P08 | T20 T21 T31 T34 T48 | E05 E09 | NOT_RUN |
| W05 — References and calibration | Upload scoped reference media and establish measured geometry/purpose/retention; malformed/missing/unqualified references block use. | P01 P02 P03 P06 P07 | T01 T03 T21 T35 T41 | E01 E09 | NOT_RUN |
| W06 — Recipe and calibration approval | Review matching qualification; approve immutable revision or retire/return failure; changed/retired bindings invalidate live results. | P01 P03 P06 | T01 T02 T03 T12 T36 | E01 E05 E13 | NOT_RUN |
| W07 — Station preparation and ownership | Enroll/list approved profiles; explicitly acquire/release/take over a station; reject unsupported setup and fence old work. | P01 P02 P04 P05 P06 | T03 T12 T20 T37 T38 | E01 E03 E05 E09 | NOT_RUN |
| W08 — Capture and measurement | Admit fresh bounded input, decode, calibrate and re-evaluate every observable constraint; unknown/out-of-envelope cases cannot pass. | P02 P03 P06 P08 | T04 T05 T06 T07 T21 T25 T44 | E02 E07 E13 E05 | NOT_RUN |
| W09 — Corrective action and reinspection | Reserve bounded proposal, revalidate latest eligibility, issue allowed action and inspect fresh outcome; timeout/budget/unsupported output escalates. | P02 P03 P04 P06 P09 | T08 T09 T10 T45 T49 | E04 E05 E09 E14 | NOT_RUN |
| W10 — Current-result validity | Verify and atomically commit complete fresh evidence with runtime/control/grant bindings; expiration/change/revocation can never restore old authority. | P01 P02 P03 P04 P05 P06 P09 | T11 T12 T13 T14 T46 T47 T48 T53 | E05 E09 E12 E03 | NOT_RUN |
| W11 — Manual exception and support handoff | Stop capture/reliance, request designated reviewer and obtain separate acceptance or use manual procedure; retain prior duty until successor accepts. Disposition stays separate. No response stops app-assisted use; backend/API checks do not accept rendered/human W11. | P01 P02 P03 P04 P06 | T09 T15 T27 T50 | E04 E06 E11 E13 | NOT_RUN |
| W12 — Close, recover and next kit | Recover invalidated same record without budget reset; close terminally, release allocation and create a genuinely new record with fresh bindings. | P01 P02 P04 P05 | T12 T13 T14 T15 T37 T38 T51 | E05 E06 E12 | NOT_RUN |
| W13 — Evidence commit/reconciliation | Persist required selected bytes before publishing result; reconcile partial writes and represent missing/deleted media explicitly. | P02 P03 P05 P06 P07 | T16 T23 T52 | E06 E09 | NOT_RUN |
| W14 — Export and authenticated delivery | Run scoped durable job; reauthorize each new download, expiry and revocation; abort/reconcile forbidden output and label history. | P01 P02 P03 P05 P07 P08 P09 | T20 T22 T23 T39 T40 T52 | E06 E09 E12 E15 | NOT_RUN |
| W15 — Label correction and permitted data | Preserve actor/origin/purpose/version; qualify independence separately and prevent poisoned/unpermissioned/exposed data reuse. | P03 P06 P07 P08 | T17 T22 T41 T42 | E07 E08 E09 E13 | NOT_RUN |
| W16 — Replay, evaluation and promotion | Lease bounded validated jobs, compare frozen cases, and require owner-reviewed complete candidate evidence for promotion/rollback. | P01 P03 P05 P06 P07 P08 | T17 T18 T19 T41 T42 T43 | E05 E07 E08 E09 E12 | NOT_RUN |
| W17 — Routine service/cost maintenance | Observe actual target, quotas, jobs and spend; optionally benchmark matched COOL workload; update approved artifacts/config and invalidate affected evidence; missing cost authority disables inference. | P01 P04 P05 P06 P07 | T04 T18 T24 T25 T26 T28 T49 | E03 E09 E10 E12 E14 | NOT_RUN |
| W18 — Incident stop and controlled resume | Persist stop/control epoch, reject racing work, diagnose and revalidate in diagnostic mode; owner enables only with current recovery evidence. | P01 P02 P03 P04 P05 P06 P07 P08 | T11 T12 T14 T28 T47 T48 T50 T53 | E05 E09 E12 E13 | NOT_RUN |
| W19 — Backup, rollback and restore | Restore only to identified isolated target; replay tombstones and regenerate auth/runtime authority before exposure; incompatible target remains disabled. | P01 P04 P05 P06 P07 | T23 T28 T47 T54 | E03 E09 E12 | NOT_RUN |
| W20 — Purpose withdrawal, retention and erasure | Deny new reads/use, complete authorized erasure jobs, retire unavailable dependencies and disclose backup/downloaded-copy limits. | P01 P03 P05 P06 P07 P08 | T20 T22 T23 T39 T40 T41 T42 T54 | E01 E08 E09 E12 E13 | NOT_RUN |
| W21 — Ownership transfer and offboarding | Verify successor and last-owner invariant; revoke app/cloud duties and sessions, close owned work and reconcile pending jobs. | P01 P02 P03 P04 P05 P06 P07 P08 P09 | T20 T32 T33 T34 T48 T55 | E05 E09 E12 | NOT_RUN |
| W22 — Installation exit and exact teardown | Stop work, inventory/export/delete permitted data and authorize exact cleanup; record retained backup duties and recurring costs. | P01 P05 P06 P07 | T23 T28 T33 T55 | E06 E09 E12 E14 | NOT_RUN |
| W23 — Physical qualification/pilot | Authorize pre-beta supervised study after local/security/ops readiness; record actual operators/specimens, manual truth, adverse cases and limits. | P01 P02 P03 P04 P06 P07 P08 | T03 T05 T06 T18 T27 T29 T36 T42 T50 T56 T58 | E01 E07 E11 E13 | NOT_RUN |
| W24 — Submission and judge session | Freeze truthful claims/rights, verify clean sanitized access, demonstrate actual mode and failures, then expire temporary access. | P01 P05 P06 P09 | T04 T08 T10 T14 T24 T30 T57 | E02 E03 E04 E05 E07 E09 E10 E11 E15 E16 | NOT_RUN |
| W25 — Feedback, impact and recipient report | Capture complete-workflow burden and adverse feedback without employee ranking; review historical evidence without asserting shipped contents. | P01 P02 P03 P04 P06 P08 | T15 T18 T22 T29 T50 T56 | E06 E07 E11 E13 | NOT_RUN |
| W26 — Accessible role journeys | Exercise all authorized role combinations and interruption/data-request routes on supported devices; understandable role denial and historical status required. | P01 P02 P03 P04 P06 P07 P08 P09 | T20 T27 T30 T50 T58 | E09 E11 E13 E15 | NOT_RUN |

## Every persona operation

Step numbers refer to the numbered operation rows in [persona operations](PERSONAS-OPERATIONS.md). Every one of the 78 rows maps below. A business decision/physical task is validated through actual review/pilot evidence, not falsely represented as an automated test of purchasing or packing.

| Persona | Step | Workflows |
|---|---|---|
| P01 | 01 | W01 |
| P01 | 02 | W02 W23 |
| P01 | 03 | W03 W04 W20 |
| P01 | 04 | W05 W06 |
| P01 | 05 | W06 W23 |
| P01 | 06 | W17 W23 |
| P01 | 07 | W16 W25 |
| P01 | 08 | W18 |
| P01 | 09 | W14 W20 W21 |
| P01 | 10 | W22 |
| P02 | 01 | W03 W04 |
| P02 | 02 | W05 W07 W26 |
| P02 | 03 | W07 W12 |
| P02 | 04 | W08 W10 |
| P02 | 05 | W09 |
| P02 | 06 | W11 |
| P02 | 07 | W10 W12 W18 |
| P02 | 08 | W10 W11 |
| P02 | 09 | W12 W13 |
| P02 | 10 | W04 W21 W25 |
| P03 | 01 | W03 W04 W15 |
| P03 | 02 | W05 W06 |
| P03 | 03 | W06 W08 W23 |
| P03 | 04 | W11 W25 |
| P03 | 05 | W15 |
| P03 | 06 | W15 W16 |
| P03 | 07 | W16 |
| P03 | 08 | W06 W16 |
| P03 | 09 | W16 W18 W23 |
| P03 | 10 | W14 W20 W21 |
| P04 | 01 | W03 W11 |
| P04 | 02 | W07 W17 |
| P04 | 03 | W07 W12 |
| P04 | 04 | W11 |
| P04 | 05 | W18 |
| P04 | 06 | W18 W19 |
| P04 | 07 | W12 W25 |
| P04 | 08 | W21 |
| P05 | 01 | W02 |
| P05 | 02 | W02 W17 |
| P05 | 03 | W02 W04 |
| P05 | 04 | W18 W19 |
| P05 | 05 | W17 |
| P05 | 06 | W18 |
| P05 | 07 | W17 W20 W21 |
| P05 | 08 | W21 W22 |
| P06 | 01 | W01 |
| P06 | 02 | W02 W08 |
| P06 | 03 | W05 W06 W07 W08 W09 W10 W13 W16 |
| P06 | 04 | W08 W10 W13 W26 |
| P06 | 05 | W09 W15 W16 W23 |
| P06 | 06 | W02 W24 |
| P06 | 07 | W18 W19 |
| P06 | 08 | W21 W24 W25 |
| P07 | 01 | W03 W20 |
| P07 | 02 | W05 W20 |
| P07 | 03 | W15 W20 |
| P07 | 04 | W14 |
| P07 | 05 | W20 |
| P07 | 06 | W19 W20 |
| P07 | 07 | W18 |
| P07 | 08 | W20 W21 W22 |
| P08 | 01 | W03 W04 W23 |
| P08 | 02 | W16 W23 |
| P08 | 03 | W23 W25 |
| P08 | 04 | W08 W23 |
| P08 | 05 | W15 W23 |
| P08 | 06 | W23 W26 |
| P08 | 07 | W18 W23 |
| P08 | 08 | W14 W20 W21 W23 |
| P09 | 01 | W24 |
| P09 | 02 | W24 |
| P09 | 03 | W24 |
| P09 | 04 | W09 W24 |
| P09 | 05 | W10 W24 |
| P09 | 06 | W24 W26 |
| P09 | 07 | W24 |
| P09 | 08 | W21 W24 |

## Coverage decisions

- P01–P09 cover the current intended human responsibilities. No additional product persona or role was justified. Initial owner provisioning, recovery, delegated security testing, role transfer and account exit are now explicit variants of existing personas.
- Kit recipients and suppliers remain indirect stakeholders; reports use the business's normal channel. No customer portal, general chatbot, inter-agent channel or shared-business pool is added.
- Owner-only users cannot perform operator/reviewer endpoints without those explicit roles. Operational IAM and release/spending authority remain separate.
- Invitation, station, calibration, asset, export, offline-job and recovery operations now have specified API/lifecycle contracts. Their inclusion is design closure only; application implementation and retest remain pending.
- Bounded/property testing cannot cover every unbounded event sequence. Report tested generator bounds/seeds and case manifests; never report exhaustive universal correctness.
- Optional model/COOL subcases require documented applicability. A disabled optional path is NOT_APPLICABLE with configuration evidence, not PASS; required deterministic/state/security/physical workflows cannot be skipped to approve beta.
- A pre-beta qualification study is separately authorized, supervised and manually checked. It collects B03/B04 evidence and does not imply B09 launch approval. Complete beta still requires all gates.
- The expanded suite is T01–T58. Each implemented test must enumerate child cases/fixtures and independent assertions, including positive, denial, boundary, conflict, retry and failure variants where applicable. One successful child case does not complete a whole test or workflow.

October 15 persona/adoption review retains every mapping above. [A05-B1/A09-B1](USER-NEEDS-ADOPTION.md#comparison-interpretation-and-adoption-acceptance) refine W16/W23/W24/W25 comparison interpretation under existing tests; no new workflow, persona or operation is added. Focused technical reporting tests cannot close these human/physical workflows. Source-bound full local regression evidence and later implementation changes are recorded in [BUILD-STATUS](BUILD-STATUS.md#current-integration-and-verification-boundary); do not infer that historical full execution verifies newer code or complete workflows. All canonical W acceptance statuses remain NOT_RUN.

## Claim and closure rule

A workflow may be reported verified only when its applicable required tests have current target/build/control-bound results, all required child cases and failure outputs are retained, and human/physical prerequisites are actually evidenced. Record scope, mode, data origin, actor independence and limitations. [Evidence ledger](../evidence/index.json) separates planned coverage from actual test results. The documentation validator checks reference/coverage structure only; beta remains NO_GO.
