# Supervised beta readiness

Current decision: **NO-GO**. Application components are partially implemented with scoped local verification; complete required workflows remain unaccepted. Physical kits/operators are unavailable; target AWS environment, spending limit and named support remain unresolved. [Build status](BUILD-STATUS.md#current-integration-and-verification-boundary) owns implementation and test applicability. Documentation completion does not change this decision.

## Beta scope

One business, five or fewer invited accounts, at most two desktop stations, supported Windows Chrome/Edge and qualified camera/recipe combinations. All participants receive the visible-check limitations and manually verify every kit before physical packing. No autonomous release/dispatch or safety-critical use. Sessions are scheduled and supervised; no 24/7 support promise.

## Gate checklist

| Gate | Required evidence | Current state |
|---|---|---|
| B01 — owner and target | Named operator support/release owner, AWS target, region/budget, data permissions and support hours | BLOCKED: owner decisions pending |
| B02 — complete feature behavior | F1–F5 implemented; critical journeys and T01–T19 pass on candidate version | NOT RUN |
| B03 — actual hardware qualification | Supported physical specimens/camera qualified, truthful error envelope and unknown-case behavior | BLOCKED: no kits |
| B04 — operator suitability | At least two actual packing operators, three independent sessions across two days; report burden and failures | BLOCKED: no access |
| B05 — state/security boundaries | T11–T16 and T20–T26; no known stale-result bug or high/critical exploitable issue | NOT RUN |
| B06 — accessible usable flow | T27 on supported desktop matrix, including interruptions and visible expiry | NOT RUN |
| B07 — durable operation | T23/T28 real restore, deletion, rollback, alerts and kill switch | NOT RUN |
| B08 — cloud and cost | T24/T25; runtime identity, cost estimate plus measured usage and budget controls | NOT RUN |
| B09 — launch decision | Owner reviews exact build/config/target, evidence and residual risks, then authorizes invitations | NOT RUN |

The full applicable T01–T58 suite and W01–W26 coverage in [workflow acceptance](WORKFLOW-COVERAGE.md) supplement every gate above. B02 includes T35–T38/T42–T47/T50–T52/T58; B05 includes T31–T34/T39–T43/T48–T49/T53/T57; B06 includes T58; B07 includes T40/T41/T47/T53–T55; B08 includes T38/T46/T49/T54; B03/B04 include T36/T42/T56. Required child cases must be complete and current. T57 is mandatory before judge access and temporary-account teardown; if no judge access is enabled for beta, its specific access subcases have an explicit scope-based applicability record. No optional-model/COOL omission can waive core role/state/privacy/physical checks.

B03 should include at least 60 independently staged real-object episodes, including at least 30 incomplete/incorrect kits and challenge cases, spread across qualified recipes/sessions. This is a proposed minimum for a supervised manually checked pilot, not a reliability certification. Any incorrect pass must be investigated and addressed or the affected recipe disabled; lack of statistical assurance remains explicit. Wider/unattended use requires a separately justified larger validation design and risk threshold.

The 20% throughput hypothesis concerns product advantage; it does not substitute for B05 or authorize use. If the benefit is inconclusive, keep the project labeled experimental and obtain owner acceptance for any continued supervised research pilot. Do not recruit a public beta to fill missing safety evidence.

## Onboarding materials

The [seven adoption gates](USER-NEEDS-ADOPTION.md) complement B01–B09 with user understanding, value, experience, truthful demonstration, implementation commitment and publication boundaries. None is READY. Before study, freeze applicable A01–A09 scope/rubrics and identify the actual decision owner. Appropriate stopping or informed non-adoption is valid; an agreeable interview is not release evidence.

Assign named people to the responsibilities in [persona operations](PERSONAS-OPERATIONS.md), especially business/release ownership (P01), packing (P02), review (P03), supervision (P04), service support (P05) and data stewardship (P07). One person may cover several responsibilities within the account limit. Record P08's independence separately; do not treat role assignment as completed gate evidence.

The [beta user guide](BETA-USER-GUIDE.md) and [session record template](templates/BETA-SESSION-RECORD.md) are included. Verify wording against implemented screens and complete owner/contact/permission fields before distribution.

Owner checklist: sign-in/MFA, invite only, accepted retention, recipe qualification, tested camera, cost controls, named contact and incident stop path. Operator guide: transmitted ROI, unsupported properties, what current status means, how to respond to actions, manual double-check and when to stop. Reviewer guide: independent truth labeling, synthetic/physical distinction, data permission, split leakage, change approval and rollback. Provide a concise in-app help panel and exportable guide; do not expose internal system detail in the normal flow.

## Pilot protocol

PP15 is a separately authorized supervised pre-beta qualification study, after applicable security/state/operations checks, with manual double-checks and participant/data permissions. It obtains B03/B04 evidence rather than claiming B09 launch approval in advance. Stop an adverse trial; do not tune against its frozen test answers. T56 records real versus acted operators, independence/conflicts, incomplete trials and actual denominators.

Observe ordinary checking first; record task times/errors with permission and no employee ranking. Run counterbalanced manual/fixed/adaptive sessions. Collect task failures, retake burden, calibration burden and whether users misunderstand a pass. Ask what they would do when the camera goes offline. Define compensation/recruitment arrangements only with owner authorization. No kits or participants have been obtained.

## Launch receipt template

Record decision GO/NO_GO, environment/account/region, code SHA/artifact/control/data hashes, evidence IDs, supported recipes/cameras, known limits, manual check policy, support owner/hours, budget, participant/data permissions, approver and timestamp. An absent field is unresolved, not an implied approval. A code/config/recipe/model/target change invalidates affected evidence and triggers scoped revalidation.

## Stop criteria

Immediately disable new inspections for a stale/incorrect current-state bug, evidence disclosure, uncontrolled spend, repeated unsafe false passes, unavailable support or broken deletion/restore. Preserve incident metadata, invalidate live passes, contact users only through authorized owner procedures, and require retest before re-enabling.
