# Hackathon evidence and submission plan

Checked October 13, 2026 against official public pages. Devpost connector calls for rules/submission requirements returned internal errors; custom submission-form fields remain unverified. This document maps the proposed product to evidence, not a declaration of eligibility or compliance.

## Published requirement checklist

Substantive OpenCV 5 and meaningful AWS execution are required. Deliver a technical report, accessible code/archive, pinned dependencies and build/deploy/test instructions, architecture diagram, working endpoint or arranged screen-share, <=5-minute team/application/architecture/results video, and evaluation including limitations. Agentic evidence must show vision changing a later action; COOL evidence must prove core workload execution on Graviton/Arm with reproducible comparisons. [Devpost requirements](https://opencv26.devpost.com/).

## Evidence IDs

| ID | Deliverable to collect | Minimum contents |
|---|---|---|
| E01 | Recipe/calibration qualification | Versions, references, approval, operating envelope and failed examples |
| E02 | OpenCV runtime proof | Version/path/build, executed functions, code hash, actual result |
| E03 | AWS execution receipt | Target identity, same-request trace, deployed artifact/config and service path |
| E04 | Agent workflow proof | Diagram, visual finding -> chosen action -> new observation -> result, actual policy mode |
| E05 | Verifier proof | Generated sequences, replay/race/restart failures, raw test outputs and exit codes |
| E06 | Evidence integrity/export | Linked manifests, historical/current distinction, partial-write recovery |
| E07 | Evaluation report | Frozen manifests, data origin, baselines, raw outcomes/denominators/uncertainty/failures |
| E08 | Learning/revision experiment | Development-only updates, untouched comparison, promotion/rollback receipt |
| E09 | Security/privacy review | Threat tests, scans, access denial, redacted logs and deletion outcomes |
| E10 | COOL benchmark, optional | Actual loaded library/workload, baseline/config equivalence, repetitions and total cost |
| E11 | UX/accessibility | Supported-device screenshots/video, keyboard/contrast/zoom/recovery results |
| E12 | Operations | Restore/rollback/kill-switch/alert delivery receipts and limitations |
| E13 | Physical/operator pilot | Actual specimens/participants, permission, protocol, outcomes and independent review |
| E14 | Cost | Dated estimate plus measured usage; credits and unmeasured components explicit |
| E15 | Submission/access package | Report/repo/demo/video access checks, form answers and actual submission receipt |
| E16 | Rights and eligibility register | Licenses/attributions, permitted media/data, human eligibility declarations and organizer clarifications |

E01–E16 start NOT_RUN in [ledger](../evidence/index.json), except E13 is BLOCKED because kits/operators are unavailable. E10 is required only when opting into COOL, not a shortcut around core evidence. Every record follows [schema](contracts/evidence.schema.json). Documentation checks have their own file and never set these records PASS.

## Overall judging mapping

| Criterion | Weight | Our implementation/evidence emphasis |
|---|---:|---|
| Technical execution | 30% | F1/F2/F4; E01/E02/E05/E07 |
| Innovation | 20% | F3/F5; E04/E08; acknowledge existing inspection products |
| Real-world impact | 20% | E13 and complete-task productivity; synthetic benefit remains unproven |
| User experience | 10% | F1–F5 operator/reviewer flow; E11 |
| Documentation/presentation | 10% | E15, clean reproduction, clear failure explanation |
| Cloud/reproducibility/responsible operation | 10% | E03/E09/E12/E14 |

Agentic weights: integration 30%, orchestration 25%, effectiveness 20%, failure/human control 15%, UX/documentation/demo 10%. Map respectively to E04, E04/E05, E07, E05/E09/E12, E11/E15. [Official rules/rubrics](https://opencv26.devpost.com/rules).

Rights, consent, fair play and truthful capabilities remain mandatory. Participants retain IP but submitted materials receive a broad license; do not put secrets or unauthorized customer assets in the submission. Complete eligibility and winner documentation when applicable. Read the controlling terms rather than treating this plan as legal clearance. [Official rules](https://opencv26.devpost.com/rules).

COOL weights: integration 30%, architecture 25%, measured value 20%, innovation 15%, reproducibility 10%. E10 must establish all five with the actual workload; E03/E07/E14 support it. [Organizer rubrics](https://opencv.org/opencv-ai-competition-2026/).

## Dates and unresolved questions

The public header says October 26 at 11:45 p.m. PDT; prose says 11:59 p.m. Use the earlier cutoff (October 27, 2:45 a.m. Eastern) and target October 25. [Deadline source](https://opencv26.devpost.com/).

Late entrants without proposals are accepted according to the manager's [clarification](https://opencv26.devpost.com/forum_topics/45369-late-entry-without-a-proposal-and-the-video-shows-the-team). Age and team-size text conflict across pages; geographic restrictions also apply. Confirm actual entrant facts, any reused-work conditions and platform form requirements before submitting. The grant is not needed to compete. No agreement, registration or submission is performed by this plan.

## Packaging and access

The [workflow coverage map](WORKFLOW-COVERAGE.md) supplies persona/operation/test coverage. T30/T57 verifies sanitized temporary judge access and its expiry; no read-only judge role is assumed. Evidence records list planned coverage separately from actual child-case outcomes/coverage-manifest hashes. A single passed case or schema-valid artifact cannot stand in for all required workflow results.

Use the [technical report template](templates/TECHNICAL-REPORT.md) and [demo script](templates/DEMO-SCRIPT.md). Freeze code/config/dataset manifests; offer sanitized fixtures plus exact setup and expected outputs. Supply a working authorized judge account/endpoint or arrange a screen-share through the user; no contact is sent automatically. Test links from a clean session. A public page is not proof private media/repo permissions work. Record video duration, accessibility/captions, team presentation and source rights. Resolve any form fields in the actual submission UI when the connector is unavailable.

Demo can show controlled or simulated scenes only if clearly labeled. Missing real-user evidence limits impact claims and does not pass beta gates. Never substitute a staged success for an evaluated result or list target percentages as achievements.
