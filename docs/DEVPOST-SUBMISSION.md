# ProofPack submission preparation

Reviewed October 19, 2026. Status: DRAFT, NOT READY FOR FINAL SUBMISSION. This record owns submission preparation only; BUILD-STATUS remains authoritative for implementation and acceptance.

## Destination and saved work

Existing entry 1246626, project 1492167, now named ProofPack; no duplicate project created. [Edit entry](https://devpost.com/submit-to/30984-opencv-ai-competition-2026-powered-by-aws/manage/submissions/1246626-proofpack/project-overview). [Preview](https://devpost.com/software/proofpack).

Saved pitch: A camera-guided packing assistant that spots visible kit discrepancies, requests the next useful view, and keeps inspection evidence tied to the current kit.

The project story describes the problem, five capabilities, architecture, Codex assistance, challenges, measured local scope and remaining work. It explicitly discloses missing AWS, physical-kit and human-use proof. The current project is a prototype; beta remains NO_GO.

## Live form checklist

Observed through the authenticated browser because Devpost connector whoami and get_submission_requirements returned internal errors. This is browser-observed form evidence, not a successful connector response. The user explicitly authorized browser preparation. No final submission or rules agreement is performed.

| Field | Current preparation / remaining action |
|---|---|
| Project name and elevator pitch | Saved |
| Project story | Saved; verify preview before final submission |
| Built with | Python and OpenCV saved; additional implementation tags optional |
| Video demo link | Required; actual public/unlisted YouTube/Vimeo URL missing |
| File upload | Required; maximum 35 MB; report archive prepared locally. Browser upload blocked by extension file-access permission; not uploaded |
| Repository URL | Public: https://github.com/vijay-v-bhoyar/ProofPack; source pushed and URL saved to Devpost. Public visibility verified after email confirmation |
| Testing instructions | Saved and re-opened to verify persistence; describes local checks and absent hosted access |
| Working web endpoint | Optional form field, but published requirements demand endpoint OR arranged live screen-share; neither verified |
| Sponsor / Special Prizes | Leave unselected until qualifying evidence is ready |
| Special Award Consideration, field 28208 | Separate selection mirrors award intent; do not claim COOL qualification |
| Repository URL, field 28209 | Saved: https://github.com/vijay-v-bhoyar/ProofPack |
| Testing instructions, field 28210 | Saved |
| Working web endpoint, field 28211 | Missing |

The live page displayed October 27, 2026 at 2:45 a.m. EDT; prose states October 26 at 11:59 p.m. Pacific. Use the earlier displayed cutoff and aim to finish October 25. [Event](https://opencv26.devpost.com/).

## Eligibility and rights

User states they are from USA. Do not infer age, residence details, employer conflicts, team authorization or asset rights. Header requires legal age of majority while rules mention age 13 with guardian permission; resolve any applicable age ambiguity before final agreement. No country field appeared in the inspected project/additional-info forms; account preferences were not changed. [Rules](https://opencv26.devpost.com/rules).

## Testing instructions for judges

Current artifact is a local prototype. No deployed credentials or AWS endpoint are provided. Review the technical report's limitations before interpreting results. Once the repository is accessible, use a clean Windows Python 3.12 environment and the pinned requirements. From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe docs/contracts/validate_documentation.py
.\.venv\Scripts\python.exe scripts/prove_runtime.py
.\.venv\Scripts\python.exe -m pytest tests/unit/test_verifier.py tests/unit/test_planner.py -q
npm.cmd ci
npm.cmd run typecheck
npm.cmd run build
```

These are scoped reproduction instructions, not a claim that this clean-install sequence ran during submission preparation. Inspect requirements-dev.txt and platform locks first. The runtime proof generates a local OpenCV known-image receipt; unit checks exercise deterministic behavior, not human accuracy. Browser tests use the repository's Playwright configuration; local integration requires Java and DynamoDB Local. Use documented guarded runners for broader suites; do not run paid/provider operations or create production resources just to inspect the project. AWS configuration, installation approval, IAM, budget and actual cloud proof remain outstanding. See [operations](OPERATIONS.md), [test plan](TEST-PLAN.md) and [build status](BUILD-STATUS.md).

## Assets and final readiness

- Technical report: [current report](submission/TECHNICAL-REPORT.md), including an architecture diagram and claim limits.
- Video: follow the existing [4:40 demo script](templates/DEMO-SCRIPT.md); show the team and actual application, label synthetic/recorded material, show a failure/invalidation, architecture and measured results. Do not present a storyboard as a working demo.
- Screenshots needed: configured recipe/capture preview; targeted correction; stale-result invalidation; historical evidence; reviewer replay. Capture actual UI and label fixtures; no fabricated application screenshots.
- Repository/source access: https://github.com/vijay-v-bhoyar/ProofPack is public at the user's explicit request, verified through GitHub after email confirmation on October 19, 2026. No collaborator invitation is needed for source access. Application/demo access remains separate.
- AWS: execute a meaningful component under separately resolved target/budget authority and attach a same-request execution receipt.
- Evaluation: physical/operator benefit remains unmeasured; report denominators, baselines and failures when collected.
- Agentic Vision: potential fit; attach an actual perception-to-action trace and evaluation before selecting both applicable award fields. COOL remains unclaimed without actual COOL/Arm workload evidence.
- Final review: inspect all saved fields, uploaded contents, rights and eligibility; obtain explicit final submission approval. A completed draft form is not contest compliance.

## Publication boundary

Maintain source, tests, fixtures, documentation, pinned dependencies and explicitly referenced evidence in Git. Keep the approximately 3.4 GB of generated execution workspaces, dependency bundles and raw captures locally. Referenced evidence records preserve their original bytes, failures and provenance; their nested references may refer to local-only raw artifacts. The source repository is not a complete forensic archive. No runtime behavior changed for this preparation. A pattern scan found only four reviewed dummy credential URLs in negative tests and their collection receipt; it is not a guarantee that arbitrary secrets cannot exist. Git whitespace checks report existing historical/log whitespace and three pre-existing blank EOF lines; no historical evidence was rewritten to clear them.

Initial push 1647888 was followed by byte-preservation correction bc5e13e without history rewriting. The corrected archive matched all 1,276 reviewed files and passed all 34 documentation checks from an isolated extraction. The first archive check caught Git line-ending normalization; the next caught an omitted directory link, repaired by including both referenced qualification reports. No application tests or AWS operations ran during submission preparation. A source archive under 35 MB is available locally at artifacts/devpost/publication-source.zip; its file upload is blocked by browser extension permissions, not a Devpost acceptance result. Video remains blank by user instruction. Final terms checkbox remains unchecked and the entry remains DRAFT.

## Judging alignment

Technical execution (30%): substantive OpenCV functions, deterministic verification and reproducible tests. Innovation (20%): targeted observations with version-bound evidence. Impact (20%): intended packing benefit, currently unvalidated. UX (10%): capture/correction/recovery flows, human evaluation pending. Documentation (10%): report, diagram, source, video and instructions. Cloud/responsibility (10%): actual AWS receipt, observability/access/retention evidence still required. [Live rubric](https://opencv26.devpost.com/rules).
