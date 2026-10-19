# ProofPack

Status: saved Devpost draft; not submitted. Video remains blank at the user's request.

## One-line summary

A camera-guided packing assistant that spots visible kit discrepancies, requests the next useful view, and keeps inspection evidence tied to the current kit.

## Saved project story

## Inspiration
A packing check is more than a photograph. An overlapping part can hide an omission, and a correct result becomes stale when someone changes the kit. ProofPack explores how a camera assistant can ask for the next useful view and keep every result tied to the evidence that produced it.

Our initial target is one small business with invited packing operators using desktop webcams. The intended benefit is fewer overlooked visible discrepancies and clearer review records. We have not yet measured that benefit with real packing operators.

## What it does
ProofPack is an in-development assistant for configured, visible kit contents. Its five connected capabilities are:
1. Versioned recipes and camera enrollment: define expected visible parts and require qualification before physical use.
2. OpenCV measurement and scene tracking: check image quality, rectify the work area, measure supported visible features, and report uncertainty.
3. Bounded active inspection: choose a recapture, separation, flat-placement or human-review action from current structured findings, then require fresh evidence.
4. Deterministic verification and evidence: bind outcomes to recipe, observation and scene versions; stale evidence cannot authorize a current pass.
5. Outcome review and replay: preserve label revisions and separate development from held-out evaluation before considering a change.

These capabilities have local implementations and selected automated checks; complete end-to-end acceptance remains unfinished. ProofPack does not authorize shipping, replace manual checking, authenticate camera footage, or verify hidden material properties.

## How we built it
The application combines a React/TypeScript client with a Python/FastAPI backend. The dependency lock pins opencv-python 5.0.0.93. Computer vision produces structured observations; bounded orchestration chooses a permitted next action; a separate deterministic verifier owns the result. An optional model adapter is constrained to the same action vocabulary and cannot grant a pass.

The AWS integration architecture uses DynamoDB for conditional state and S3 for selected evidence, with authenticated access and configured runtime controls. Current evidence includes DynamoDB Local and synthetic identity/storage fixtures. Meaningful execution on actual AWS, native Graviton/Arm validation and a judge-accessible deployment are still pending; we do not claim those results.

Codex assisted with implementation, documentation, regression analysis and testing. The proposed Agentic Vision contribution is the application's visual finding-to-action-to-reinspection loop, not the use of a coding assistant.

## Challenges we ran into
The hardest issue is evidence becoming stale across camera changes, retries, concurrent actions, access changes and process recovery. We built explicit version bindings, finite action budgets and conservative hold states. We also learned to keep successful local tests distinct from deployment proof and user acceptance.

## Accomplishments and evaluation
Selected verification records cover backend behavior, installed-package behavior and browser workflows. The latest narrow checkpoint passed six metadata-history rollover/retry/clock cases on source and the installed package, plus three local database/CV integration cases. The native run used only its owned local emulator and made zero external SDK requests. These tests establish their specific engineering behavior; they do not measure inspection accuracy or packing productivity.

Earlier source-bound owner-metadata verification recorded 645 source cases, 592 installed-backend cases and 54 browser cases. Browser APIs were intercepted with synthetic responses. Counts refer to scoped checkpoints and are not additive or a claim that the whole current test suite passed.

## What we learned
An inspection assistant needs to explain when it cannot decide, preserve human control and invalidate obsolete results. A useful next observation can matter more than another confident answer. Reliable evidence also requires recording limits and failed attempts, not just successful screenshots.

## What's next
Complete the remaining privacy and recovery workflows; execute and record the meaningful AWS component; qualify real camera/kit combinations; compare against a manual checklist and fixed inspection policy with independent participants; and produce the final judge-accessible repository, technical report and five-minute demonstration. COOL integration and performance gains are not claimed. The product remains a prototype and is not approved for beta use.

## Preparation and assets

See [submission checklist](docs/DEVPOST-SUBMISSION.md) for actual form fields, testing instructions, video outline, screenshot shot list, eligibility questions and missing evidence. [Technical report](docs/submission/TECHNICAL-REPORT.md). No public demo or video link is available yet. [Repository](https://github.com/vijay-v-bhoyar/ProofPack) was created private; judge access remains required. The user requested leaving video blank. The local report archive is not uploaded because browser file access is disabled.
