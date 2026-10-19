# Agent behavior blueprint

Mode: application design from current requirements. No expert interview or operational transcript exists. The decision table below contains inferred judgments to validate with a packer; it is not expert interview evidence.

## Topology and responsibilities

One bounded planner, tool executor and deterministic verifier inside one application. This is separation of responsibilities, not a fleet of autonomous agents. The vision module measures; planner selects next evidence; executor validates/contracts actions; verifier controls current status; human reviewer adjudicates unsupported cases and approves future changes.

Use an observe/action/reinspect loop because a physical action changes subsequent evidence. Stable configuration steps are deterministic. Offline reflection is structured label review and regression testing; no uncontrolled memory-driven changes. No model judge approves a pass, and no second model is required merely to look sophisticated.

## Memory

Use the [workflow coverage map](WORKFLOW-COVERAGE.md), especially W09/W10/W15/W16/W18, for decision, authorization, poisoning and recovery cases. Full integrated acceptance remains NOT_RUN; [build status](BUILD-STATUS.md) distinguishes executed local component checks.

Working: current observation, unresolved constraints, eligible actions, remaining budget and version bindings; cleared when inspection closes. Episodic: reviewed action/outcome tuples, segregated by deployment and approved purposes. Reference: immutable recipe, calibration, allowlist and policy version. Never persist private chain-of-thought, provider credentials, continuous video or unreviewed free-text instructions as future policy.

## Tool contracts

| Tool | Input | Output | Budget/failure | Verification |
|---|---|---|---|---|
| measure_current | Inspection and accepted observation IDs | Typed constraints/quality/objects | 500 ms p95 target; worker timeout -> review | Check epoch, versions, sequence, fresh frame and build |
| select_action | Current findings and eligible action IDs | Constrained action proposal | Optional model <=3 s/256 output tokens; otherwise deterministic | Reject unknown enum, unbound ROI or stale finding |
| request_operator_action | Validated action/observation IDs | Durable action and UI template | Two corrective requests total | Atomically count once; verify action can address constraint |
| reinspect | New capture permit/frame after action | New typed observation | Same measurement limits | Do not reuse earlier image/result as fresh |
| record_review | Human disposition, reason and current binding | Separate review event | Authorized human only | No change to machine verification state |

Planner-facing contract has no network URL, command execution, recipe mutation or direct storage tool. Raw OCR/label text is not needed; if later introduced, it remains data and cannot override instructions. Tool output must validate before it reaches the planner or verifier.

The optional model returns only the allowed action/constraint/ROI fields. Reject extra free-text or instruction fields. Construct the displayed/logged decision summary from validated findings and server-owned templates; do not copy raw model prose, prompts or private reasoning into the UI or evidence export.

## Optional model integration

Use Amazon Bedrock through the application IAM role only if a regional, tool-capable model is approved and available. Do not name an unverified model ID or assume cross-region inference is acceptable. Validate model availability, residency, terms and price in the actual account. Model sees compact numeric findings and candidates, not raw operator images, unless separately approved. Client-side tool execution remains subject to application validation. [Bedrock tool-use reference](https://docs.aws.amazon.com/bedrock/latest/userguide/tool-use.html).

Default deterministic policy is both a fallback and a strong comparator. Name the actual mode in every trace. An agentic entry must demonstrate conditional orchestration with tool results influencing later actions; a fixed scripted video or a commentary-only chatbot is inadequate. Do not imply an LLM was used in deterministic runs.

Before a model call, reserve a durable decision ID bound to inspection version and observation. Permit at most one planner call in flight per station and two model requests per inspection, as defined in [controls](controls.yaml). Duplicate observations, reloads and retries reuse the reservation/result. A timeout or invalid output leads to REVIEW_REQUIRED; uncertain provider completion consumes its reservation and is not retried automatically. The separate corrective-request budget is charged when the operator action is issued. No additional model call is required to verify the second correction.

Also reserve against a target-approved deployment inference allowance with bounded input/output estimates before provider invocation. Repeated new inspections and runtime restart cannot reset that accounting. Missing model/price/allowance authorization disables paid inference; deterministic operation remains available where verifier conditions permit. Billing alerts are not a hard spending cap. T09/T49 covers reservations and uncertain completion.

The proposed token limits in controls include the fixed prompt/tool schema and findings, not only generated text. Reject oversized input instead of silently dropping required constraints. Actual adapter token accounting, model support and cost basis must be approved/tested before enabling inference; unset allowance fields remain a denial.

A delayed proposal is advisory. Publishing requires the latest fresh eligible observation, unchanged runtime/session/scene/recipe/calibration/policy and the same pending decision, then a CAS of the current state version. Validate ROI against that observation and record source plus validation IDs. If later measurement resolved the case or it closed/changed/revoked, discard the proposal without overwriting state or refunding uncertain usage. Measurement/verifier never wait for it. Timeout escalates only if the decision is still current and unresolved. T45 covers this branch.

## Trace fields

trace_id, inspection_id, observation_id, software/recipe/calibration/policy versions, policy mode/model ID if any, quality cues, eligible actions, selected action, concise public decision summary, tool inputs/outputs (redacted), duration, budget used, verifier result and escalation reason. Provider request ID and usage/cost counters contain no API secrets. Trace coverage is an eval, not an assumption.

## Discovery prompts and their design impact

Ask an actual packer to walk through a missing-part check; record which cues distinguish missing from obscured. Ask when they would stop trusting a camera; convert answers into quality gates. Stage a wrong-size component; learn the minimum useful dimension distinction. Interrupt a check; learn recovery expectations. Ask which records they actually retain; avoid speculative workflow dependence. Each answer must become a named requirement/change plus test, or be marked informational.

No contact is authorized by this document. Pilot access remains missing. Design decisions can proceed using explicit assumptions; beta sign-off cannot.


## Operator decisions to validate

| Step | Signal | Assumption | Decision / strategy | Failure and verification | Design consequence | Evidence status |
|---|---|---|---|---|---|---|
| Configure recipe | BOM and specimens | Visible variants separable | Choose observable constraints; Validation plus human qualification | Infer hidden properties; Physical reference measurement | Immutable recipe | Requirements; expert validation missing |
| Calibrate camera | Markers scale lighting | Printed scale and plane correct | Accept envelope; Geometry checks | Print scaling or raised parts; Known-length residual | Versioned calibration | Design; physical validation missing |
| Inspect ambiguity | Overlap glare uncertainty | Action can resolve ambiguity | Choose next observation; Observe-act-reinspect | Missing confused with obscured; Fresh same-kit evidence | Bounded planner | Design; packer interview missing |
| Verify correction | New features and bindings | Current scene correctly bound | Issue or withhold status; Deterministic verification | Old approval survives change; Fence version and lease | No planner pass authority | R09 and R10 |
| Recover interruption | Loss timeout or change | Old evidence is historical only | Invalidate and restart; Human handoff | Reuse old result on reconnect; Adversarial sequences | Fail closed | Requirements; runtime proof missing |
| Learn outcomes | Reviewed action tuple | Ground truth permissioned | Approve revision; Offline replay | Leak test data; Grouped untouched holdout | No online self-modification | Moat hypothesis |
| Decide beta | Physical/user/ops evidence | Evidence supports supervised use | GO or NO_GO; Human evidence review | Treat synthetic as real; Exact-target gates | Named release owner | User has no kits/operators |
