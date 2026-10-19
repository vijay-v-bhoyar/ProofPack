# ProofPack

ProofPack is an in-development assistant for checking configured visible kit contents. The first release targets one business, invited users and desktop webcams. It does not authorize shipping, replace manual checking or verify hidden properties.

**Full product acceptance is incomplete; beta remains NO_GO.** The [build status](docs/BUILD-STATUS.md) owns current implementation, exact source-bound verification, retained failures and remaining work. Local/synthetic checks do not establish actual AWS, physical-kit or human-use acceptance. An AWS account exists, but the authorized deployment target and spending limit remain unresolved; physical kits and packing operators are unavailable.

[Personas](docs/PERSONAS-OPERATIONS.md#persona-inventory) defines nine responsibility profiles and 78 operations, plus affected non-users. Select a linked persona name in that inventory to open its complete operation map. The [current adoption decision](docs/USER-NEEDS-ADOPTION.md#current-improve-decision--october-18-2026) separates local mechanisms, untested human needs and release conditions. This overview points to canonical status instead of duplicating changing test counts.

## Product and delivery

- [Current implementation and verification status](docs/BUILD-STATUS.md)

- [Product direction and differentiation](VISION.md)
- [Requirements and canonical traceability](PRD.md)
- [User personas and end-to-end operations](docs/PERSONAS-OPERATIONS.md)
- [User needs, experience evaluation and adoption decisions](docs/USER-NEEDS-ADOPTION.md)
- [Complete workflow and test coverage](docs/WORKFLOW-COVERAGE.md)
- [Architecture](ARCHITECTURE.md)
- [Implementation plan and delivery evidence](IMPLEMENTATION-PLAN.md)
- [Canonical task backlog](BACKLOG.md)

## Implementation specifications

- [All five features](docs/FEATURE-SPECS.md)
- [State, data and API contracts](docs/STATE-DATA-API.md)
- [OpenCV 5 pipeline](docs/OPENCV-PIPELINE.md)
- [Agent design and operator decisions](docs/AGENT-DESIGN.md)
- [AWS integration and cost/deployment plan](docs/AWS-DEPLOYMENT.md)
- [Proposed numeric controls](docs/controls.yaml)

## Verification and beta operation

- [Testing and evaluation](docs/TEST-PLAN.md)
- [Security, privacy and AI Red Team evaluation](docs/SECURITY-PRIVACY.md)
- [UX and accessibility](docs/UX-ACCESSIBILITY.md)
- [Beta readiness gates](docs/BETA-READINESS.md)
- [Beta user guide](docs/BETA-USER-GUIDE.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Decisions and dependencies](docs/DECISIONS.md)

## Hackathon and records

- [Saved Devpost draft and submission checklist](docs/DEVPOST-SUBMISSION.md)
- [Submission technical report](docs/submission/TECHNICAL-REPORT.md)
- [Rules, judging criteria and required evidence](docs/HACKATHON-EVIDENCE.md)
- [Sources](docs/SOURCES.md)
- [Technical report template](docs/templates/TECHNICAL-REPORT.md)
- [Demo script](docs/templates/DEMO-SCRIPT.md)
- [Beta session record template](docs/templates/BETA-SESSION-RECORD.md)
- [Evidence ledger](evidence/index.json) and [schema](docs/contracts/evidence.schema.json)

## Document ownership and status

The Git repository contains maintained project files and referenced evidence. Large generated execution workspaces, dependency bundles and raw captures remain local; nested raw-run references in retained receipts may therefore not resolve from a clone. No omitted run is treated as passed. Git attributes preserve exact bytes for evidence hashes.

VISION owns positioning; PRD owns requirements and their traceability; BACKLOG owns task dependencies and estimates. PERSONAS-OPERATIONS owns human responsibilities and workflow handoffs. Feature specifications and state/API contracts define behavior. Controls owns numeric defaults; the evidence ledger owns actual execution status. Decisions records confirmed choices and unresolved inputs. Update these canonical owners together when a change affects their contracts.

WORKFLOW-COVERAGE maps all nine personas and 78 operation steps to 26 workflow contracts and T01–T58. TEST-PLAN owns case prerequisites/stimuli/oracles; evidence planned IDs are separate from actual child-case results. Documentation coverage does not establish runtime correctness or an executed beta gate.

These documents specify an application under implementation. Templates remain blank because their participant sessions/results have not occurred. The AI Red Team skill informed the attack/evaluation plan; planned application probes remain distinct from executed component checks. The Agentic Product Loop skill informed delivery review and a discovery check; its admitted runner execution remains NOT_INITIALIZED. Their boundaries and evidence requirements are stated in the security document and implementation plan; current implementation and verification are recorded in BUILD-STATUS.

## Documentation validation

Local backend checks include a pinned DynamoDB Local emulator. Install Java 17+ and run `python scripts/dynamodb_local.py --install` with the project environment before the full verification command. The [build status](docs/BUILD-STATUS.md) distinguishes these local tests from remaining integration work and actual AWS/physical evidence.

USER-NEEDS-ADOPTION owns contextual findings, participant incentives and research coverage, experience contracts, A01–A09 evaluation scenarios, adoption gates, claim dependencies and the prepared whole-task comparison protocol. Start with its current decision and [review navigation](docs/USER-NEEDS-ADOPTION.md#use-this-review). Dated historical checkpoints retain their original scope; human evaluation remains NOT_RUN. This work refines existing requirements and tasks; it does not add access roles or imply participant validation.

Run `python docs/contracts/validate_documentation.py` with Python, PyYAML and jsonschema installed. The [validation receipt](evidence/documentation-validation.json) records versions, checks and input hashes. The validator checks local links, inventories, dependencies, traceability, evidence schema and retained-file boundaries. It does not establish application, AWS, physical, user or release readiness.
