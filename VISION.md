# Product direction

## Outcome

Help a small hardware-kit business resolve uncertain visual checks before packing. One buyer: the owner. One daily user role: packing operator. Natural cadence: each order within a batch, not an assumed daily engagement target. The product must reduce useful inspection effort without increasing incorrect approvals.

## Five features

F1: approved recipes and camera enrollment. F2: OpenCV measurement and scene tracking. F3: bounded active inspection. F4: verifier states and evidence. F5: reviewed outcomes and regression replay. Their detailed acceptance criteria are in [PRD](PRD.md) and [feature specifications](docs/FEATURE-SPECS.md).

## Trust promise

A pass applies only to configured visible constraints in the most recent valid observation. It expires; it is not certification of hidden contents, material grade, thread specification, downstream packing or shipment. A human disposition is recorded separately and never changes the machine finding into a verified pass.

The system cannot authenticate the physical origin of arbitrary browser-provided pixels. Non-adversarial invited operators and a controlled webcam setup are the initial capture trust boundary. Challenge tokens prevent protocol reuse, not sophisticated video spoofing. Unobserved changes between sampled frames can occur; claims are explicitly bounded by observation frequency and result lifetime.

## Differentiation and moat hypotheses

Kit checking and photographs are established capabilities. Tulip's Laerdal case study describes checking parts against a bill of materials and capturing a reference photograph. These are vendor-reported capabilities, not independent ProofPack results or proof that competing products lack adaptive inspection. [Tulip case study](https://tulip.co/case-studies/laerdal-medical/).

ProofPack's differentiation hypothesis is that targeted separation, flat placement or recapture resolves visual uncertainty with less total operator effort than a strong fixed checklist. Demonstrate different outcomes for an overlapping pair and an actually missing part under equal capture/action budgets. Measure the benefit; do not claim invention of kit inspection or guaranteed prize odds.

| Candidate advantage | First-release mechanism | Evidence needed before claiming an advantage |
|---|---|---|
| Reviewed intervention data | Permissioned before/action/after/ground-truth/time tuples; offline policy replay | Better outcomes on untouched grouped data than the strong rule baseline, with equal budgets |
| Accepted recipe and qualification history | Immutable revisions, owner approval, execution lineage and portable export | Actual workflow adoption and measured replacement/requalification effort |
| Earned reliability history | Independent operator retests, adverse-case records and correction history separate from training labels | Repeated independently observed performance and buyer acceptance |

These are three conditional mechanisms, with zero proven moats. No proprietary dataset, customer dependence, exclusive distribution or earned trust exists. Keep records portable. Public OpenCV/AWS/COOL services, prompts, file hashes and generic logs are implementation tools. Do not count the same recipe knowledge again as a separate expertise or network moat.

Willingness to pay, error costs, setup tolerance, retention and an affordable route to customers remain unvalidated. Observe actual packing and purchasing decisions before expanding scope. If the workflow adds more burden than manual checking, the intended user benefit has failed.

## Success and stopping

Primary: correctly completed inspections per operator-hour, including configuration allocation, retakes and escalation. Secondary: incorrect-pass rate with denominators and uncertainty. Report unresolved coverage to prevent an always-abstain system from appearing successful. Kill condition: any known stale-context authorization defect; fix and retest before claiming verifier correctness.

The proposed 20% throughput improvement is an evaluation hypothesis, not a beta safety threshold or a predicted result. Failure to demonstrate advantage removes the advantage claim and triggers product review; it does not justify weakening test cases.

## Product ambition and sequencing

Build a maintainable product with qualified recipes, usable recovery and protected records. Sequence delivery into a controlled demonstration and a later supervised beta; neither substitutes for the other. Broader parts, multi-business hosting, robots, ERP/shipping automation, medical use and cross-customer learning are outside this release. They require a new scope decision and evidence.
