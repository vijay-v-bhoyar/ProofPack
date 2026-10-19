# OpenCV 5 pipeline and qualification

## Build identity first

Use Python 3.12 and an explicitly pinned OpenCV 5 build. Record `cv2.__version__`, `cv2.__file__`, `cv2.getBuildInformation()`, distribution/version or source commit, compiler flags, CPU architecture, loaded shared libraries and artifact hash. Fail application readiness if major version is not 5 or the tested APIs/modules are missing. OpenCV 5 changes module organization and has a C++17 baseline; port against its actual APIs rather than assuming an OpenCV 4 tutorial is exact. [OpenCV 5 documentation](https://docs.opencv.org/5.0/).

POC exit: load a known image, run calibration/rectification/contour primitives and reproduce expected geometric measurements on both the development machine and intended ARM runtime. Source fallback pins tag plus verified SHA and all build dependencies in an isolated build image; never invent a commit hash. Store artifact output for E02. COOL is optional; retain a plain upstream build for comparison.

## Pipeline stages and error budget

Current local implementation: `vision/calibration.py` verifies four distinct DICT_4X4_50 markers, enrolled displacement, planar residuals and ROI bounds before rectifying. `vision/tracking.py` compares consecutive and anchor frames, so cumulative drift cannot reuse an old scene generation. `vision/worker.py` admits one pending frame per worker and carries only bounded JSON bytes from child to parent; no decoder-origin pickle or pass authority. Full API/storage/physical integration remains incomplete; see [build status](BUILD-STATUS.md).

Worker controls in [controls](controls.yaml) are explicit development defaults: at most two per-runtime processes, 512 MiB/process, 30 seconds cumulative process CPU, 750 ms per-call wall deadline, one CV thread, bounded input/metadata/reply and contour/object counts. Five-second warmup occurs before capture admission; it does not extend permit freshness. Timeout/crash permanently closes that worker; the service must fence the station before explicit replacement. OS memory/CPU limits use Windows Job Objects or Linux rlimits; Linux/ARM execution still needs proof. These are resource bounds, not a complete filesystem/network sandbox. Native-process filesystem/egress/credential isolation must be enforced and tested on the target before release. The per-runtime pool is additional to durable station/capacity allocation, not a substitute.

The three synthetic recipes use explicit shape/blur/error thresholds and a rectilinear-lens profile. They do not qualify a physical camera, printed scale, reflective part or distorted lens. A physical lens needs actual qualification; non-rectilinear lens undistortion remains unimplemented. Scene thresholds (delta 12, zero changed pixels beyond it) are development settings, not calibrated real-camera tolerances.

Capacity is enforced per pool instance. Service wiring must own one pool per admitted runtime and separately enforce durable deployment allocation; that wiring remains incomplete. CPU seconds are cumulative per worker incarnation, not a renewed allowance on each frame. No replacement is automatic after timeout/crash.

1. **Capture admission:** validate authenticated station, permit, sequence, rate and byte limits. Decode only JPEG/PNG in a restricted worker; inspect actual format/dimensions; reject animation, oversized buffers and malformed files. Strip ancillary metadata from retained derivatives.
2. **Geometry:** locate all required markers and check their ordering/residuals. Undistort using enrolled lens parameters where needed; rectify only the enrolled plane. Detect camera/mat changes. A planar homography does not determine height or hidden geometry.
3. **Quality:** quantify blur, saturation/glare, clipped ROI, motion and inadequate pixels-per-mm. Thresholds originate from development data and are versioned with qualification results. Mark UNOBSERVABLE when outside the envelope; do not optimize thresholds on held-out cases.
4. **Segmentation:** controlled background and lighting first; connected components/contours and morphology. Keep an unknown-region mask. Merge/split ambiguity yields an action request, not guessed counts. Any learned detector is an optional later replacement subject to license, accuracy and runtime tests.
5. **Features:** contour area, perimeter, hole count, circularity, bounding dimensions and shape descriptors for the enrolled objects. Use measured physical references to map pixels to planar millimeters; carry error intervals. Require an interval entirely within the allowed recipe interval; overlap with a boundary is uncertain, not pass.
6. **Constraint evaluation:** expected counts, permitted broad variants, extras/unknowns and visibility. Never infer thread pitch, material grade, torque or concealed components from these features.
7. **Tracking/stability:** compare calibrated ROI and item associations; movement resets stability and increments scene generation. Re-evaluate constraints on every accepted observation; stable does not mean correct. Require the configured consistent observation window.
8. **Evidence:** return typed measurements, reason codes, masks/overlays, execution timing and version binding. Retain only selected before/after/decision frames under permission and retention rules.

## Data acquisition without current hardware access

`python scripts/generate_fixtures.py` creates immutable `fixtures/synthetic/v1`; `--verify` checks paths, provenance and hashes without replacement. There are 144 DEVELOPMENT episodes across 24 setup groups, with paired complete/missing/wrong-silhouette/overlap/white-occluder/post-removal cases. They are not 144 independent physical setups or the untouched holdout in the evaluation plan. `python scripts/evaluate_synthetic.py` records every single-frame finding and failure in local evidence. No throughput/adaptive advantage is inferred; public licensing remains an owner decision.

- Synthetic images: deterministic seeds, ground-truth object masks/counts and controlled blur/glare/occlusion transforms. These verify algorithms/contracts, not real-camera performance.
- Printable mat and paper fixtures: validate capture flow, perspective and protocol in a webcam session if one is available. Record them as PRINTABLE, never hardware.
- Physical qualification: acquire/borrow actual washers/nuts/bolts/brackets and a ruler only after owner arrangements; record specimens, measurement method, lighting and camera. No acquisition is assumed complete or charged by this plan.
- Operator pilot: recruit an actual packing operator through user-authorized outreach. No contact is sent now. Without these steps, demonstration labels remain synthetic/controlled and beta is blocked.

## Qualification record

T35/T36/T41 verifies that approved reference assets remain permitted/available and that qualification matches the active versions. T44 exercises tolerance-edge and empty/unknown cases plus crop, orientation, mirroring and normalized-overlay coordinate transforms. T46 checks original permit/acceptance ticks after worker/storage delay; no delayed pipeline stage can extend the effective deadline. Use [state contracts](STATE-DATA-API.md) and [workflow acceptance](WORKFLOW-COVERAGE.md) for runtime/data-authority fencing and fixture coverage.

Per recipe/camera: reference object measurements, supported dimensions/angles/lighting, at least complete/missing/wrong/extra/overlap/glare cases, measurement residual distributions, unknown/review behavior and failures. Document maximum reliable discrimination rather than inventing a millimeter accuracy target. Real observations must include changes of session and operator, not only adjacent frames. Approval is specific to that envelope; outside it, abstain.

## COOL experiment

Run plain OpenCV 5 and COOL on equivalent Graviton hardware with the same inputs, CPU threads, build settings where feasible, and output tolerances. Record vendor-version differences and any non-equivalent algorithm implementations. Use both isolated kernels and the full inspection workflow; the latter includes decoding, upload, storage, orchestration and operator effort. Repeat warm/cold samples, record all exclusions and raw timings; quantify uncertainty. Include Marketplace charges in cost; do not assume Free Tier credits cover them.

The current listing describes COOL 3.1 on OpenCV 5 with Arm AMI delivery; this does not prove the installed application used it. Record runtime library provenance and actual executed functions. Never claim a published vendor speedup as this product's measurement. [COOL Marketplace](https://aws.amazon.com/marketplace/pp/prodview-fdvbfiewzuehs), [official benchmark examples](https://github.com/opencv/COOL-Benchmark).

Reference intake now has a separate `reference` child operation in the same bounded process pool: validate type/single-frame/orientation/byte/pixel/side limits, then encode a metadata-free canonical JPEG. Parent-side provenance binds input hash, stored hash, dimensions and bounded byte length; it never decodes the image. This diagnostic cannot produce findings, calibration qualification, physical-origin certification or a pass. Existing scene/inspection worker fences remain unchanged; local tests use synthetic files and are not physical or ARM proof.

## Current local mat/enrollment diagnostics

`vision/mat.py` renders the fixed 800 by 500 nominal desktop-v1 grid at fourfold PNG scale with 304.8 DPI metadata and a 100 mm ruler outside its work area. The nominal 600 by 300 work area represents 200 by 100 mm. `vision/calibration_diagnostics.py` derives or checks geometry, marker displacement, reprojection and focus with explicit settings in the bounded child. Actual print scale, physical uncertainty, lens distortion and supported scene envelope still require independently measured evidence; metadata and synthetic test results cannot establish them.

Immutable calibration revisions and case reports bind source hashes, data/runtime/build identity and purpose expiry. Actual accepted/rejected outcomes and mismatches remain inspectable. Approval is separate from diagnostics and physical assurance remains separately required for beta. See STATE-DATA-API, TEST-PLAN and BUILD-STATUS; no new physical accuracy claim is made.

## Measured correction references — current local implementation

F3 retains unknown nonconvex multi-hole silhouettes as possible touching/overlap instead of declaring a supported flat bracket. Optional owner-enrolled flat-reference aspect bounds use oriented contour lengths with the enrolled planar error; an interval outside or straddling those bounds, or unbounded by that error, remains UNOBSERVABLE before count decisions. This is planar projection evidence, never 3D pose. Legacy recipes omit the optional field and do not infer flatness from free text.

Typed worker targets and output dimensions are checked against the actual profile. Publication binds their result/crop/source/calibration digest to observation, retained crop and action. Protected reads reconstruct the binding before exposing coordinates; original images and owner-only metadata receive no crop overlay. The operator opens a stopped-camera historical reference and then obtains fresh same-kit evidence after acknowledgment. Numbered boxes/text never overlay the moving scene, grant pass authority or refund attempts. Exports retain only bounded provenance/action-index summaries and must match the actual recorded action; no private result JSON or coordinates. Selected native, rendered and offline installed-package checks pass; BUILD-STATUS owns exact results and remaining whole-product obligations. Synthetic contours and local checks do not qualify physical kits or beta users.
