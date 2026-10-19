# Operator and reviewer experience

Two surfaces: operator station and owner/reviewer workbench. Desktop webcam first. No public enrollment flow. Quality, status and next action must be understandable without seeing implementation details.

Design each surface and its recovery paths against the [persona operations](PERSONAS-OPERATIONS.md). Core personas P01–P03 use these surfaces; supporting/evaluation responsibilities use explicitly granted existing roles, operational tools or sanitized artifacts rather than additional product modules.

## Operator station

1. Sign in; select approved recipe and station. Show camera/privacy explanation before permission.
2. Check mat alignment and physical scale; reject unsupported setup with a clear corrective instruction.
3. Start a new inspection with opaque kit reference. Show the exact transmitted calibrated capture rectangle (including enrolled mat markers), the smaller retained work ROI, and expected counts. Crop the camera source to that calibrated rectangle; do not imply only retained crop pixels are transmitted.
4. Highlight one unresolved region and one action. Acknowledge, then reacquire; never let acknowledgment alone clear a finding.
5. Show current visible-check result with observation time and an expiring indicator. On lost visibility: clear green status and show Recheck required.
6. Record a human disposition or close a historical record. Explain that the station does not authorize shipment.

Statuses use text plus icon, never only red/green. Keep overlays outside critical details; provide a findings list usable without interpreting colors. Planned targets: >=16px main text, >=44px primary touch/click targets, visible focus, 4.5:1 normal-text contrast and keyboard completion without traps. These targets require measured/rendered verification, including Windows high contrast and 200% zoom.

## Recovery copy

The operator workspace loads only after an explicit open action and authenticated `/me`; owner/reviewer roles do not inherit packing controls. Show empty/denied/dependency states and paginated approved stations/recipes. Acquisition, takeover acknowledgment and unresolved-work disposition are explicit. An owned active inspection can be resumed under its originating session; do not silently create replacement records or reset budgets. Read the server capture context before requesting camera access. The default unconfigured app remains unavailable.

Camera permission requires an explicit start action. Preview the context-v1 centered crop at its enrolled resolution, without upscaling/mirroring. Confirm the whole transmitted rectangle and manual double-check before starting the two-observations/second loop. Obtain each permit before capturing a subsequent actual video frame; one upload at a time. Keep authority and raw frame/Blob buffers in memory, never local/session storage. Stop tracks and clear buffers/approval on stop, logout, hidden/offline page, source loss, geometry mismatch or failed requests. Local motion checks and server leases are conservative sampled safeguards, not physical interlocks.

Re-read the operator session and inspection context immediately before requesting camera permission. Stop cancels the logical permission wait even if the browser prompt is unanswered; a subsequent late grant closes its own tracks and never reopens preview. Arrange an occupied-station handoff explicitly and provide its acknowledgment/reason before acquisition. During checking, show the result beside the preview; keep per-constraint findings labeled as historical unless the observation is current. The present correction outline covers the qualified work area; part-specific localization remains incomplete.

Use a monotonic request-start bound for returned remaining lease, avoiding a fresh full lease after network delay. Expired or late results cannot restore approval or restart capture after a stop/context change. Unknown outcomes require a status refresh and explicit recovery; no automatic mutation retry. Closing an unresolved inspection needs a distinct human disposition and reason; an offline logout stops capture but remains unconfirmed until the server acknowledges it. Automated fixture browser tests establish only the exercised rendering/API contract, not real login, webcam, human comprehension or beta readiness.

| Condition | Message/action |
|---|---|
| Camera denied or unavailable | Explain browser permission/device selection; stop capture; retry explicitly |
| Glare/overlap | Show one validated action and the affected region |
| Network loss or slow frames | Recheck required; keep no current approval; reconnect then new observations |
| Recipe/camera changed | Configuration changed; restart inspection using current approved version |
| Planner failed | Cannot choose another check; request human review |
| Evidence store failed | Result could not be recorded; no verified result issued |
| Unsupported part | Cannot verify this part with the current recipe |

## Workbench

Recipe editor exposes constraints, limits and qualification failures before approval. Outcome review displays same-kit before/action/after with provenance and label history. Evaluation view shows denominators, all failures, synthetic/physical flags and independent/non-independent reviewers. Promotion/rollback shows affected sessions and tests. Export makes omitted/deleted media visible. Human overrides are labeled separately in every view.

## Rendered checks

Implement the applicable [experience contracts and A01–A09](USER-NEEDS-ADOPTION.md) under existing requirements; N08 remains research-first. Offer a disclosed practice task with an uncertainty/recovery example, capture/data explanation and stop/help route before ordinary work. Use explicit guidance/access preferences, not guessed emotions. Rendered controls do not establish human comprehension or usability. Collect suitable participant evidence separately, including access needs not covered by automated checks.

T58 adds full owner-only, operator-only, reviewer-only and explicitly combined-role journeys: invitation/recovery, reference/calibration approval, station release/takeover, manual escalation, label correction, job cancellation, export denial/expiry, privacy request handoff and sign-out. There is no implicit role inheritance. Bind overlays to the processed frame/coordinate transform and never present a pending frame as newly verified. While waiting, preserve the last verified observation time and never extend its deadline; clear it on detected change/expiry. Test failed/uncertain logout explicitly: stop local capture and report server revocation as unconfirmed until acknowledged, rather than falsely promising global sign-out while offline.

Playwright tests at 1366x768 and 1920x1080, 200% zoom, high contrast, keyboard only and reduced motion. Verify clipping, overlay readability, dialog focus return, long error messages, interrupted uploads, disabled submit state and stale-result expiry. Camera fixture tests are separate from a real desktop webcam session. Collect screenshots/video with actual viewport/browser versions; DOM visibility alone is insufficient. Required T27/E11.


## Workbench metadata journeys

Local owner/reviewer/invitee components now support explicit grant/notice choices, masked ephemeral invitation capabilities, account/resource version review, failed qualification inspection, inactive drafts and explicit owner approval/retirement. Runtime enablement reviews existing assurance and remains distinct from beta GO. Current source-bound Chrome fixtures exercise keyboard focus/tab order, zoom/forced colors, notice failure/change, grant changes, delayed/interrupted expiry and unconfirmed sign-out/retry. See BUILD-STATUS for actual current results; automated fixtures do not establish human comprehension or full WCAG conformance.

Returning from inspections stops camera tracks and preserves server work for explicit resume. The workbench exposes no camera control. Busy work disables navigation; errors identify unconfirmed outcomes rather than presenting success. A successor may decline to accept ownership; a pending invitee can decline without capability, optional reuse or working notice delivery. Pending invitations and first-use grants do not imply permission to inspect. Reference/evaluation/privacy/recovery journeys remain incomplete and require separate implementation/testing.
