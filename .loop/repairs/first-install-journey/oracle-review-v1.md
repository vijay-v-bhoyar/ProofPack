# Decline protocol oracle correction — independent acceptance pending

Original run: three cases/nine phases; accept and wrong-notice passed; decline failed because its post-decline account read returned401 rather than the test's403. The original whole test is retained in original-oracle-v1.py and the output in evidence/local/fresh-enrollment-models-first-install-journey-baseline-v1. There was no observed application security defect.

Source contract: auth/http.py decline explicitly deletes COOKIE for a restricted invitee after decline. actor resolves an absent/invalid cookie to HTTP401; only an authenticated restricted invitation session receives403 for missing membership. auth-http-v1.py preserves that source. No application behavior is changed to accommodate the test.

Candidate correction requires both absence of the restricted cookie and exactly401 after decline. Every other original assertion remains unchanged. This strengthens signed-out verification and aligns the specific status with the existing authentication contract; it does not accept either status generically, remove the denial or waive membership checks.

P06 must separately review the original output, preserved source and replacement contract before treating the original defective-oracle finding as independently accepted. Implementing-agent inspection is not independent approval, and the portable repair helper cannot waive oracle identity. Candidate test passes may establish their stated local scope; do not label the original whole-file oracle unchanged/passed or a product repair closed. Native/provider/physical/human and full-suite acceptance remain separate.
