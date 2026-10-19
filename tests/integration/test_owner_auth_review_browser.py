"""Actual configured HTTPS/store/rendered auth review; synthetic provider/media only."""
from dataclasses import replace
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case
from test_owner_review_host import configuration
from test_owner_review_browser import REVIEW_BROWSER,exercise_configured_owner_review
from test_purpose_context_store import RUNTIME
from test_access_context_store import ACCESS
from test_auth_history_consumption_store import AUTH
from proofpack.evidence.owner_metadata_review import AuthReviewLimits

AUTH_REVIEW_BROWSER=REVIEW_BROWSER.replace(
 "  await expect(page.getByRole('table',{name:'Historical record counts; no cleanup authority'})).toBeVisible();",
 """  await expect(page.getByRole('table',{name:'Historical record counts; no cleanup authority'})).toBeVisible();
  await expect(page.getByText('Accounting policy: conservative-family-accounting-v5.',{exact:true})).toBeVisible();
  await expect(page.getByText('Supported authentication history was inspected.',{exact:false})).toContainText('Operational authentication policy remains unresolved');""")
assert AUTH_REVIEW_BROWSER!=REVIEW_BROWSER


def test_actual_configured_https_owner_v5_keeps_policy_held_then_cancels_without_erasure(world,publication_case,composition_case):
    review=replace(configuration(),auth_review=AuthReviewLimits(RUNTIME,ACCESS,AUTH))
    return exercise_configured_owner_review(world,publication_case,composition_case,
        review_configuration=review,browser=AUTH_REVIEW_BROWSER,receipt_name='configured-auth-review-browser.json')
