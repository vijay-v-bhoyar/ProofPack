"""Configured HTTPS/store/Chrome proposal; synthetic identity and CV specimens only."""
from dataclasses import replace
from pathlib import Path
import json,os
import test_owner_review_browser as baseline
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case
from test_owner_collateral_review import BOUNDS

def test_configured_https_collateral_scope_has_no_action_authority(world,publication_case,composition_case,monkeypatch):
    original=baseline.configuration
    monkeypatch.setattr(baseline,'configuration',lambda:replace(original(),collateral_limits=BOUNDS))
    marker="  await page.getByRole('button',{name:'Read historical accounting',exact:true}).click();"
    assert baseline.REVIEW_BROWSER.count(marker)==1
    addition="""  await page.getByRole('button',{name:'Read collateral scope proposal',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Historical collateral scope proposal',exact:true})).toBeVisible();
  await expect(page.getByText('Original inspection references: '+data.inspection+'.',{exact:true})).toBeVisible();
  await expect(page.getByText('Additional inspection references: none.',{exact:true})).toBeVisible();
  await expect(page.getByText(/Unknown obligations remain pending even when no additional inspections/)).toBeVisible();
  await expect(page.getByRole('button',{name:'Read collateral scope proposal',exact:true})).toBeDisabled();
  const retained=await page.evaluate(()=>JSON.stringify({...sessionStorage,...localStorage}));
  if(retained.includes('proposed_inspection_ids'))throw new Error('Proposal persisted as local authority');
"""
    monkeypatch.setattr(baseline,'REVIEW_BROWSER',baseline.REVIEW_BROWSER.replace(marker,addition+marker))
    baseline.test_actual_configured_https_owner_review_uses_published_cv_history(world,publication_case,composition_case)
    receipt=Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).with_name('configured-review-browser.json')
    result=json.loads(receipt.read_text());proposals=[r for r in result['responses'] if r['path'].endswith('/collateral-scope-proposal')]
    assert len(proposals)==1 and proposals[0]['status']==200
    assert result['server_thread_exited'] and result['application_closed'] and result['resource_drain_verified'] and result['ephemeral_tls_material_removed']
    receipt.with_name('configured-collateral-browser.json').write_text(json.dumps({**result,'scope':'actual configured local HTTPS/Chrome/DynamoDB collateral proposal and legacy accounting/cancellation; genuine synthetic CV history, synthetic trusted identity/bootstrap, intercepted STS/S3, test-only self-signed TLS bypass; no API response interception or provider/physical/human acceptance'},indent=2)+'\n')
