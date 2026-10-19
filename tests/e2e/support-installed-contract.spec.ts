// Cross-language unit check against actual installed-service returns, not copied API fixtures.
import {readFileSync} from 'node:fs';
import {test,expect} from '@playwright/test';
import {supportDetail,supportInbox,supportNone} from '../../apps/web/src/supportHandoff';
test('frontend decodes actual installed handoff detail, inbox and no-request contracts',()=>{
  const capture=JSON.parse(readFileSync('evidence/local/support-ui-installed-contracts.json','utf8'));
  expect(capture.records.length).toBeGreaterThan(0);const kinds=new Set<string>();
  for(const row of capture.records){kinds.add(row.kind);
    if(row.kind==='detail')expect(supportDetail(row.value).inspection_id).toBe(row.value.inspection_id);
    else if(row.kind==='inbox')expect(supportInbox(row.value).requests.length).toBe(row.value.requests.length);
    else {expect(row.kind).toBe('none');expect(supportNone(row.value,row.value.inspection_id)).toBe(true);}
  }
  expect([...kinds].sort()).toEqual(['detail','inbox','none']);
});
