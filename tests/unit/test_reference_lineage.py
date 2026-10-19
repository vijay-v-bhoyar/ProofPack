"""Synthetic complete reference transaction histories; not rights or storage proof."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import pytest
from botocore.client import BaseClient

from test_capture_lineage import uid, DEPLOYMENT
from proofpack.auth.service import HEAD, RUNTIME
from proofpack.evidence.repository import Key, Row, Write
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.evidence.reference_lineage import discover, ReferenceLimits, ReferenceHistoryHeld
from proofpack.runtime.control import DATA

LIMITS=ReferenceLimits(32,1_000_000,64,1000)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*a,**k):raise AssertionError('pure reference history invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def linked(operation,writes,checks):
    prepared,_=prepare_linked(DEPLOYMENT,operation,writes,checks)
    return {w.key:Row(w.key,1 if w.expected_revision is None else w.expected_revision+1,w.data) for w in prepared}


def family(state='linked',*,asset_changes=None,receipt_changes=None,target=None):
    ident=uid(801);owner=uid(3);session=uid(4);purpose=uid(2)
    ikey=Key('state','reference-intent#'+ident);opkey=Key('state','idempotency#'+'f'*64)
    akey=Key('state','asset#'+ident);accesskey=Key('events','access#'+uid(810));eventkey=Key('events','reference#'+uid(811))
    context=(Row(HEAD,1,{'version':1}),Row(RUNTIME,1,{'runtime_epoch':1}),Row(DATA,1,{'epoch':1,'changed_at_ms':100}),
        Row(Key('state','purpose#'+purpose),1,{'id':purpose}),Row(Key('state','user#'+owner),1,{'id':owner}),
        Row(Key('state','session#'+session),1,{'id':session}),Row(Key('state','cookie#'+'c'*64),1,{'session_id':session}))
    raw={'id':ident,'kind':'reference','status':'reserved','asset_id':ident,
        'key':'deployments/'+DEPLOYMENT+'/references/'+ident,'purpose_id':purpose,'source_sha256':'a'*64,
        'context_sha256':'d'*64,'owner_user_id':owner,'session_id':session,'runtime_epoch':1,'data_epoch':1,'created_at_ms':100}
    if target is not None:raw.update(target)
    first=linked('reference-upload',(Write(ikey,None,raw),Write(opkey,None,{'body_hash':'d'*64,'result':{'id':ident,'status':'processing'},'at_ms':102}),
        Write(accesskey,None,{'kind':'reference-upload','actor_scope':'e'*64,'at_ms':101,'session_id':session})),context)
    root=first[ikey];op=first[opkey];access=first[accesskey]
    if state=='reserved':return root,(op,access)
    if state!='failed_reserved':root=Row(ikey,2,{**root.data,'status':'writing','stored_sha256':'b'*64,'stored_byte_length':256})
    if state=='writing':return root,(op,access)
    if state.startswith('failed_'):
        result=linked('reference_failed',(Write(opkey,1,{**op.data,'result':{'id':ident,'status':'failed'}}),
            Write(ikey,root.revision,{**root.data,'status':'needs_reconciliation'})),())
        return result[ikey],(result[opkey],access)
    assert state=='linked'
    receipt={'asset_id':ident,'key':raw['key'],'version_id':'PRIVATE_VERSION','source_sha256':'b'*64,
        'context_sha256':'d'*64,'byte_length':256,'content_type':'image/jpeg',**(receipt_changes or {})}
    asset={'storage_binding_sha256':'9'*64,'id':ident,'kind':'reference','status':'committed','read_denied':False,
        'sha256':'b'*64,'source_sha256':'a'*64,'width':64,'height':64,'byte_length':256,'content_type':'image/jpeg',
        'object_receipt':receipt,'purpose_id':purpose,'source_permission_reference':'source-owned-1','data_origin':'synthetic',
        'origin_basis':'owner_declaration','physical_truth_verified':False,'expires_at_ms':1000,
        'owner_user_id':owner,'created_at_ms':110,**(asset_changes or {})}
    result=linked('reference_committed',(Write(akey,None,asset),Write(DATA,1,{'epoch':2,'changed_at_ms':120}),
        Write(ikey,2,{**root.data,'status':'linked','object_receipt':receipt}),
        Write(opkey,1,{**op.data,'result':{'id':ident,'status':'committed'}}),
        Write(eventkey,None,{'kind':'reference_committed','asset_id':ident,'purpose_id':purpose,'actor_scope':'e'*64,'at_ms':120})),
        (*context,op,root))
    return result[ikey],(result[opkey],access,result[akey],result[eventkey])


def run(root,rows,**changes):
    return discover(root,rows,**(dict(deployment=DEPLOYMENT,limits=LIMITS,deadline_ns=1000,tick=lambda:1,checkpoint=lambda:None)|changes))


@pytest.mark.parametrize('state',['reserved','writing','failed_reserved','failed_writing','linked'])
def test_exact_supported_histories_preserve_uncertainty_and_never_grant_scope(state):
    root,rows=family(state);before=deepcopy((root,rows));result=run(root,rows)
    assert result.state==root.data['status'] and len(result.records)==len(rows)
    assert result.intent.key==root.key and result.dependencies
    assert 'INSPECTION_ORIGIN_NOT_RECORDED' in result.obligations
    assert 'REQUEST_PREIMAGE_NOT_RETAINED' in result.obligations
    assert 'STORAGE_TARGET_NOT_RECORDED' in result.obligations
    assert bool(result.media)==(state=='linked')
    assert ('STORAGE_RECONCILIATION_REQUIRED' in result.obligations)==(state!='linked')
    assert before==(root,rows) and not hasattr(result,'inspection_ids') and not hasattr(result,'can_delete')
    assert all(s not in repr(result) for s in ['deployments/',uid(801),'PRIVATE_VERSION'])
    with pytest.raises(FrozenInstanceError):result.state='linked'


@pytest.mark.parametrize('index',range(4))
def test_every_committed_family_output_is_required(index):
    root,rows=family()
    with pytest.raises(ReferenceHistoryHeld):run(root,rows[:index]+rows[index+1:])


@pytest.mark.parametrize('field,value',[
    ('read_denied',True),('physical_truth_verified',True),('origin_basis','independent'),('kind','frame'),
    ('width',2001),('height',True),('byte_length',True),('data_origin','unrecognized'),
    ('owner_user_id',uid(99)),('purpose_id',uid(99)),('source_sha256','8'*64),('sha256','8'*64),
    ('expires_at_ms',100),('content_type','image/png'),('extra','private'),
])
def test_resealed_but_invalid_business_metadata_never_passes(field,value):
    root,rows=family(asset_changes={field:value})
    with pytest.raises(ReferenceHistoryHeld):run(root,rows)


@pytest.mark.parametrize('field,value',[
    ('key','foreign/key'),('version_id','null'),('version_id','contains space'),('byte_length',True),
    ('source_sha256','8'*64),('context_sha256','8'*64),('asset_id',uid(99)),('content_type','image/png'),
])
def test_resealed_receipt_must_match_original_target_version_and_normalized_bytes(field,value):
    root,rows=family(receipt_changes={field:value})
    with pytest.raises(ReferenceHistoryHeld):run(root,rows)


@pytest.mark.parametrize('fault',['duplicate','extra','foreign_deployment','root_revision','result','binding'])
def test_missing_or_conflicting_identity_and_provenance_holds(fault):
    root,rows=deepcopy(family())
    if fault=='duplicate':rows=(*rows,rows[0])
    elif fault=='extra':rows=(*rows,Row(Key('state','unknown#opaque'),1,{'private':True}))
    elif fault=='root_revision':root=replace(root,revision=True)
    elif fault=='result':rows[0].data['result']['id']=uid(99)
    elif fault=='binding':rows[1].data['resource_bindings']['writes'][0]['sha256']='8'*64
    with pytest.raises(ReferenceHistoryHeld):run(root,rows,**({'deployment':'foreign'} if fault=='foreign_deployment' else {}))


@pytest.mark.parametrize('field',['max_records','max_payload_bytes','max_dependencies','max_work'])
def test_independent_exact_limit_and_one_below(field):
    root,rows=family();result=run(root,rows)
    used={'max_records':len(rows)+1,'max_payload_bytes':result.payload_bytes,
        'max_dependencies':len(result.dependencies),'max_work':result.work}[field]
    assert used>1 and run(root,rows,limits=replace(LIMITS,**{field:used}))==result
    with pytest.raises(ReferenceHistoryHeld):run(root,rows,limits=replace(LIMITS,**{field:used-1}))


@pytest.mark.parametrize('clock',[lambda:True,lambda:-1,lambda:1000])
def test_invalid_or_expired_original_clock_holds(clock):
    with pytest.raises(ReferenceHistoryHeld):run(*family(),tick=clock)


def test_order_independence_and_detached_result():
    root,rows=family();result=run(root,rows)
    assert run(root,tuple(reversed(rows)))==result
    rows[0].data['result']['id']=uid(99)
    assert result.intent.key==root.key and uid(99) not in repr(result)
