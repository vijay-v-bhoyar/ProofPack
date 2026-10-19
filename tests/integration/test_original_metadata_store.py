"""Actual local capture and erasure denial; intercepted object protocol, no AWS proof."""
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_original_frames import original_case
from proofpack.evidence.originals import validate_original_source
from proofpack.evidence.repository import Key,Write,StoreUnavailable
from proofpack.evidence.erasure import AssetErasure
from proofpack.evidence.erasure_models import ErasurePreview,ErasureConfirmation

@pytest.mark.parametrize('selected',['crop','original','both'])
def test_exact_private_metadata_survives_real_erasure_admission_but_reads_stay_denied(world,original_case,selected):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();repo=world[1];crop_id=ob.data['asset_id'];original_id=ob.data['original_asset_id']
    ids=(crop_id,original_id) if selected=='both' else (crop_id if selected=='crop' else original_id,)
    service=AssetErasure(reads.purposes,objects,reads.references,review_ms=30000,jobs_per_minute=8,lease_ms=15000,version_page_size=3)
    preview=service.preview(world[5],request=ErasurePreview(asset_ids=ids),idempotency_key='metadata-preview')
    request=ErasureConfirmation(preview_id=preview['id'],confirmed_digest=preview['scope_sha256'],
        erase_asset_versions_acknowledged=True,understands_remaining_metadata_and_backups=True)
    job=service.confirm(world[5],request=request,expected_version=preview['state_version'],idempotency_key='metadata-deny')
    assert not job['erasure_complete']
    keys=(Key('state','asset#'+original_id),Key('state','asset#'+crop_id));rows=repo.snapshot(keys)
    original,crop=rows[keys[0]],rows[keys[1]]
    assert validate_original_source(original,ob,crop,metadata_only=True).source_sha256==ob.data['source_sha256']
    assert all(rows[Key('state','asset#'+ident)].data['read_denied'] is True for ident in ids)
    for ident in ids:
        with pytest.raises(StoreUnavailable):reads.read(operator,ident,binary=True)
    if selected in {'crop','both'}:
        with pytest.raises(StoreUnavailable):validate_original_source(original,ob,crop)
    after=repo.snapshot(keys)
    assert after==rows


def test_stored_denied_source_cannot_hide_provenance_corruption(world,original_case):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();repo=world[1];okey=Key('state','asset#'+ob.data['original_asset_id']);ckey=Key('state','asset#'+ob.data['asset_id'])
    rows=repo.snapshot((okey,ckey));original=rows[okey]
    # A malformed denied record is held, even when every ordinary media read is denied.
    repo.transact((Write(okey,original.revision,{**original.data,'read_denied':True,'deletion_job_id':'bad','denied_at_ms':world[2]()}),))
    original=repo.snapshot((okey,))[okey]
    with pytest.raises(StoreUnavailable):validate_original_source(original,ob,rows[ckey],metadata_only=True)
    with pytest.raises(StoreUnavailable):reads.read(operator,original.data['id'],binary=True)
