"""Versioned synthetic target history, not permission or provider verification."""
import pytest
from decimal import Decimal
from test_reference_lineage import family,run,no_sdk
from proofpack.evidence.reference_lineage import ReferenceHistoryHeld


@pytest.mark.parametrize('state',['reserved','writing','failed_reserved','failed_writing','linked'])
def test_original_target_survives_every_supported_version_two_history(state):
    root,rows=family(state,target={'history_version':2,'storage_binding_sha256':'9'*64})
    result=run(root,rows)
    assert 'STORAGE_TARGET_NOT_RECORDED' not in result.obligations
    assert 'INSPECTION_ORIGIN_NOT_RECORDED' in result.obligations
    assert ('STORAGE_RECONCILIATION_REQUIRED' in result.obligations)==(state!='linked')
    assert not hasattr(result,'can_delete')
    if result.media:assert result.media[0].storage_binding_sha256=='9'*64


@pytest.mark.parametrize('target',[
    {'history_version':True,'storage_binding_sha256':'9'*64},
    {'history_version':3,'storage_binding_sha256':'9'*64},
    {'history_version':2},
    {'storage_binding_sha256':'9'*64},
    {'history_version':2,'storage_binding_sha256':'not-a-digest'},
])
def test_even_resealed_malformed_target_history_is_rejected(target):
    root,rows=family(target=target)
    with pytest.raises(ReferenceHistoryHeld):run(root,rows)


def test_resealed_linked_asset_cannot_claim_another_storage_target():
    root,rows=family(target={'history_version':2,'storage_binding_sha256':'8'*64})
    with pytest.raises(ReferenceHistoryHeld):run(root,rows)


def test_float_version_is_rejected_before_a_storable_envelope_can_be_forged():
    with pytest.raises(ValueError,match='canonical storable record payload required'):
        family(target={'history_version':2.0,'storage_binding_sha256':'9'*64})


@pytest.mark.parametrize('version',[Decimal('2'),Decimal('2.0')])
def test_integral_dynamodb_version_roundtrip_remains_supported(version):
    root,rows=family(target={'history_version':version,'storage_binding_sha256':'9'*64})
    assert run(root,rows).state=='linked'


@pytest.mark.parametrize('version',[Decimal('1'),False,'2'])
def test_non_integral_or_non_version_dynamodb_values_are_held(version):
    root,rows=family(target={'history_version':version,'storage_binding_sha256':'9'*64})
    with pytest.raises(ReferenceHistoryHeld):run(root,rows)


def test_non_integral_decimal_cannot_forge_a_canonical_history_envelope():
    with pytest.raises(ValueError,match='canonical structured record value required'):
        family(target={'history_version':Decimal('2.5'),'storage_binding_sha256':'9'*64})
