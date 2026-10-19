from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

import pytest

from proofpack.runtime.control import RuntimeControl,integer


@pytest.mark.parametrize('value',[True,False,-1,1.5,'1',None,Decimal('NaN'),Decimal('Infinity'),Decimal('1.5')])
def test_receipt_integer_fields_reject_coercion_or_nonfinite(value):
    with pytest.raises(ValueError):integer(value)


def test_receipt_integer_fields_normalize_losslessly():
    assert integer(Decimal('12345678901234567890'))==12345678901234567890


@pytest.mark.parametrize('changes',[{'instance_id':'bad'}, {'artifact_sha256':'bad'},
    {'controls_sha256':'bad'},{'environment':'development'}])
def test_runtime_configuration_is_explicit(changes):
    config={'instance_id':str(uuid4()),'artifact_sha256':'a'*64,'controls_sha256':'b'*64,'environment':'test',**changes}
    with pytest.raises(ValueError):RuntimeControl(SimpleNamespace(repository=None),**config)
