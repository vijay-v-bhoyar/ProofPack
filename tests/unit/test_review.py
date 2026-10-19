from dataclasses import replace

import pytest

from proofpack.recipes.models import Origin
from proofpack.review.datasets import Example, Split, manifest, throughput


def sample():
    return Example("e1","kit1","session1","operator1",Split.DEVELOPMENT,Origin.SYNTHETIC,True,1000.,1,False)


@pytest.mark.parametrize("group", ["kit_group","session_group","operator_group"])
def test_split_leakage_rejected(group):
    a=sample()
    b=replace(a,example_id="e2",kit_group="kit2",session_group="session2",operator_group="operator2",split=Split.FROZEN_TEST)
    b=replace(b,**{group:getattr(a,group)})
    with pytest.raises(ValueError,match="leakage"):
        manifest((a,b),now=10.)


@pytest.mark.parametrize("changes", [{"permitted":False},{"expires_at":10.},{"label_revision":0}])
def test_expired_withdrawn_unreviewed_examples_rejected(changes):
    with pytest.raises(ValueError):
        manifest((replace(sample(),**changes),),now=10.)


def test_manifest_lineage_and_origins_not_rewritten():
    a=sample()
    m=manifest((a,),now=10.)
    assert m["rows"][0]["origin"] == "synthetic"
    assert m["rows"][0]["independent"] is False
    assert manifest((replace(a,label_revision=2),),now=10.)["sha256"] != m["sha256"]
    assert manifest((replace(a,kit_group="different"),),now=10.)["sha256"] != m["sha256"]
    assert manifest((replace(a,expires_at=999.),),now=10.)["sha256"] != m["sha256"]
    with pytest.raises(ValueError):
        manifest((a,a),now=10.)


def test_throughput_uses_all_operator_effort():
    assert throughput(correct_completions=10,total_operator_seconds=7200.) == 5
    with pytest.raises(ValueError):
        throughput(correct_completions=10,total_operator_seconds=0.)


@pytest.mark.parametrize("tick",[float('nan'),float('inf'),float('-inf')])
def test_invalid_clock_does_not_admit_dataset_or_metrics(tick):
    with pytest.raises(ValueError):
        manifest((sample(),),now=tick)
    with pytest.raises(ValueError):
        manifest((replace(sample(),expires_at=tick),),now=10.)
    with pytest.raises(ValueError):
        throughput(correct_completions=1,total_operator_seconds=tick)
