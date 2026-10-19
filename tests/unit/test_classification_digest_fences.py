"""Original frozen digest inputs must survive trusted checkpoint callbacks."""
from dataclasses import replace
import pytest
from test_classification_accounting_digest import artifact,verifier,no_sdk
from proofpack.evidence.ownership_classification import ClassificationHeld

@pytest.mark.parametrize('field',['policy','entries','relationships','inventory','runtime','access','auth'])
def test_final_checkpoint_cannot_substitute_verified_input(monkeypatch,field):
    result,_=artifact(monkeypatch,5);a=result.accounting;c=result.corpus
    required=1+len(a.entries)+len(a.relationships);spent=[0];changed=[]
    def check(cost=0):
        spent[0]+=cost
        if cost==0 and spent[0]==required and not changed:
            changed.append(True)
            if field=='policy':object.__setattr__(a,'policy','conservative-family-accounting-v1')
            elif field=='entries':object.__setattr__(a,'entries',tuple(reversed(a.entries)))
            elif field=='relationships':object.__setattr__(a,'relationships',a.relationships[1:])
            elif field=='inventory':object.__setattr__(c.inventory,'summary_sha256','b'*64)
            elif field=='runtime':object.__setattr__(c.runtime_context,'summary_sha256','b'*64)
            elif field=='access':object.__setattr__(c.access_context,'summary_sha256','b'*64)
            elif field=='auth':object.__setattr__(c.auth_history,'summary_sha256','b'*64)
    with pytest.raises(ClassificationHeld):verifier(a,c,maximum=a.summary_bytes,check=check)
    assert changed==[True]

def test_last_checkpoint_failure_remains_failure_not_a_partial_verification(monkeypatch):
    result,_=artifact(monkeypatch,5);a=result.accounting;required=1+len(a.entries)+len(a.relationships);spent=[0]
    def check(cost=0):
        spent[0]+=cost
        if cost==0 and spent[0]==required:raise RuntimeError('original checkpoint failed')
    with pytest.raises(RuntimeError,match='original checkpoint failed'):verifier(a,result.corpus,maximum=a.summary_bytes,check=check)

@pytest.mark.parametrize('missing',['runtime_context','access_context','auth_history'])
def test_incomplete_context_cannot_be_a_matching_version(monkeypatch,missing):
    result,_=artifact(monkeypatch,5);c=replace(result.corpus,**{missing:None})
    with pytest.raises(ClassificationHeld):verifier(result.accounting,c,maximum=result.accounting.summary_bytes,check=lambda cost=0:None)

def test_transient_container_swap_does_not_change_original_verified_frames(monkeypatch):
    result,_=artifact(monkeypatch,5);a=result.accounting;original=a.entries;spent=[]
    def check(cost=0):
        spent.append(cost)
        if cost:
            object.__setattr__(a,'entries',tuple(reversed(original)))
            object.__setattr__(a,'entries',original)
    assert verifier(a,result.corpus,maximum=a.summary_bytes,check=check) is None
    assert a.entries is original and sum(spent)==1+len(a.entries)+len(a.relationships)
