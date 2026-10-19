"""Pure strict storage-command checks; no client, permissions or deletion claim."""
import pytest
from proofpack.evidence.repository import Erase,Key

@pytest.mark.parametrize('revision',[None,False,True,0,-1,1.0,'1',2**63-1,2**63])
def test_erasure_requires_an_exact_incrementable_revision(revision):
    with pytest.raises(ValueError):Erase(Key('state','inspection#test'),revision,'a'*64)

@pytest.mark.parametrize('reference',[None,False,'','a'*63,'a'*65,'A'*64,'g'*64])
def test_erasure_reference_is_an_opaque_lowercase_digest(reference):
    with pytest.raises(ValueError):Erase(Key('state','inspection#test'),1,reference)

@pytest.mark.parametrize('key',[None,False,Key('foreign','x'),Key([], 'x'),Key('state',''),Key('events','x'*257)])
def test_erasure_accepts_only_the_owned_bounded_key_shape(key):
    with pytest.raises(ValueError):Erase(key,1,'a'*64)

def test_erasure_command_has_no_original_payload_or_user_fields():
    command=Erase(Key('events','capture#test'),1,'a'*64)
    assert set(vars(command))=={'key','expected_revision','reference_sha256'}
    assert command.key.table=='events' and command.expected_revision==1
