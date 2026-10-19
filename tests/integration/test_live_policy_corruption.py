"""Real CV/local transactions with TEST-INJECTED policy assurance, not beta proof."""
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from proofpack.capture.service import observation_key
from proofpack.evidence.repository import Write,StoreConflict
from proofpack.stations.service import inspection_key


@pytest.mark.parametrize('operation',['status','acknowledge'])
def test_corrupt_observation_policy_provenance_withdraws_action_and_cannot_acknowledge(world,publication_case,operation):
    service,capture,started,operator,_,_,_,_,_,observe=publication_case
    status,admission,_=observe('missing');assert status['effective_state']=='ACTION_REQUIRED'
    repo=world[1];key=observation_key(admission['id']);row=repo.snapshot((key,))[key]
    repo.transact((Write(key,row.revision,{**row.data,'policy_provenance':{}}),))
    workkey=inspection_key(started['inspection_id']);before=repo.snapshot((workkey,))[workkey]
    if operation=='status':
        invalid=service.status(operator,started['inspection_id'])
        assert invalid['effective_state']=='INVALIDATED' and invalid['action'] is None and invalid['remaining_lease_ms']==0
    else:
        with pytest.raises(StoreConflict):service.acknowledge(operator,inspection_id=started['inspection_id'],
            action_id=status['action']['id'],expected_version=status['state_version'],idempotency_key='corrupt-source-ack')
        assert repo.snapshot((workkey,))[workkey]==before
