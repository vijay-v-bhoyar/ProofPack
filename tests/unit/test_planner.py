from dataclasses import replace

import pytest

from proofpack.planner.policy import Action, ActionKind, acknowledge, choose_action, issue
from proofpack.verifier.core import Conflict, Inspection, State


@pytest.mark.parametrize("reasons,kind", [(("overlap",),ActionKind.SEPARATE_REGION),
    (("not_flat",),ActionKind.PLACE_FLAT), (("blur",),ActionKind.RECAPTURE),
    (("unsupported",),ActionKind.REVIEW)])
def test_findings_change_action(reasons, kind):
    assert choose_action(reasons) == kind


def test_two_corrective_requests_ack_is_not_pass(authority):
    i = Inspection("i",authority,state=State.OBSERVING,scene=1)
    for n in range(2):
        a = Action(f"a{n}",ActionKind.SEPARATE_REGION,"o",1,i.version)
        i = issue(i,a,latest_observation_id="o")
        assert i.corrections == n+1
        assert i.state == State.ACTION_REQUIRED
        with pytest.raises(Conflict):
            issue(i,a,latest_observation_id="o")
        i = acknowledge(i,a,a.action_id)
        assert i.state == State.OBSERVING
        assert i.deadline_tick == 0
        with pytest.raises(Conflict):
            acknowledge(i,a,a.action_id)
    a = Action("a3",ActionKind.RECAPTURE,"o",1,i.version)
    i = issue(i,a,latest_observation_id="o")
    assert i.state == State.REVIEW_REQUIRED
    assert i.corrections == 2


def test_stale_proposals_and_wrong_ack_rejected(authority):
    i = Inspection("i",authority,state=State.OBSERVING,scene=1)
    a = Action("a",ActionKind.RECAPTURE,"old",1,i.version)
    with pytest.raises(Conflict):
        issue(i,a,latest_observation_id="new")
    a = replace(a,observation_id="new")
    pending = issue(i,a,latest_observation_id="new")
    with pytest.raises(Conflict):
        acknowledge(pending,a,"other")
