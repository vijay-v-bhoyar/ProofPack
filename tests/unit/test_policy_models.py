from itertools import combinations, permutations
import json
import pytest
from proofpack.planner.candidates import PolicyDraft, PolicyCatalogConfig
from proofpack.planner.policy import ActionKind, DEFAULT_PRIORITY, choose_action


def draft(**changes):
    return PolicyDraft.model_validate_json(json.dumps({'name':'Kit priority','algorithm':'reason_priority_v1',
        'priority':[x.value for x in DEFAULT_PRIORITY],**changes}))


@pytest.mark.parametrize('priority',list(permutations(DEFAULT_PRIORITY)))
def test_installed_ordering_never_invents_an_ineligible_action(priority):
    assert draft(priority=priority).priority==priority
    pairs=(('overlap',ActionKind.SEPARATE_REGION),('not_flat',ActionKind.PLACE_FLAT),('blur',ActionKind.RECAPTURE))
    for n in range(4):
        for subset in combinations(pairs,n):
            eligible={p[1] for p in subset}
            expected=next((action for action in priority if action in eligible),ActionKind.REVIEW)
            assert choose_action(tuple(p[0] for p in subset)+('unrecognized',),priority=priority)==expected


def test_default_policy_preserves_original_choices_for_all_known_reason_subsets():
    reasons=('overlap','not_flat','blur','glare','motion','missing','extra')
    for n in range(8):
        for subset in combinations(reasons,n):
            expected=(ActionKind.SEPARATE_REGION if 'overlap' in subset else ActionKind.PLACE_FLAT if 'not_flat' in subset
                else ActionKind.RECAPTURE if set(subset)&set(reasons[2:]) else ActionKind.REVIEW)
            assert choose_action(subset)==expected


@pytest.mark.parametrize('changes',[
    {'priority':['RECAPTURE']*3},{'priority':['REVIEW','RECAPTURE','PLACE_FLAT']},
    {'priority':['SEPARATE_REGION','PLACE_FLAT']},{'priority':['SEPARATE_REGION','PLACE_FLAT','RECAPTURE','REVIEW']},
    {'priority':['SEPARATE_REGION','PLACE_FLAT',True]},{'algorithm':'execute_python'},
    {'name':''},{'name':' '*4},{'name':'a\nb'},{'name':'x'*81},{'name':True},
    {'script':'pass'},{'url':'https://example.invalid'},{'approved':True},{'max_requests':99},{'model':'fake'},
])
def test_uninstalled_or_authority_changing_parameters_are_rejected(changes):
    with pytest.raises(ValueError):draft(**changes)


@pytest.mark.parametrize('priority',[['SEPARATE_REGION','PLACE_FLAT','RECAPTURE'],tuple(['SEPARATE_REGION','PLACE_FLAT','RECAPTURE']),
    (ActionKind.RECAPTURE,)*3,(ActionKind.REVIEW,ActionKind.PLACE_FLAT,ActionKind.RECAPTURE)])
def test_runtime_selector_rejects_unvalidated_priority(priority):
    with pytest.raises(ValueError):choose_action(('overlap',),priority=priority)


@pytest.mark.parametrize('field,bad',[('writes_per_minute',0),('writes_per_minute',101),('reads_per_minute',121),
    ('reads_per_minute',True),('max_revisions',0),('max_revisions',1001),('max_revisions',1.0)])
def test_explicit_bounded_catalog_configuration(field,bad):
    with pytest.raises(ValueError):PolicyCatalogConfig(**{'writes_per_minute':20,'reads_per_minute':120,'max_revisions':100,field:bad})
