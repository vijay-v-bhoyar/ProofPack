from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from proofpack.recipes.models import Constraint, Interval, Origin, PartClass, Qualification, Recipe, check_activation


def test_immutable_and_extra_fields_rejected(recipe):
    with pytest.raises(ValidationError):
        recipe.name = "silently edited"
    with pytest.raises(ValidationError):
        Recipe.model_validate({**recipe.model_dump(), "passed":True})


@pytest.mark.parametrize("count", [-1, 21, True, "1", 1.2])
def test_count_bounds_and_strict_types(count):
    with pytest.raises(ValidationError):
        Constraint(constraint_id="washer", part_class_id=PartClass.WASHER,
                   expected_count=count, required_visibility="top")


def test_recipe_total_and_duplicates_rejected(recipe):
    raw = recipe.model_dump()
    raw["constraints"] = tuple(c.model_copy(update={"expected_count":20}) for c in recipe.constraints)
    with pytest.raises(ValidationError, match="30"):
        Recipe.model_validate(raw)
    with pytest.raises(ValidationError, match="duplicate"):
        Recipe.model_validate({**recipe.model_dump(), "constraints":(recipe.constraints[0],recipe.constraints[0])})


@pytest.mark.parametrize("lo,hi", [(2.,1.), (float("nan"),2.), (-1.,2.), (1.,float("inf"))])
def test_bad_intervals(lo,hi):
    with pytest.raises(ValidationError):
        Interval(minimum=lo, maximum=hi)


def test_activation_binds_origin_revision_and_permission(recipe):
    q = Qualification(run_id="q", recipe_id=recipe.recipe_id, recipe_revision=1,
                      calibration_profile_id=recipe.calibration_profile_id, data_origin=Origin.SYNTHETIC,
                      passed=True, artifact_sha256="a"*64, reviewer_id="reviewer")
    check_activation(recipe,q,environment="synthetic_demo",references_permitted=True)
    for changes in ({"recipe_revision":2},{"calibration_profile_id":"other"},{"passed":False},{"data_origin":Origin.PHYSICAL}):
        with pytest.raises(ValueError):
            check_activation(recipe,q.model_copy(update=changes),environment="synthetic_demo",references_permitted=True)
    with pytest.raises(ValueError, match="physical"):
        check_activation(recipe,q,environment="beta",references_permitted=True)
    with pytest.raises(ValueError):
        check_activation(recipe,q,environment="test",references_permitted=False)
