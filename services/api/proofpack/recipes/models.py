"""F1 validation. Qualification is an independent evidence decision, not schema validity."""
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Origin(StrEnum):
    SYNTHETIC = "synthetic"
    PRINTABLE = "printable"
    PHYSICAL = "physical"


class PartClass(StrEnum):
    WASHER = "washer"
    NUT = "nut"
    BOLT = "bolt"
    FLAT_BRACKET = "flat_bracket"


class Interval(Contract):
    minimum: float = Field(ge=0, allow_inf_nan=False)
    maximum: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.minimum > self.maximum:
            raise ValueError("interval is inverted")
        return self


class Constraint(Contract):
    constraint_id: Identifier
    part_class_id: PartClass
    expected_count: int = Field(ge=0, le=20)
    dimension_mm: Interval | None = None
    flat_reference_aspect_ratio: Interval | None = Field(default=None,exclude_if=lambda value:value is None)
    permitted_variant_ids: tuple[Identifier, ...] = ()
    required_visibility: str = Field(min_length=1, max_length=300)
    unsupported_properties: tuple[str, ...] = ("material", "thread specification", "hidden contents")

    @model_validator(mode='after')
    def flat_reference_domain(self) -> Self:
        reference=self.flat_reference_aspect_ratio
        if reference is not None and not 1<=reference.minimum<=reference.maximum<=2000:
            raise ValueError('bounded planar flat-reference aspect interval required')
        return self


class Recipe(Contract):
    recipe_id: Identifier
    revision: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=100)
    kit_sku: Identifier
    constraints: tuple[Constraint, ...] = Field(min_length=1, max_length=4)
    reference_asset_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    calibration_profile_id: Identifier
    data_origin: Origin

    @model_validator(mode="after")
    def bounded_unique(self) -> Self:
        if sum(c.expected_count for c in self.constraints) > 30:
            raise ValueError("recipe exceeds 30 items")
        if len({c.constraint_id for c in self.constraints}) != len(self.constraints):
            raise ValueError("duplicate constraint ID")
        if len({c.part_class_id for c in self.constraints}) != len(self.constraints):
            raise ValueError("one unambiguous constraint per broad class is required")
        if len(set(self.reference_asset_ids)) != len(self.reference_asset_ids):
            raise ValueError("duplicate reference asset")
        return self


class Qualification(Contract):
    run_id: Identifier
    recipe_id: Identifier
    recipe_revision: int = Field(ge=1)
    calibration_profile_id: Identifier
    data_origin: Origin
    passed: bool
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewer_id: Identifier


def check_qualification_binding(recipe: Recipe, qualification: Qualification, *, environment: str,
                     references_permitted: bool) -> None:
    if not references_permitted:raise ValueError('permitted references required')
    if (recipe.recipe_id, recipe.revision, recipe.calibration_profile_id, recipe.data_origin) != (
        qualification.recipe_id, qualification.recipe_revision,
        qualification.calibration_profile_id, qualification.data_origin
    ):
        raise ValueError("qualification does not match this immutable recipe")
    if environment not in {"test", "synthetic_demo", "beta"}:
        raise ValueError("unknown environment")
    if environment == "beta" and recipe.data_origin != Origin.PHYSICAL:
        raise ValueError("beta requires physical qualification")


def check_activation(recipe: Recipe, qualification: Qualification, *, environment: str,
                     references_permitted: bool) -> None:
    check_qualification_binding(recipe,qualification,environment=environment,references_permitted=references_permitted)
    if not qualification.passed:raise ValueError('successful qualification required')
