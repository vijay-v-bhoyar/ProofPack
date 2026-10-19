from dataclasses import replace

import pytest

from proofpack.recipes.models import Constraint, Origin, PartClass, Recipe
from proofpack.verifier.core import Authority


@pytest.fixture
def authority():
    return Authority(runtime=1, control=1, data=1, station=1, recipe=1, calibration=1,
                     policy=1, access=1, session="session-a", artifact="artifact-a", enabled=True,
                     operator_granted=True, dependencies_valid=True, valid_until_tick=1000.0)


@pytest.fixture
def recipe():
    return Recipe(recipe_id="demo", revision=1, name="Synthetic one of each", kit_sku="demo",
                  constraints=tuple(Constraint(constraint_id=c.value, part_class_id=c,
                                    expected_count=1, required_visibility="top planar view") for c in PartClass),
                  reference_asset_ids=("synthetic-reference",), calibration_profile_id="synthetic-mat",
                  data_origin=Origin.SYNTHETIC)


from pathlib import Path


@pytest.fixture(scope='session')
def installation_wheel(tmp_path_factory):
    """Synthetic local archive of actual imported package/assets; not release approval."""
    import proofpack
    from test_configured_installation import archive
    package=Path(proofpack.__file__).parent
    web=package/'web' if (package/'web/index.html').is_file() else package.parents[2]/'apps/web/dist'
    payload={'proofpack/'+p.relative_to(package).as_posix():p.read_bytes() for p in package.rglob('*.py') if '__pycache__' not in p.parts}
    payload.update({'proofpack/web/'+p.relative_to(web).as_posix():p.read_bytes() for p in web.rglob('*') if p.is_file()})
    wheel=tmp_path_factory.mktemp('synthetic-installation')/'proofpack-0.1.0-py3-none-any.whl'
    return wheel,archive(wheel,payload)

