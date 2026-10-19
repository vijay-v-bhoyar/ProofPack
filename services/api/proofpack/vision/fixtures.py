"""Deterministic paper-shape fixtures and a nominal printable mat, never hardware truth."""
import hashlib
import json
from pathlib import Path

import cv2
import numpy as np

from proofpack.recipes.models import Constraint,Origin,PartClass,Recipe
from proofpack.vision.calibration import CalibrationProfile,detect_markers

MARKER_IDS=(0,1,2,3)
MARKER_TOP_LEFTS=((28,28),(708,28),(708,408),(28,408))
COUNTS=((1,1,1,1),(2,1,1,0),(1,0,2,1))
CONDITIONS=("complete","missing","wrong_visible_variant","overlap","glare","post_pass_removal")


def blank_mat() -> np.ndarray:
    image=np.full((500,800,3),255,np.uint8)
    dictionary=cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50)
    for ident,(x,y) in zip(MARKER_IDS,MARKER_TOP_LEFTS,strict=True):
        marker=cv2.aruco.generateImageMarker(dictionary,ident,64)
        image[y:y+64,x:x+64]=cv2.cvtColor(marker,cv2.COLOR_GRAY2BGR)
    return image


def synthetic_profile() -> CalibrationProfile:
    frame=blank_mat()
    detected=detect_markers(frame,MARKER_IDS)
    # Analytic marker placement is independent of detector residuals. Physical
    # printing still requires ruler verification and independent qualification.
    plane=tuple(tuple((float(x+dx-100),float(y+dy-100)) for dx,dy in ((0,0),(63,0),(63,63),(0,63)))
                for x,y in MARKER_TOP_LEFTS)
    return CalibrationProfile(profile_id="synthetic-mat",revision=1,camera_id="synthetic-camera",
        frame_width=800,frame_height=500,output_width=600,output_height=300,
        physical_width_mm=200.,physical_height_mm=100.,marker_ids=MARKER_IDS,
        plane_corners=plane,enrolled_image_corners=detected,max_displacement_px=2.,
        max_reprojection_error_px=1.,measurement_error_mm=.5,min_area_px=30.,
        min_blur_variance=1.,threshold_gray=127,data_origin=Origin.SYNTHETIC,lens_model="rectilinear_qualified")


def demo_recipe(index: int = 0) -> Recipe:
    if not 0<=index<len(COUNTS):
        raise ValueError("three synthetic recipes available")
    return Recipe(recipe_id=f"synthetic-{index+1}",revision=1,name=f"Synthetic fixture {index+1}",
        kit_sku=f"paper-{index+1}",constraints=tuple(Constraint(constraint_id=c.value,part_class_id=c,
            expected_count=n,required_visibility="synthetic top silhouette") for c,n in zip(PartClass,COUNTS[index],strict=True)),
        reference_asset_ids=("generated-paper-shapes",),calibration_profile_id="synthetic-mat",data_origin=Origin.SYNTHETIC)


def _draw(image: np.ndarray, kind: PartClass, center: tuple[int,int], *, wrong: bool=False) -> None:
    x,y=center
    black=(0,0,0); white=(255,255,255)
    if kind==PartClass.WASHER:
        cv2.circle(image,(x,y),24,black,-1);cv2.circle(image,(x,y),9,white,-1)
    elif kind==PartClass.NUT:
        points=np.array([(x+25*np.cos(t),y+25*np.sin(t)) for t in np.arange(6)*np.pi/3],np.int32)
        cv2.fillPoly(image,[points],black);cv2.circle(image,(x,y),8,white,-1)
    elif kind==PartClass.BOLT:
        cv2.rectangle(image,(x-40,y-13),(x-25,y+13),black,-1)
        cv2.rectangle(image,(x-25,y-5),(x+40,y+5),black,-1)
    else:
        cv2.rectangle(image,(x-42,y-17),(x+42,y+17),black,-1)
        cv2.circle(image,(x-24,y),7,white,-1);cv2.circle(image,(x+24,y),7,white,-1)
    if wrong:
        # Deliberately non-enrolled visible silhouette, not a hidden property.
        cv2.rectangle(image,(x-7,y-7),(x+7,y+7),black,-1)


def make_fixture(recipe_index: int, condition: str, *, seed: int) -> tuple[np.ndarray,dict]:
    recipe=demo_recipe(recipe_index)
    if condition not in CONDITIONS:
        raise ValueError("unknown fixture condition")
    random=np.random.default_rng(seed)
    image=blank_mat()
    contents=[]
    for class_index,(kind,count) in enumerate(zip(PartClass,COUNTS[recipe_index],strict=True)):
        for ordinal in range(count):
            x=165+class_index*150+int(random.integers(-4,5))
            y=180+ordinal*110+int(random.integers(-4,5))
            contents.append((kind,(x,y)))
    actual_counts=dict(zip([c.value for c in PartClass],COUNTS[recipe_index],strict=True))
    absent=condition in {"missing","post_pass_removal"}
    if absent:
        removed=contents.pop(0)
        actual_counts[removed[0].value]-=1
    for i,(kind,center) in enumerate(contents):
        _draw(image,kind,center,wrong=condition=="wrong_visible_variant" and i==0)
    if condition=="overlap":
        # Two touching opaque regions whose appearance does not establish count.
        cv2.rectangle(image,(140,170),(220,210),(0,0,0),-1)
        cv2.circle(image,(170,190),26,(0,0,0),-1)
    if condition=="glare":
        # A controlled white occluder; it is not a calibrated physical glare model.
        cv2.rectangle(image,(130,160),(205,182),(255,255,255),-1)
    truth={"recipe_id":recipe.recipe_id,"data_origin":"synthetic","seed":seed,"condition":condition,
        "actual_counts":actual_counts,"independent_setup_group":f"synthetic-setup-{seed}",
        "session_group":f"synthetic-session-{seed}","operator_group":f"simulated-operator-{seed}",
        "actual_packing_operator":False,"physical_specimens":False,
        "condition_model_limit":"glare is a white occluder; wrong variant is a synthetic silhouette",
        "known_incomplete":absent or condition=="wrong_visible_variant",
        "expected_pass_allowed":condition=="complete"}
    return image,truth


def write_corpus(target: Path) -> dict:
    """Owned synthetic outputs only; refuse to overwrite any existing manifest."""
    target=target.resolve()
    target.mkdir(parents=True,exist_ok=True)
    manifest_path=target/"manifest.json"
    if manifest_path.exists():
        raise FileExistsError("choose a fresh corpus directory; preserve the old manifest")
    records=[]
    for recipe_index in range(3):
        for condition in CONDITIONS:
            for setup in range(8):
                seed=recipe_index*100+setup
                frame,truth=make_fixture(recipe_index,condition,seed=seed)
                name=f"r{recipe_index+1}-{condition}-{setup}.png"
                path=target/name
                if path.exists():
                    raise FileExistsError("refuse to replace an existing fixture")
                ok,encoded=cv2.imencode('.png',frame)
                if not ok:raise RuntimeError("fixture encoding failed")
                payload=encoded.tobytes();path.write_bytes(payload)
                records.append({"id":name.removesuffix('.png'),"image":name,
                    "split":"DEVELOPMENT","ground_truth_method":"generator_parameters",
                    "reviewer_independent":False,
                    "paired_complete_id":f"r{recipe_index+1}-complete-{setup}",
                    "sha256":hashlib.sha256(payload).hexdigest(),**truth})
    metadata={"schema_version":1,"data_origin":"synthetic","generation_seed_scheme":"recipe_index*100+setup",
        "episode_count":144,"setup_groups":24,"paired_conditions_share_setup":True,
        "license":"OWNER_PUBLICATION_DECISION_REQUIRED",
        "provenance":"generated geometry and OpenCV DICT_4X4_50 markers; no photographed hardware",
        "purpose":"local development and controlled evaluation; not physical qualification",
        "generator_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "opencv_version":cv2.__version__,
        "records":records,"calibration_profile":synthetic_profile().model_dump(mode='json'),
        "recipes":[demo_recipe(i).model_dump(mode='json') for i in range(3)]}
    manifest_path.write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    return metadata
