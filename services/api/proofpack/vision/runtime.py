import hashlib
import importlib.metadata
import platform
from pathlib import Path

import cv2
import numpy as np


def runtime_proof() -> dict:
    if cv2.__version__.split(".")[0] != "5":
        raise RuntimeError("OpenCV 5 is required; inspection readiness denied")
    required = ("imdecode", "findContours", "getPerspectiveTransform", "warpPerspective", "calibrateCamera",
                "findHomography", "perspectiveTransform", "aruco")
    missing = [name for name in required if not hasattr(cv2, name)]
    if missing:
        raise RuntimeError(f"required OpenCV primitives missing: {missing}")
    if not all(hasattr(cv2.aruco,name) for name in ('ArucoDetector','generateImageMarker','getPredefinedDictionary')):
        raise RuntimeError('required ArUco primitives missing')
    image = np.full((100, 120), 255, np.uint8)
    cv2.rectangle(image, (20, 20), (60, 50), 0, -1)
    ok, encoded = cv2.imencode(".png", image)
    if not ok:
        raise RuntimeError("image encode failed")
    decoded = cv2.imdecode(encoded, cv2.IMREAD_GRAYSCALE)
    _, binary = cv2.threshold(decoded, 127, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    area = cv2.contourArea(contours[0]) if len(contours) == 1 else None
    corners = np.float32([[0, 0], [119, 0], [119, 99], [0, 99]])
    transform = cv2.getPerspectiveTransform(corners, corners)
    warped = cv2.warpPerspective(decoded, transform, (120, 100))
    if area != 1200 or not np.array_equal(decoded, warped):
        raise RuntimeError("known-image contour/rectification oracle failed")
    module_dir = Path(cv2.__file__).parent
    libraries = sorted([*module_dir.glob("*.pyd"), *module_dir.glob("*.so")])
    return {
        "cv2_version": cv2.__version__, "distribution": "opencv-python",
        "distribution_version": importlib.metadata.version("opencv-python"),
        "python": platform.python_version(), "architecture": platform.machine(),
        "platform": platform.system(), "module": str(Path(cv2.__file__).resolve()),
        "libraries": [{"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                      for p in libraries],
        "build_information": cv2.getBuildInformation(),
        "oracles": {"contour_area_px": area, "identity_rectification_exact": True,
                    "encode_decode_exact": bool(np.array_equal(image, decoded))},
        "scope": "local_known_image_only", "aws_arm_execution": "NOT_RUN",
    }
