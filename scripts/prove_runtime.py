"""Run from the repository root with the project's Python environment."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from proofpack.vision.runtime import runtime_proof

if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "evidence/local/opencv-runtime.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(runtime_proof(), indent=2) + "\n", encoding="utf-8")
    print(f"PASS: actual OpenCV 5 known-image proof written to {target}")
