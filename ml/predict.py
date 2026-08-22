from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.detector import BaseDetector
from app.ml.preprocessing import feature_frame


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict one already-engineered flow-v1 feature record")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("features", type=Path, help="JSON object containing flow-v1 features")
    args = parser.parse_args()
    artifact = BaseDetector.load_artifact(args.artifact)
    frame = feature_frame(json.loads(args.features.read_text(encoding="utf-8")))
    label = int(artifact["pipeline"].predict(frame)[0])
    probability = float(artifact["pipeline"].predict_proba(frame)[0, 1])
    print(json.dumps({"prediction": "malicious" if label else "benign", "model_probability": probability, "severity": None}))


if __name__ == "__main__":
    main()
