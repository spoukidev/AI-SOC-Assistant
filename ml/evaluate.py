from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.detector import BaseDetector
from app.ml.evaluation import evaluate_detector
from app.ml.preprocessing import load_labeled_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a serialized detector on a labeled CSV")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()
    artifact = BaseDetector.load_artifact(args.artifact)
    features, labels, dataset = load_labeled_csv(args.dataset.read_bytes())
    metrics, inference_time_ms = evaluate_detector(type("Loaded", (), {
        "predict": artifact["pipeline"].predict,
        "predict_proba": artifact["pipeline"].predict_proba,
    })(), features, labels)
    print(json.dumps({"model": artifact["name"], "dataset": dataset, "metrics": metrics, "inference_time_ms": inference_time_ms}, indent=2))


if __name__ == "__main__":
    main()
