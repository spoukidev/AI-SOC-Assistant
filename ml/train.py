from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ml.training import train_experiment


def main() -> None:
    parser = argparse.ArgumentParser(description="Train an evidence-traceable network-flow classifier")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--model", choices=["logistic_regression", "random_forest", "xgboost"], default="logistic_regression")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=ROOT / "ml" / "models")
    args = parser.parse_args()
    result = train_experiment(args.dataset.read_bytes(), args.model, args.output, args.seed)
    print(json.dumps({
        "data_label": "SYNTHETIC DEMO DATA" if "synthetic" in args.dataset.name.lower() else "USER-SUPPLIED DATASET",
        "model": result.model_name, "version": result.version, "artifact": result.artifact_path,
        "metrics": result.metrics, "split": result.split, "dataset": result.dataset_metadata,
    }, indent=2))


if __name__ == "__main__":
    main()
