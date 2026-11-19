"""Measure SHAP explanation stability on the synthetic labeled dataset.

For each model family and training seed, train on the synthetic demo data, then rebuild the SHAP
explainer on random halves of the stored background sample and compare feature rankings
(see ``app.ml.explain._ModelExplainer.stability``). Results describe synthetic data only.

Usage (from backend/):  python ../ml/shap_stability.py [--seeds 5] [--rows-per-class 150] [--label-noise 0.1]
"""
from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ml.demo_data import generate_labeled_demo_csv  # noqa: E402
from app.ml.explain import get_explainer  # noqa: E402
from app.ml.training import train_experiment  # noqa: E402

MODELS = ["logistic_regression", "random_forest", "xgboost"]


def with_label_noise(content: bytes, fraction: float, seed: int = 0) -> bytes:
    """Flip a fraction of labels so the synthetic task is not perfectly separable."""
    rows = list(csv.DictReader(io.StringIO(content.decode())))
    rng = random.Random(seed)
    for row in rng.sample(rows, int(len(rows) * fraction)):
        row["label"] = "benign" if row["label"] == "malicious" else "malicious"
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--rows-per-class", type=int, default=150)
    parser.add_argument("--label-noise", type=float, default=0.0, help="fraction of labels to flip (0-0.5)")
    args = parser.parse_args()
    data = generate_labeled_demo_csv(args.rows_per_class)
    if args.label_noise:
        data = with_label_noise(data, min(0.5, max(0.0, args.label_noise)))
    print("| Model | Seeds | Global top-5 Jaccard (mean, min) | Local top-3 Jaccard (mean, min) | Rank Spearman (mean) | Verdicts |")
    print("|---|---|---|---|---|---|")
    with tempfile.TemporaryDirectory() as directory:
        for model in MODELS:
            results = []
            for seed in range(args.seeds):
                trained = train_experiment(data, model, directory, random_seed=seed)
                results.append(get_explainer(trained.artifact_path, directory).stability(seed=seed))
            g = [r["global_top_k_jaccard"] for r in results]
            loc = [r["local_top3_jaccard"] for r in results]
            rho = [r["global_rank_spearman"] for r in results]
            verdicts = ", ".join(sorted({r["verdict"] for r in results}))
            print(f"| {model} | {args.seeds} | {sum(g)/len(g):.3f}, {min(g):.3f} | {sum(loc)/len(loc):.3f}, {min(loc):.3f} "
                  f"| {sum(rho)/len(rho):.3f} | {verdicts} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
