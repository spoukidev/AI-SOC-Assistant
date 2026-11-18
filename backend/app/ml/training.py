from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from sklearn.model_selection import train_test_split

from .detector import create_detector
from .evaluation import evaluate_detector
from .preprocessing import MODEL_FEATURES, load_labeled_csv


@dataclass
class TrainingResult:
    model_name: str
    version: str
    artifact_path: str
    metrics: dict
    validation_metrics: dict
    dataset_metadata: dict
    split: dict
    parameters: dict
    random_seed: int
    training_time_ms: float
    inference_time_ms: float


def train_experiment(
    content: bytes,
    model_name: str,
    artifact_dir: str | Path,
    random_seed: int = 42,
    parameters: dict | None = None,
) -> TrainingResult:
    features, labels, dataset_metadata = load_labeled_csv(content)
    x_train, x_temp, y_train, y_temp = train_test_split(
        features, labels, test_size=0.30, random_state=random_seed, stratify=labels,
    )
    x_validation, x_test, y_validation, y_test = train_test_split(
        x_temp, y_temp, test_size=0.50, random_state=random_seed, stratify=y_temp,
    )
    detector = create_detector(model_name, random_seed, parameters)
    started = perf_counter()
    detector.train(x_train, y_train)
    training_time_ms = (perf_counter() - started) * 1000
    validation_metrics, _ = evaluate_detector(detector, x_validation, y_validation)
    test_metrics, inference_time_ms = evaluate_detector(detector, x_test, y_test)
    version = f"{model_name}-{uuid4().hex[:12]}"
    path = Path(artifact_dir).resolve() / f"{version}.joblib"
    detector.save(path)
    split = {"strategy": "stratified_random", "train": len(x_train), "validation": len(x_validation), "test": len(x_test), "ratios": [0.70, 0.15, 0.15]}
    metadata_path = path.with_suffix(".metadata.json")
    metadata_path.write_text(json.dumps({
        "model_name": model_name, "model_version": version,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": dataset_metadata["sha256"], "dataset_samples": dataset_metadata["samples"],
        "class_distribution": dataset_metadata["class_distribution"], "features": MODEL_FEATURES,
        "hyperparameters": detector.pipeline.named_steps["classifier"].get_params(deep=False),
        "test_metrics": test_metrics, "validation_metrics": validation_metrics,
        "split": split, "random_seed": random_seed,
        "training_time_ms": training_time_ms, "inference_time_ms": inference_time_ms,
    }, indent=2, default=str), encoding="utf-8")
    return TrainingResult(
        model_name=model_name, version=version, artifact_path=str(path), metrics=test_metrics,
        validation_metrics=validation_metrics, dataset_metadata=dataset_metadata, split=split,
        parameters=detector.pipeline.named_steps["classifier"].get_params(deep=False),
        random_seed=random_seed, training_time_ms=training_time_ms,
        inference_time_ms=inference_time_ms,
    )


__all__ = ["MODEL_FEATURES", "TrainingResult", "train_experiment"]
