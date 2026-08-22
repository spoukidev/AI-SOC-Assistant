from pathlib import Path

import pytest

from app.ml.demo_data import generate_labeled_demo_csv
from app.ml.detector import BaseDetector
from app.ml.training import train_experiment


@pytest.mark.parametrize("model_name", ["logistic_regression", "random_forest", "xgboost"])
def test_three_classifiers_train_evaluate_and_serialize(tmp_path: Path, model_name: str):
    result = train_experiment(generate_labeled_demo_csv(30), model_name, tmp_path, random_seed=17)
    assert Path(result.artifact_path).is_file()
    assert Path(result.artifact_path).with_suffix(".metadata.json").is_file()
    assert 0.0 <= result.metrics["precision"] <= 1.0
    assert 0.0 <= result.metrics["recall"] <= 1.0
    assert sum(result.metrics[key] for key in ("true_positive", "true_negative", "false_positive", "false_negative")) == result.split["test"]
    artifact = BaseDetector.load_artifact(result.artifact_path)
    assert artifact["name"] == model_name
