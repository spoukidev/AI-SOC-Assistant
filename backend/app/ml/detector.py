from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from .preprocessing import build_preprocessor


# User-tunable hyperparameters per detector with inclusive bounds. Anything else
# (unknown keys, n_jobs, callbacks, objects) is rejected so an API caller cannot
# request unbounded training work or pass arbitrary constructor arguments.
ParameterSpec = tuple[type, float | None, float | None]
ALLOWED_PARAMETERS: dict[str, dict[str, ParameterSpec]] = {
    "logistic_regression": {"C": (float, 1e-6, 1e6), "max_iter": (int, 1, 10_000)},
    "random_forest": {
        "n_estimators": (int, 1, 1000), "max_depth": (int, 1, 64),
        "min_samples_split": (int, 2, 1000), "min_samples_leaf": (int, 1, 1000),
    },
    "xgboost": {
        "n_estimators": (int, 1, 1000), "max_depth": (int, 1, 16),
        "learning_rate": (float, 1e-4, 1.0), "subsample": (float, 0.1, 1.0),
        "colsample_bytree": (float, 0.1, 1.0),
    },
}


def validate_parameters(name: str, parameters: dict | None) -> dict:
    allowed = ALLOWED_PARAMETERS.get(name, {})
    validated: dict = {}
    for key, value in (parameters or {}).items():
        if key not in allowed:
            raise ValueError(f"Unsupported parameter for {name}: {key}. Allowed: {', '.join(sorted(allowed)) or 'none'}")
        kind, minimum, maximum = allowed[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (kind is int and not float(value).is_integer()):
            raise ValueError(f"{key} must be {'an integer' if kind is int else 'a number'}")
        value = kind(value)
        if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
            raise ValueError(f"{key} must be between {minimum} and {maximum}")
        validated[key] = value
    return validated


class BaseDetector(ABC):
    name: str

    def __init__(self, random_seed: int = 42, parameters: dict | None = None):
        self.random_seed = random_seed
        self.parameters = validate_parameters(self.name, parameters)
        self.pipeline = Pipeline([("preprocess", build_preprocessor()), ("classifier", self.build_estimator())])

    @abstractmethod
    def build_estimator(self):
        raise NotImplementedError

    def train(self, features: pd.DataFrame, labels: pd.Series) -> "BaseDetector":
        self.pipeline.fit(features, labels)
        return self

    def predict(self, features: pd.DataFrame):
        return self.pipeline.predict(features)

    def predict_proba(self, features: pd.DataFrame):
        return self.pipeline.predict_proba(features)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"name": self.name, "random_seed": self.random_seed, "parameters": self.parameters, "pipeline": self.pipeline}, path)

    @classmethod
    def load_artifact(cls, path: str | Path, allowed_dir: str | Path | None = None) -> dict:
        """Load a joblib (pickle) artifact. Only load files this application produced.

        joblib/pickle can execute code on load, so when ``allowed_dir`` is given the
        resolved path must sit inside it; this stops a tampered database row from
        pointing the API at an arbitrary file on disk.
        """
        resolved = Path(path).resolve()
        if allowed_dir is not None and not resolved.is_relative_to(Path(allowed_dir).resolve()):
            raise ValueError("Model artifact is outside the configured artifact directory")
        return joblib.load(resolved)


class LogisticRegressionDetector(BaseDetector):
    name = "logistic_regression"

    def build_estimator(self):
        defaults = {"max_iter": 1000, "class_weight": "balanced", "random_state": self.random_seed}
        defaults.update(self.parameters)
        return LogisticRegression(**defaults)


class RandomForestDetector(BaseDetector):
    name = "random_forest"

    def build_estimator(self):
        defaults = {"n_estimators": 150, "class_weight": "balanced", "random_state": self.random_seed, "n_jobs": -1}
        defaults.update(self.parameters)
        return RandomForestClassifier(**defaults)


class XGBoostDetector(BaseDetector):
    name = "xgboost"

    def build_estimator(self):
        defaults = {
            "n_estimators": 150, "max_depth": 4, "learning_rate": 0.08,
            "subsample": 0.9, "colsample_bytree": 0.9, "random_state": self.random_seed,
            "eval_metric": "logloss", "n_jobs": -1,
        }
        defaults.update(self.parameters)
        return XGBClassifier(**defaults)


DETECTORS = {
    LogisticRegressionDetector.name: LogisticRegressionDetector,
    RandomForestDetector.name: RandomForestDetector,
    XGBoostDetector.name: XGBoostDetector,
}


def create_detector(name: str, random_seed: int = 42, parameters: dict | None = None) -> BaseDetector:
    detector_type = DETECTORS.get(name)
    if not detector_type:
        raise ValueError(f"Unsupported model: {name}")
    return detector_type(random_seed=random_seed, parameters=parameters)
