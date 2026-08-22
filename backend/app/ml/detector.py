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


class BaseDetector(ABC):
    name: str

    def __init__(self, random_seed: int = 42, parameters: dict | None = None):
        self.random_seed = random_seed
        self.parameters = parameters or {}
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
    def load_artifact(cls, path: str | Path) -> dict:
        return joblib.load(path)


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
