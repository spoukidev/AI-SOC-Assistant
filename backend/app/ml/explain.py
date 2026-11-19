"""SHAP explanations for trained flow-v1 detectors (Milestone 5).

Explanations are computed against the background sample stored in the model
artifact at training time. They describe how *this model's* output moved away
from its average output on that sample. They are model evidence, not proof of
malicious activity, and not a causal statement about the network flow.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path

import numpy as np
import pandas as pd

from .preprocessing import CATEGORICAL_FEATURES, MODEL_FEATURES, NUMERIC_FEATURES, feature_frame

logger = logging.getLogger(__name__)

BACKGROUND_SIZE = 100
TOP_FEATURES = 8
STABILITY_TOP_K = 5
STABILITY_RESAMPLES = 5
EXPLANATION_NOTE = (
    "SHAP values show how each feature moved this model's output relative to its average output on the "
    "training background sample. They explain the model, not the attacker, and are not proof of malicious activity."
)

_cache: dict[tuple[str, float], "_ModelExplainer"] = {}
_cache_lock = threading.Lock()
_CACHE_LIMIT = 8


class ExplanationUnavailable(Exception):
    """Raised when a model cannot be explained (for example, a pre-Milestone 5 artifact)."""


def background_sample(features: pd.DataFrame, random_seed: int = 42, size: int = BACKGROUND_SIZE) -> pd.DataFrame:
    """Pick a reproducible background sample of engineered features (no raw identifiers)."""
    if len(features) <= size:
        return features.reset_index(drop=True).copy()
    return features.sample(n=size, random_state=random_seed).reset_index(drop=True)


def original_feature(transformed_name: str) -> str:
    """Map a ColumnTransformer output name back to its flow-v1 feature."""
    _, _, name = transformed_name.partition("__")
    if name in NUMERIC_FEATURES:
        return name
    for feature in CATEGORICAL_FEATURES:
        if name == feature or name.startswith(f"{feature}_"):
            return feature
    return name


class _ModelExplainer:
    def __init__(self, artifact: dict):
        background = artifact.get("background")
        if background is None or len(background) == 0:
            raise ExplanationUnavailable(
                "This model artifact predates Milestone 5 and has no stored SHAP background sample. "
                "Retrain the model to enable explanations."
            )
        import shap  # imported lazily: shap is heavy and only needed for explanations

        self.pipeline = artifact["pipeline"]
        self.model_name = artifact.get("name", "unknown")
        self.preprocess = self.pipeline.named_steps["preprocess"]
        self.classifier = self.pipeline.named_steps["classifier"]
        self.background = pd.DataFrame(background, columns=MODEL_FEATURES)
        self.background_matrix = self._transform(self.background)
        self.transformed_names = [str(name) for name in self.preprocess.get_feature_names_out()]
        groups: dict[str, list[int]] = {}
        for index, name in enumerate(self.transformed_names):
            groups.setdefault(original_feature(name), []).append(index)
        self.groups = [(feature, groups[feature]) for feature in MODEL_FEATURES if feature in groups]

        if self.model_name == "logistic_regression":
            self.method = "SHAP LinearExplainer (interventional)"
            self.output_space = "log_odds"
        elif self.model_name in {"random_forest", "xgboost"}:
            self.method = "SHAP TreeExplainer (interventional)"
            self.output_space = "probability"
        else:
            raise ExplanationUnavailable(f"No SHAP explainer is configured for model type {self.model_name}")
        self.explainer = self._build_explainer(self.background_matrix)
        self.global_result: dict | None = None
        self.stability_result: dict | None = None

    def _build_explainer(self, reference: np.ndarray):
        import shap

        if self.output_space == "log_odds":
            return shap.LinearExplainer(self.classifier, reference)
        return shap.TreeExplainer(self.classifier, reference, feature_perturbation="interventional",
                                  model_output="probability")

    def _transform(self, frame: pd.DataFrame) -> np.ndarray:
        matrix = self.preprocess.transform(frame)
        if hasattr(matrix, "toarray"):
            matrix = matrix.toarray()
        return np.asarray(matrix, dtype=float)

    def _shap(self, matrix: np.ndarray, explainer=None) -> tuple[np.ndarray, float]:
        explainer = explainer or self.explainer
        values = np.asarray(explainer.shap_values(matrix, check_additivity=False)
                            if self.output_space == "probability" else explainer.shap_values(matrix))
        base = np.asarray(explainer.expected_value, dtype=float).reshape(-1)
        if values.ndim == 3:  # (rows, features, classes): keep the positive ("malicious") class
            values = values[:, :, 1]
            base_value = float(base[1] if base.size > 1 else base[0])
        else:
            base_value = float(base[-1])
        grouped = np.column_stack([values[:, indexes].sum(axis=1) for _, indexes in self.groups])
        return grouped, base_value

    def model_output(self, frame: pd.DataFrame) -> float:
        if self.output_space == "log_odds":
            return float(self.pipeline.decision_function(frame)[0])
        return float(self.pipeline.predict_proba(frame)[0, 1])

    def local(self, features: dict, top_k: int = TOP_FEATURES) -> dict:
        frame = feature_frame(features)
        grouped, base_value = self._shap(self._transform(frame))
        row = grouped[0]
        contributions = [
            {"feature": feature, "value": _json_value(features.get(feature)), "shap_value": round(float(value), 6),
             "direction": "increases_malicious_score" if value > 0 else "decreases_malicious_score" if value < 0 else "neutral"}
            for (feature, _), value in zip(self.groups, row)
        ]
        contributions.sort(key=lambda item: abs(item["shap_value"]), reverse=True)
        shown = contributions[:top_k]
        rest = float(sum(item["shap_value"] for item in contributions[top_k:]))
        return {
            "status": "available", "method": self.method, "output_space": self.output_space,
            "base_value": round(base_value, 6), "model_output": round(self.model_output(frame), 6),
            "predicted_probability": round(float(self.pipeline.predict_proba(frame)[0, 1]), 6),
            "contributions": shown, "other_features_total": round(rest, 6),
            "background_samples": len(self.background), "note": EXPLANATION_NOTE,
        }

    def global_importance(self) -> dict:
        if self.global_result is None:
            grouped, base_value = self._shap(self.background_matrix)
            mean_abs = np.abs(grouped).mean(axis=0)
            mean_signed = grouped.mean(axis=0)
            importance = [
                {"feature": feature, "mean_abs_shap": round(float(abs_value), 6), "mean_shap": round(float(signed), 6)}
                for (feature, _), abs_value, signed in zip(self.groups, mean_abs, mean_signed)
            ]
            importance.sort(key=lambda item: item["mean_abs_shap"], reverse=True)
            self.global_result = {
                "status": "available", "method": self.method, "output_space": self.output_space,
                "base_value": round(base_value, 6), "samples": len(self.background),
                "sample_description": "Stored training background sample (engineered features only, no IPs)",
                "importance": importance, "note": EXPLANATION_NOTE,
            }
        return self.global_result


    def stability(self, top_k: int = STABILITY_TOP_K, resamples: int = STABILITY_RESAMPLES,
                  fraction: float = 0.5, seed: int = 0) -> dict:
        """Measure how much the explanations depend on which reference rows SHAP uses.

        The explainer is rebuilt on ``resamples`` random halves of the stored background sample, and
        every background row is explained each time. Reported numbers are mean pairwise Jaccard
        overlaps of (a) the global top-k features and (b) each row's local top-3 features, plus the
        mean Spearman correlation of the global importance ranking. 1.0 = identical every time.
        """
        if self.stability_result is not None:
            return self.stability_result
        rows = len(self.background_matrix)
        if rows < 10:
            self.stability_result = {"status": "unavailable", "reason": "At least 10 background rows are needed."}
            return self.stability_result
        rng = np.random.default_rng(seed)
        size = max(5, int(rows * fraction))
        global_sets, rankings, local_sets = [], [], []
        for _ in range(resamples):
            reference = self.background_matrix[rng.choice(rows, size=size, replace=False)]
            grouped, _ = self._shap(self.background_matrix, self._build_explainer(reference))
            importance = np.abs(grouped).mean(axis=0)
            global_sets.append(_top(importance, top_k))
            rankings.append(_ranks(importance))
            local_sets.append([_top(np.abs(row), 3) for row in grouped])
        pairs = [(a, b) for a in range(resamples) for b in range(a + 1, resamples)]
        global_overlap = float(np.mean([_jaccard(global_sets[a], global_sets[b]) for a, b in pairs]))
        local_overlap = float(np.mean([
            np.mean([_jaccard(local_sets[a][row], local_sets[b][row]) for row in range(rows)]) for a, b in pairs
        ]))
        rank_correlation = float(np.mean([_spearman(rankings[a], rankings[b]) for a, b in pairs]))
        if global_overlap >= 0.8 and local_overlap >= 0.8:
            verdict = "stable"
        elif global_overlap >= 0.6 and local_overlap >= 0.6:
            verdict = "moderately stable"
        else:
            verdict = "unstable"
        self.stability_result = {
            "status": "available", "verdict": verdict, "top_k": top_k, "resamples": resamples,
            "reference_rows_per_resample": size, "explained_rows": rows,
            "global_top_k_jaccard": round(global_overlap, 4), "local_top3_jaccard": round(local_overlap, 4),
            "global_rank_spearman": round(rank_correlation, 4),
            "method": "Rebuild the explainer on random halves of the background sample and compare feature rankings.",
            "thresholds": "stable: both overlaps ≥ 0.8; moderately stable: both ≥ 0.6; otherwise unstable",
        }
        return self.stability_result


def _top(values: np.ndarray, k: int, epsilon: float = 1e-9) -> set[int]:
    """Indexes of the k largest values, ignoring (near-)zero ones so ties among unused features
    cannot make rankings look more stable than they are."""
    return {int(index) for index in np.argsort(-values, kind="stable")[:k] if values[index] > epsilon}


def _jaccard(a: set, b: set) -> float:
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def _ranks(values: np.ndarray) -> np.ndarray:
    order = np.argsort(-values, kind="stable")
    ranks = np.empty(len(values))
    ranks[order] = np.arange(len(values))
    return ranks


def _spearman(a: np.ndarray, b: np.ndarray) -> float:
    if np.std(a) == 0 or np.std(b) == 0:
        return 1.0
    return float(np.corrcoef(a, b)[0, 1])


def _json_value(value):
    if isinstance(value, (np.generic,)):
        return value.item()
    return value


def get_explainer(artifact_path: str | Path, allowed_dir: str | Path) -> _ModelExplainer:
    """Load (and cache) an explainer for an artifact inside the configured artifact directory."""
    from .detector import BaseDetector

    path = Path(artifact_path).resolve()
    if not path.is_relative_to(Path(allowed_dir).resolve()) or not path.is_file():
        raise ExplanationUnavailable("Model artifact is unavailable")
    key = (str(path), path.stat().st_mtime)
    with _cache_lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached
    explainer = _ModelExplainer(BaseDetector.load_artifact(path, allowed_dir=allowed_dir))
    with _cache_lock:
        if len(_cache) >= _CACHE_LIMIT:
            _cache.pop(next(iter(_cache)))
        _cache[key] = explainer
    return explainer


def unavailable(reason: str, status: str = "unavailable") -> dict:
    return {"status": status, "reason": reason, "contributions": [], "note": EXPLANATION_NOTE}


def safe_local_explanation(artifact_path: str | Path, allowed_dir: str | Path, features: dict | None) -> dict:
    if not features:
        return unavailable("Event has no flow-v1 feature vector to explain.")
    try:
        return get_explainer(artifact_path, allowed_dir).local(features)
    except ExplanationUnavailable as exc:
        return unavailable(str(exc))
    except Exception:  # never let an explainer failure break alert triage
        logger.exception("SHAP local explanation failed for %s", artifact_path)
        return unavailable("The explanation could not be computed for this model.", status="error")


def safe_global_explanation(artifact_path: str | Path, allowed_dir: str | Path, include_stability: bool = True) -> dict:
    try:
        explainer = get_explainer(artifact_path, allowed_dir)
        result = dict(explainer.global_importance())
        if include_stability:
            try:
                result["stability"] = explainer.stability()
            except Exception:  # stability is a diagnostic; never lose the explanation over it
                logger.exception("SHAP stability check failed for %s", artifact_path)
                result["stability"] = {"status": "error", "reason": "The stability check could not be computed."}
        return result
    except ExplanationUnavailable as exc:
        return {"status": "unavailable", "reason": str(exc), "importance": [], "note": EXPLANATION_NOTE}
    except Exception:
        logger.exception("SHAP global explanation failed for %s", artifact_path)
        return {"status": "error", "reason": "The explanation could not be computed for this model.",
                "importance": [], "note": EXPLANATION_NOTE}
