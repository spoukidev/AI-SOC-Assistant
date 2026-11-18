from __future__ import annotations

from time import perf_counter

import pandas as pd
from sklearn.metrics import (
    accuracy_score, average_precision_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)


def evaluate_detector(detector, features: pd.DataFrame, labels: pd.Series) -> tuple[dict, float]:
    started = perf_counter()
    predictions = detector.predict(features)
    probabilities = detector.predict_proba(features)[:, 1]
    elapsed_ms = (perf_counter() - started) * 1000
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    metrics = {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc": float(average_precision_score(labels, probabilities)),
        "true_positive": int(tp), "true_negative": int(tn),
        "false_positive": int(fp), "false_negative": int(fn),
        "true_positive_rate": float(tp / (tp + fn)) if tp + fn else 0.0,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
    }
    return metrics, elapsed_ms
