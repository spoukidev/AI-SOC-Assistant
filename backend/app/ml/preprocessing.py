from __future__ import annotations

import hashlib
import io

import pandas as pd
from fastapi import HTTPException
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from ..services.csv_ingestion import normalize_row
from .features import engineer_flow_features

NUMERIC_FEATURES = [
    "duration", "total_packets", "total_bytes", "bytes_per_packet",
    "packets_per_second", "bytes_per_second", "src_dst_byte_ratio",
    "src_dst_packet_ratio",
]
CATEGORICAL_FEATURES = ["src_port_category", "dst_port_category", "protocol", "has_tcp_flags"]
MODEL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
RAW_REQUIRED = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "duration", "packets", "bytes", "label"}


def build_preprocessor() -> ColumnTransformer:
    numeric = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scale", StandardScaler())])
    categorical = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encode", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])
    return ColumnTransformer([
        ("numeric", numeric, NUMERIC_FEATURES),
        ("categorical", categorical, CATEGORICAL_FEATURES),
    ], remainder="drop")


def load_labeled_csv(content: bytes) -> tuple[pd.DataFrame, pd.Series, dict]:
    if b"\x00" in content:
        raise HTTPException(422, "Dataset contains binary data")
    try:
        frame = pd.read_csv(io.BytesIO(content))
    except (UnicodeDecodeError, pd.errors.ParserError) as exc:
        raise HTTPException(422, "Dataset must be a valid UTF-8 CSV") from exc
    missing = RAW_REQUIRED - set(frame.columns)
    if missing:
        raise HTTPException(422, f"Labeled dataset is missing columns: {', '.join(sorted(missing))}")
    if len(frame) < 20:
        raise HTTPException(422, "At least 20 labeled rows are required for a train/validation/test split")
    if frame["label"].isna().any():
        raise HTTPException(422, "Labels cannot be empty")

    label_map = {"benign": 0, "normal": 0, "0": 0, "malicious": 1, "attack": 1, "1": 1}
    normalized_labels = frame["label"].astype(str).str.strip().str.lower().map(label_map)
    if normalized_labels.isna().any():
        unknown = sorted(frame.loc[normalized_labels.isna(), "label"].astype(str).unique())
        raise HTTPException(422, f"Unsupported labels: {', '.join(unknown)}. Use benign/malicious or 0/1")
    counts = normalized_labels.value_counts()
    if len(counts) != 2 or counts.min() < 5:
        raise HTTPException(422, "Both classes need at least 5 examples")

    feature_rows = []
    errors = []
    for index, row in frame.iterrows():
        raw = {column: "" if pd.isna(value) else str(value) for column, value in row.items()}
        try:
            normalized = normalize_row(raw)
            feature_rows.append(engineer_flow_features(normalized))
        except ValueError as exc:
            errors.append({"row": int(index) + 2, "reason": str(exc)})
    if errors:
        raise HTTPException(422, {"message": "Dataset contains invalid rows", "errors": errors[:100]})
    features = pd.DataFrame(feature_rows, columns=MODEL_FEATURES)
    metadata = {
        "sha256": hashlib.sha256(content).hexdigest(),
        "samples": len(frame),
        "class_distribution": {"benign": int((normalized_labels == 0).sum()), "malicious": int((normalized_labels == 1).sum())},
        "features": MODEL_FEATURES,
    }
    return features, normalized_labels.astype(int), metadata


def feature_frame(features: dict) -> pd.DataFrame:
    return pd.DataFrame([{name: features.get(name) for name in MODEL_FEATURES}], columns=MODEL_FEATURES)
