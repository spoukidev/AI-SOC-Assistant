from __future__ import annotations

import csv
import io
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, UploadFile

from ..config import settings
from ..ml.features import engineer_flow_features

CANONICAL_FIELDS = (
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "duration", "packets", "bytes", "tcp_flags", "src_bytes", "dst_bytes",
    "src_packets", "dst_packets",
)
REQUIRED_FIELDS = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "duration", "packets", "bytes"}
ALIASES = {
    "source_ip": "src_ip", "source": "src_ip", "destination_ip": "dst_ip", "destination": "dst_ip",
    "source_port": "src_port", "destination_port": "dst_port", "proto": "protocol",
    "total_packets": "packets", "total_bytes": "bytes", "flags": "tcp_flags",
}


@dataclass
class ParsedImport:
    filename: str
    mapping: dict[str, str]
    total_rows: int
    events: list[dict]
    errors: list[dict]


def safe_filename(name: str | None) -> str:
    cleaned = Path(name or "network-events.csv").name
    return "".join(char for char in cleaned if char.isalnum() or char in "._-")[:255] or "network-events.csv"


def parse_mapping(mapping_json: str | None) -> dict[str, str]:
    if not mapping_json:
        return {}
    try:
        value = json.loads(mapping_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(422, "column_mapping must be valid JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise HTTPException(422, "column_mapping must be an object of CSV column names to canonical field names")
    unknown = set(value.values()) - set(CANONICAL_FIELDS)
    if unknown:
        raise HTTPException(422, f"Unknown canonical fields: {', '.join(sorted(unknown))}")
    return value


async def read_csv_upload(upload: UploadFile, mapping_json: str | None = None) -> ParsedImport:
    filename = safe_filename(upload.filename)
    if not filename.lower().endswith(".csv"):
        raise HTTPException(415, "Only .csv files are supported")
    if upload.content_type and upload.content_type not in {"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain", "application/octet-stream"}:
        raise HTTPException(415, "Unsupported CSV content type")
    content = await upload.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"CSV exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB upload limit")
    if b"\x00" in content:
        raise HTTPException(422, "CSV contains binary data")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "CSV must use UTF-8 encoding") from exc
    return parse_csv_text(text, filename, parse_mapping(mapping_json))


def parse_csv_text(text: str, filename: str, explicit_mapping: dict[str, str]) -> ParsedImport:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(422, "CSV header is missing")
    normalized_headers = {header.strip(): header for header in reader.fieldnames if header}
    mapping: dict[str, str] = {}
    for clean, original in normalized_headers.items():
        canonical = explicit_mapping.get(original, explicit_mapping.get(clean, ALIASES.get(clean.lower(), clean.lower())))
        if canonical in CANONICAL_FIELDS:
            mapping[original] = canonical
    missing = REQUIRED_FIELDS - set(mapping.values())
    if missing:
        raise HTTPException(422, f"Missing required columns: {', '.join(sorted(missing))}")

    events: list[dict] = []
    errors: list[dict] = []
    total = 0
    for row_number, raw_row in enumerate(reader, start=2):
        total += 1
        if total > settings.max_import_rows:
            raise HTTPException(413, f"CSV exceeds the {settings.max_import_rows:,} row limit")
        canonical_row = {canonical: (raw_row.get(source) or "").strip() for source, canonical in mapping.items()}
        try:
            normalized = normalize_row(canonical_row)
            normalized["raw_event"] = {key: value for key, value in raw_row.items() if key is not None}
            normalized["features"] = engineer_flow_features(normalized)
            events.append(normalized)
        except ValueError as exc:
            errors.append({"row": row_number, "reason": str(exc)})
    if total == 0:
        raise HTTPException(422, "CSV contains no data rows")
    if not events:
        raise HTTPException(422, {"message": "No valid rows found", "errors": errors[:100]})
    return ParsedImport(filename, mapping, total, events, errors[:100])


def normalize_row(row: dict[str, str]) -> dict:
    try:
        timestamp_text = row["timestamp"].replace("Z", "+00:00")
        timestamp = datetime.fromisoformat(timestamp_text)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid timestamp; use ISO 8601") from exc
    try:
        src_ip = str(ipaddress.ip_address(row["src_ip"]))
        dst_ip = str(ipaddress.ip_address(row["dst_ip"]))
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid source or destination IP address") from exc

    def integer(name: str, minimum: int = 0, maximum: int | None = None) -> int:
        try:
            value = int(row.get(name) or 0)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if value < minimum or (maximum is not None and value > maximum):
            raise ValueError(f"{name} must be between {minimum} and {maximum}")
        return value

    try:
        duration = float(row["duration"])
    except (KeyError, ValueError) as exc:
        raise ValueError("duration must be numeric") from exc
    if duration < 0:
        raise ValueError("duration cannot be negative")
    protocol = row.get("protocol", "").upper()
    if not protocol or len(protocol) > 16:
        raise ValueError("protocol is required and must be at most 16 characters")
    return {
        "timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": integer("src_port", 0, 65535), "dst_port": integer("dst_port", 0, 65535),
        "protocol": protocol, "duration": duration, "packets": integer("packets"), "bytes": integer("bytes"),
        "tcp_flags": (row.get("tcp_flags") or None)[:32] if row.get("tcp_flags") else None,
        "src_bytes": integer("src_bytes"), "dst_bytes": integer("dst_bytes"),
        "src_packets": integer("src_packets"), "dst_packets": integer("dst_packets"),
    }
