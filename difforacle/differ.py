"""
DiffOracle Differ — Semantic comparison of forensic tool outputs.

Goes beyond string comparison: understands timestamp formats, timezone
representations, precision differences, and encoding variations to
distinguish genuine parser differentials from cosmetic differences.
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass


@dataclass
class TimestampComparison:
    """Result of comparing two timestamp representations."""
    identical: bool
    delta_seconds: float
    format_a: str
    format_b: str
    normalized_a: Optional[datetime]
    normalized_b: Optional[datetime]
    differential_type: str  # "none", "precision", "timezone", "value", "epoch"


TIMESTAMP_PATTERNS = [
    # ISO 8601
    (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)", "iso8601"),
    # Sleuthkit bodyfile format
    (r"(\d{10,13})", "unix_epoch"),
    # Human-readable
    (r"(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})", "ctime"),
    # NTFS FILETIME (hex)
    (r"0x([0-9a-fA-F]{16})", "filetime_hex"),
    # Standard date format
    (r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})", "slash_datetime"),
    (r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", "us_datetime"),
]


def normalize_timestamp(value: str) -> Optional[datetime]:
    """Parse a timestamp string into a normalized datetime."""
    value = value.strip()

    # Unix epoch (seconds or milliseconds)
    if re.match(r"^\d{10,13}$", value):
        ts = int(value)
        if ts > 1e12:
            ts = ts / 1000
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, ValueError):
            pass

    # ISO 8601
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Slash format
    for fmt in ["%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # NTFS FILETIME (100-ns intervals since 1601-01-01)
    match = re.match(r"^0x([0-9a-fA-F]{16})$", value)
    if match:
        filetime = int(match.group(1), 16)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        try:
            return epoch + timedelta(microseconds=filetime // 10)
        except (OverflowError, ValueError):
            pass

    return None


def compare_timestamps(value_a: str, value_b: str) -> TimestampComparison:
    """Compare two timestamp representations and classify the differential."""
    norm_a = normalize_timestamp(value_a)
    norm_b = normalize_timestamp(value_b)

    fmt_a = _detect_format(value_a)
    fmt_b = _detect_format(value_b)

    if norm_a is None or norm_b is None:
        return TimestampComparison(
            identical=value_a == value_b,
            delta_seconds=0,
            format_a=fmt_a,
            format_b=fmt_b,
            normalized_a=norm_a,
            normalized_b=norm_b,
            differential_type="unparseable",
        )

    delta = abs((norm_a - norm_b).total_seconds())

    if delta == 0:
        diff_type = "none"
    elif delta < 0.001:
        diff_type = "precision"  # sub-millisecond
    elif delta < 2:
        diff_type = "precision"  # rounding
    elif delta % 3600 == 0 and delta <= 86400:
        diff_type = "timezone"  # exact hour offset
    elif delta == 3600:
        diff_type = "dst"  # daylight saving
    else:
        diff_type = "value"  # genuine disagreement

    return TimestampComparison(
        identical=delta == 0,
        delta_seconds=delta,
        format_a=fmt_a,
        format_b=fmt_b,
        normalized_a=norm_a,
        normalized_b=norm_b,
        differential_type=diff_type,
    )


def _detect_format(value: str) -> str:
    for pattern, name in TIMESTAMP_PATTERNS:
        if re.search(pattern, value):
            return name
    return "unknown"


def compare_records(
    record_a: dict, record_b: dict, key_fields: Optional[list[str]] = None
) -> list[dict]:
    """Compare two parsed forensic records field by field."""
    diffs = []
    all_keys = set(record_a.keys()) | set(record_b.keys())

    if key_fields:
        all_keys = {k for k in all_keys if k in key_fields}

    for key in sorted(all_keys):
        val_a = str(record_a.get(key, ""))
        val_b = str(record_b.get(key, ""))

        if val_a == val_b:
            continue

        # Check if it's a timestamp field
        is_timestamp = any(
            t in key.lower()
            for t in ["time", "date", "stamp", "created", "modified", "accessed"]
        )

        if is_timestamp:
            ts_cmp = compare_timestamps(val_a, val_b)
            diffs.append({
                "field": key,
                "value_a": val_a,
                "value_b": val_b,
                "type": "timestamp",
                "differential": ts_cmp.differential_type,
                "delta_seconds": ts_cmp.delta_seconds,
            })
        else:
            diffs.append({
                "field": key,
                "value_a": val_a,
                "value_b": val_b,
                "type": "value",
                "differential": "mismatch",
                "delta_seconds": 0,
            })

    return diffs
