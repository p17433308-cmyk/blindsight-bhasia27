"""
BlindSight Validator — Structural anomaly detection for forensic artifacts.

Detects signs of programmatic artifact generation that differ from
organic system-generated artifacts.
"""

import struct
import math
import os
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field

from .integrity import AlertSeverity, IntegrityAlert

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    try:
        seconds = ft / 10_000_000
        return NTFS_EPOCH + __import__("datetime").timedelta(seconds=seconds)
    except (OverflowError, ValueError, OSError):
        return None


class TimestampAnomalyDetector:
    """Detect anomalous timestamp patterns in forensic artifacts."""

    def __init__(self):
        self.alerts: list[IntegrityAlert] = []

    def analyze_timestamp_distribution(
        self,
        timestamps: list[int],
        artifact_type: str,
        artifact_path: str,
    ) -> list[IntegrityAlert]:
        """Analyze FILETIME values for statistical anomalies."""
        if len(timestamps) < 5:
            return []

        valid_ts = [t for t in timestamps if t > 0]
        if len(valid_ts) < 5:
            return []

        # Check 1: Sub-second precision distribution
        self._check_precision_distribution(valid_ts, artifact_type, artifact_path)

        # Check 2: Inter-timestamp interval regularity
        self._check_interval_regularity(valid_ts, artifact_type, artifact_path)

        # Check 3: Timestamp clustering
        self._check_clustering(valid_ts, artifact_type, artifact_path)

        # Check 4: Weekend/off-hours activity
        self._check_temporal_plausibility(valid_ts, artifact_type, artifact_path)

        return self.alerts

    def _check_precision_distribution(
        self, timestamps: list[int], artifact_type: str, path: str
    ) -> None:
        """Real timestamps have varied sub-second components.
        Programmatically generated ones often have round values."""
        sub_second = [t % 10_000_000 for t in timestamps]

        # Check for exact-second timestamps (sub-second = 0)
        exact_second = sum(1 for s in sub_second if s == 0)
        ratio = exact_second / len(sub_second)

        if ratio > 0.5:
            self.alerts.append(IntegrityAlert(
                severity=AlertSeverity.HIGH,
                artifact_type=artifact_type,
                artifact_path=path,
                check_name="precision_anomaly",
                description=(
                    f"{exact_second}/{len(sub_second)} timestamps "
                    f"({ratio:.0%}) have zero sub-second precision. "
                    f"Real NTFS timestamps have ~100ns precision from "
                    f"system clock; fabricated timestamps from Python's "
                    f"datetime often lack sub-second components."
                ),
                evidence={"exact_second_count": exact_second, "total": len(sub_second)},
            ))

        # Check for repeated sub-second patterns
        if len(set(sub_second)) < len(sub_second) * 0.3:
            self.alerts.append(IntegrityAlert(
                severity=AlertSeverity.MEDIUM,
                artifact_type=artifact_type,
                artifact_path=path,
                check_name="precision_repetition",
                description=(
                    f"Only {len(set(sub_second))} unique sub-second values "
                    f"across {len(sub_second)} timestamps. Low entropy in "
                    f"sub-second precision suggests programmatic generation."
                ),
                evidence={"unique_values": len(set(sub_second)), "total": len(sub_second)},
            ))

    def _check_interval_regularity(
        self, timestamps: list[int], artifact_type: str, path: str
    ) -> None:
        """Real file activity has irregular intervals.
        Fabricated timestamps may have suspiciously regular spacing."""
        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

        if not intervals:
            return

        # Check for exact-interval repetition
        interval_counts: dict[int, int] = {}
        for iv in intervals:
            rounded = round(iv / 10_000_000) * 10_000_000  # round to seconds
            interval_counts[rounded] = interval_counts.get(rounded, 0) + 1

        max_repeat = max(interval_counts.values())
        if max_repeat > len(intervals) * 0.4 and len(intervals) > 5:
            most_common = max(interval_counts, key=interval_counts.get)
            seconds = most_common / 10_000_000

            self.alerts.append(IntegrityAlert(
                severity=AlertSeverity.MEDIUM,
                artifact_type=artifact_type,
                artifact_path=path,
                check_name="interval_regularity",
                description=(
                    f"{max_repeat}/{len(intervals)} inter-timestamp intervals "
                    f"are ~{seconds:.0f} seconds. Highly regular spacing "
                    f"suggests scripted timestamp generation rather than "
                    f"organic user activity."
                ),
                evidence={
                    "repeated_interval_seconds": seconds,
                    "repeat_count": max_repeat,
                    "total_intervals": len(intervals),
                },
            ))

    def _check_clustering(
        self, timestamps: list[int], artifact_type: str, path: str
    ) -> None:
        """Detect suspicious temporal clustering of file activity."""
        sorted_ts = sorted(timestamps)
        ten_minutes = 10 * 60 * 10_000_000  # 10 minutes in FILETIME units

        clusters = []
        current_cluster = [sorted_ts[0]]

        for i in range(1, len(sorted_ts)):
            if sorted_ts[i] - sorted_ts[i - 1] < ten_minutes:
                current_cluster.append(sorted_ts[i])
            else:
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)
                current_cluster = [sorted_ts[i]]
        if len(current_cluster) > 1:
            clusters.append(current_cluster)

        for cluster in clusters:
            if len(cluster) > len(timestamps) * 0.5 and len(cluster) > 3:
                start = filetime_to_datetime(cluster[0])
                end = filetime_to_datetime(cluster[-1])
                if start and end:
                    span = (end - start).total_seconds()
                    self.alerts.append(IntegrityAlert(
                        severity=AlertSeverity.MEDIUM,
                        artifact_type=artifact_type,
                        artifact_path=path,
                        check_name="temporal_clustering",
                        description=(
                            f"{len(cluster)}/{len(timestamps)} timestamps "
                            f"cluster within {span:.0f} seconds "
                            f"({start.strftime('%H:%M')}-{end.strftime('%H:%M')}). "
                            f"Bulk fabrication often produces tight temporal clusters."
                        ),
                        evidence={
                            "cluster_size": len(cluster),
                            "span_seconds": span,
                        },
                    ))

    def _check_temporal_plausibility(
        self, timestamps: list[int], artifact_type: str, path: str
    ) -> None:
        """Flag activity during implausible hours for the locale."""
        off_hours = 0
        for t in timestamps:
            dt = filetime_to_datetime(t)
            if dt and (dt.hour < 5 or dt.hour > 23):
                off_hours += 1

        ratio = off_hours / len(timestamps) if timestamps else 0
        if ratio > 0.7 and len(timestamps) > 5:
            self.alerts.append(IntegrityAlert(
                severity=AlertSeverity.LOW,
                artifact_type=artifact_type,
                artifact_path=path,
                check_name="off_hours_activity",
                description=(
                    f"{off_hours}/{len(timestamps)} ({ratio:.0%}) timestamps "
                    f"fall outside business hours (UTC). Consider timezone "
                    f"context, but high off-hours ratios may indicate "
                    f"fabrication using UTC without locale adjustment."
                ),
                evidence={"off_hours": off_hours, "total": len(timestamps)},
            ))


class PrefetchAnomalyDetector:
    """Detect anomalies in Prefetch files."""

    def __init__(self):
        self.alerts: list[IntegrityAlert] = []

    def check_prefetch_directory(self, prefetch_dir: str) -> list[IntegrityAlert]:
        """Analyze a directory of Prefetch files for anomalies."""
        pf_files = [
            f for f in os.listdir(prefetch_dir)
            if f.upper().endswith(".PF")
        ]

        if not pf_files:
            return []

        # Check: Prefetch files with creation timestamps clustered together
        create_times = []
        for pf in pf_files:
            path = os.path.join(prefetch_dir, pf)
            stat = os.stat(path)
            create_times.append((pf, stat.st_ctime))

        # Check for batch creation
        sorted_times = sorted(create_times, key=lambda x: x[1])
        batch_threshold = 5  # seconds
        current_batch = [sorted_times[0]]

        for i in range(1, len(sorted_times)):
            if sorted_times[i][1] - sorted_times[i - 1][1] < batch_threshold:
                current_batch.append(sorted_times[i])
            else:
                if len(current_batch) > 3:
                    self._report_batch(current_batch, prefetch_dir)
                current_batch = [sorted_times[i]]

        if len(current_batch) > 3:
            self._report_batch(current_batch, prefetch_dir)

        return self.alerts

    def _report_batch(self, batch: list, prefetch_dir: str) -> None:
        files = [b[0] for b in batch]
        self.alerts.append(IntegrityAlert(
            severity=AlertSeverity.HIGH,
            artifact_type="Prefetch",
            artifact_path=prefetch_dir,
            check_name="batch_creation",
            description=(
                f"{len(batch)} Prefetch files created within seconds of each "
                f"other: {', '.join(files[:5])}{'...' if len(files) > 5 else ''}. "
                f"Prefetch files are normally created individually during "
                f"program execution, not in bulk."
            ),
            evidence={"files": files, "count": len(batch)},
            recommendation="Verify each program's execution against other sources",
        ))
