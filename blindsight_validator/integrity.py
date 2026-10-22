"""
BlindSight Validator — Cross-tool evidence integrity checker.

Validates forensic artifacts by cross-referencing outputs from multiple
tools, detecting structural anomalies, and identifying generated evidence
through statistical analysis.
"""

import struct
import os
import math
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum


class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IntegrityAlert:
    """An alert raised by the validator."""
    severity: AlertSeverity
    artifact_type: str
    artifact_path: str
    check_name: str
    description: str
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""


class MFTIntegrityChecker:
    """Detect generated MFT entries."""

    MFT_RECORD_SIZE = 1024
    MFT_MAGIC = b"FILE"

    def __init__(self, mft_path: str):
        self.mft_path = mft_path
        self.alerts: list[IntegrityAlert] = []

    def check_all(self) -> list[IntegrityAlert]:
        with open(self.mft_path, "rb") as f:
            data = f.read()

        self._check_sequence_gaps(data)
        self._check_timestamp_entropy(data)
        self._check_attribute_ordering(data)
        self._check_logfile_sequence(data)
        return self.alerts

    def _check_sequence_gaps(self, data: bytes) -> None:
        """Detect gaps in MFT sequence numbers indicating synthesis."""
        record_count = len(data) // self.MFT_RECORD_SIZE
        sequences = []

        for i in range(record_count):
            offset = i * self.MFT_RECORD_SIZE
            if data[offset:offset + 4] != self.MFT_MAGIC:
                continue
            flags = struct.unpack_from("<H", data, offset + 0x16)[0]
            if flags & 0x01:  # in-use
                seq = struct.unpack_from("<H", data, offset + 0x12)[0]
                sequences.append((i, seq))

        # Look for in-use records with seq=1 surrounded by higher sequences
        for idx, (rec_num, seq) in enumerate(sequences):
            if seq == 1 and rec_num > 24:
                neighbors = []
                for j in range(max(0, idx - 3), min(len(sequences), idx + 4)):
                    if j != idx:
                        neighbors.append(sequences[j][1])
                if neighbors and all(n > 2 for n in neighbors):
                    self.alerts.append(IntegrityAlert(
                        severity=AlertSeverity.HIGH,
                        artifact_type="MFT",
                        artifact_path=self.mft_path,
                        check_name="sequence_gap",
                        description=(
                            f"MFT record #{rec_num} has sequence number 1 "
                            f"while neighbors have sequences {neighbors}. "
                            f"This suggests a freshly synthesized record."
                        ),
                        evidence={"record": rec_num, "sequence": seq, "neighbors": neighbors},
                        recommendation="Cross-reference with $LogFile and $UsnJrnl",
                    ))

    def _check_timestamp_entropy(self, data: bytes) -> None:
        """Detect statistically improbable timestamp patterns."""
        timestamps = []
        record_count = len(data) // self.MFT_RECORD_SIZE

        for i in range(24, record_count):
            offset = i * self.MFT_RECORD_SIZE
            if data[offset:offset + 4] != self.MFT_MAGIC:
                continue
            flags = struct.unpack_from("<H", data, offset + 0x16)[0]
            if not (flags & 0x01):
                continue

            # Read $SI timestamps (first attribute, typically at offset 0x38+0x18)
            first_attr_offset = struct.unpack_from("<H", data, offset + 0x14)[0]
            si_offset = offset + first_attr_offset
            if si_offset + 0x48 > len(data):
                continue

            attr_type = struct.unpack_from("<I", data, si_offset)[0]
            if attr_type != 0x10:  # $STANDARD_INFORMATION
                continue

            body_offset = si_offset + 0x18
            if body_offset + 32 > len(data):
                continue

            created = struct.unpack_from("<Q", data, body_offset)[0]
            modified = struct.unpack_from("<Q", data, body_offset + 8)[0]

            if created > 0 and modified > 0:
                timestamps.append({
                    "record": i,
                    "created": created,
                    "modified": modified,
                })

        if len(timestamps) < 10:
            return

        # Check for clusters of identical sub-second precision (synthesis artifact)
        nanosecond_parts = [t["created"] % 10_000_000 for t in timestamps]
        zero_count = sum(1 for ns in nanosecond_parts if ns == 0)
        zero_ratio = zero_count / len(nanosecond_parts)

        if zero_ratio > 0.3:
            self.alerts.append(IntegrityAlert(
                severity=AlertSeverity.MEDIUM,
                artifact_type="MFT",
                artifact_path=self.mft_path,
                check_name="timestamp_precision",
                description=(
                    f"{zero_count}/{len(nanosecond_parts)} timestamps have "
                    f"zero sub-second precision ({zero_ratio:.0%}). "
                    f"Genuine NTFS timestamps almost always have non-zero "
                    f"100-nanosecond components. High zero ratios suggest "
                    f"programmatic timestamp generation."
                ),
                evidence={"zero_count": zero_count, "total": len(nanosecond_parts)},
                recommendation="Examine records with zero sub-second precision",
            ))

    def _check_attribute_ordering(self, data: bytes) -> None:
        """Check that attributes follow standard ordering."""
        record_count = len(data) // self.MFT_RECORD_SIZE

        for i in range(24, record_count):
            offset = i * self.MFT_RECORD_SIZE
            if data[offset:offset + 4] != self.MFT_MAGIC:
                continue
            flags = struct.unpack_from("<H", data, offset + 0x16)[0]
            if not (flags & 0x01):
                continue

            first_attr = struct.unpack_from("<H", data, offset + 0x14)[0]
            attr_offset = offset + first_attr
            prev_type = 0
            attr_types = []

            while attr_offset < offset + self.MFT_RECORD_SIZE - 8:
                attr_type = struct.unpack_from("<I", data, attr_offset)[0]
                if attr_type == 0xFFFFFFFF:
                    break
                attr_len = struct.unpack_from("<I", data, attr_offset + 4)[0]
                if attr_len == 0 or attr_len > self.MFT_RECORD_SIZE:
                    break
                attr_types.append(attr_type)
                if attr_type < prev_type:
                    self.alerts.append(IntegrityAlert(
                        severity=AlertSeverity.MEDIUM,
                        artifact_type="MFT",
                        artifact_path=self.mft_path,
                        check_name="attribute_order",
                        description=(
                            f"MFT record #{i} has out-of-order attributes: "
                            f"{[hex(t) for t in attr_types]}. "
                            f"NTFS stores attributes in ascending type order."
                        ),
                        evidence={"record": i, "attr_types": [hex(t) for t in attr_types]},
                    ))
                    break
                prev_type = attr_type
                attr_offset += attr_len

    def _check_logfile_sequence(self, data: bytes) -> None:
        """Check $LogFile sequence numbers for consistency."""
        record_count = len(data) // self.MFT_RECORD_SIZE
        lsn_values = []

        for i in range(24, record_count):
            offset = i * self.MFT_RECORD_SIZE
            if data[offset:offset + 4] != self.MFT_MAGIC:
                continue
            flags = struct.unpack_from("<H", data, offset + 0x16)[0]
            if not (flags & 0x01):
                continue
            lsn = struct.unpack_from("<Q", data, offset + 0x08)[0]
            if lsn > 0:
                lsn_values.append((i, lsn))

        # Records with LSN=0 in an MFT where others have high LSNs
        if lsn_values:
            max_lsn = max(lsn for _, lsn in lsn_values)
            for i in range(24, record_count):
                offset = i * self.MFT_RECORD_SIZE
                if data[offset:offset + 4] != self.MFT_MAGIC:
                    continue
                flags = struct.unpack_from("<H", data, offset + 0x16)[0]
                if not (flags & 0x01):
                    continue
                lsn = struct.unpack_from("<Q", data, offset + 0x08)[0]
                if lsn == 0 and max_lsn > 1000:
                    self.alerts.append(IntegrityAlert(
                        severity=AlertSeverity.HIGH,
                        artifact_type="MFT",
                        artifact_path=self.mft_path,
                        check_name="logfile_sequence",
                        description=(
                            f"MFT record #{i} has $LogFile sequence number 0 "
                            f"while other records reach LSN {max_lsn}. "
                            f"Synthesized records bypass the NTFS journal."
                        ),
                        evidence={"record": i, "lsn": 0, "max_lsn": max_lsn},
                        recommendation="Verify against $LogFile and $UsnJrnl entries",
                    ))


class EVTXIntegrityChecker:
    """Detect generated EVTX records."""

    def __init__(self, evtx_path: str):
        self.evtx_path = evtx_path
        self.alerts: list[IntegrityAlert] = []

    def check_all(self) -> list[IntegrityAlert]:
        with open(self.evtx_path, "rb") as f:
            data = f.read()

        self._check_record_id_gaps(data)
        self._check_timestamp_monotonicity(data)
        return self.alerts

    def _check_record_id_gaps(self, data: bytes) -> None:
        """Detect gaps or duplicates in EventRecordID sequence."""
        record_ids = []
        offset = 0x1000 + 0x200  # first chunk, after chunk header

        while offset < len(data) - 24:
            magic = data[offset:offset + 4]
            if magic == b"\x2a\x2a\x00\x00":
                size = struct.unpack_from("<I", data, offset + 4)[0]
                if 24 < size < 0x10000:
                    record_id = struct.unpack_from("<Q", data, offset + 8)[0]
                    record_ids.append(record_id)
                    offset += size
                else:
                    offset += 8
            else:
                offset += 8

        if len(record_ids) < 2:
            return

        for i in range(1, len(record_ids)):
            gap = record_ids[i] - record_ids[i - 1]
            if gap > 1:
                self.alerts.append(IntegrityAlert(
                    severity=AlertSeverity.MEDIUM,
                    artifact_type="EVTX",
                    artifact_path=self.evtx_path,
                    check_name="record_id_gap",
                    description=(
                        f"EventRecordID gap: {record_ids[i-1]} → {record_ids[i]} "
                        f"(gap of {gap}). May indicate deleted or synthesized records."
                    ),
                    evidence={"before": record_ids[i - 1], "after": record_ids[i], "gap": gap},
                ))
            elif gap <= 0:
                self.alerts.append(IntegrityAlert(
                    severity=AlertSeverity.CRITICAL,
                    artifact_type="EVTX",
                    artifact_path=self.evtx_path,
                    check_name="record_id_duplicate",
                    description=(
                        f"EventRecordID non-monotonic: {record_ids[i-1]} → {record_ids[i]}. "
                        f"Duplicate or out-of-order IDs indicate tampering."
                    ),
                    evidence={"id_a": record_ids[i - 1], "id_b": record_ids[i]},
                ))

    def _check_timestamp_monotonicity(self, data: bytes) -> None:
        """Event timestamps should be monotonically increasing."""
        timestamps = []
        offset = 0x1000 + 0x200

        while offset < len(data) - 24:
            magic = data[offset:offset + 4]
            if magic == b"\x2a\x2a\x00\x00":
                size = struct.unpack_from("<I", data, offset + 4)[0]
                if 24 < size < 0x10000:
                    record_id = struct.unpack_from("<Q", data, offset + 8)[0]
                    ts = struct.unpack_from("<Q", data, offset + 16)[0]
                    timestamps.append((record_id, ts))
                    offset += size
                else:
                    offset += 8
            else:
                offset += 8

        for i in range(1, len(timestamps)):
            if timestamps[i][1] < timestamps[i - 1][1]:
                self.alerts.append(IntegrityAlert(
                    severity=AlertSeverity.HIGH,
                    artifact_type="EVTX",
                    artifact_path=self.evtx_path,
                    check_name="timestamp_regression",
                    description=(
                        f"Timestamp regression at record {timestamps[i][0]}: "
                        f"timestamp goes backward from previous record. "
                        f"Event log timestamps should be monotonically increasing."
                    ),
                    evidence={
                        "record_a": timestamps[i - 1][0],
                        "record_b": timestamps[i][0],
                    },
                ))


class CrossSourceValidator:
    """Validate evidence consistency across multiple artifact sources."""

    def __init__(self):
        self.alerts: list[IntegrityAlert] = []

    def validate_execution_evidence(
        self,
        prefetch_programs: list[str],
        userassist_programs: list[str],
        shimcache_programs: list[str],
        evtx_4688_programs: list[str],
    ) -> list[IntegrityAlert]:
        """Cross-reference program execution evidence across sources.

        Legitimate execution typically leaves traces in multiple sources.
        Evidence in only one source may indicate generation.
        """
        all_programs = set()
        all_programs.update(prefetch_programs)
        all_programs.update(userassist_programs)
        all_programs.update(shimcache_programs)
        all_programs.update(evtx_4688_programs)

        for prog in all_programs:
            sources = []
            if prog in prefetch_programs:
                sources.append("Prefetch")
            if prog in userassist_programs:
                sources.append("UserAssist")
            if prog in shimcache_programs:
                sources.append("ShimCache")
            if prog in evtx_4688_programs:
                sources.append("EVTX-4688")

            if len(sources) == 1:
                self.alerts.append(IntegrityAlert(
                    severity=AlertSeverity.MEDIUM,
                    artifact_type="cross-source",
                    artifact_path="multiple",
                    check_name="single_source_execution",
                    description=(
                        f"Program '{prog}' has execution evidence ONLY in "
                        f"{sources[0]}. Legitimate execution typically leaves "
                        f"traces in multiple sources (Prefetch, UserAssist, "
                        f"ShimCache, Event Logs). Single-source evidence may "
                        f"indicate targeted artifact synthesis."
                    ),
                    evidence={"program": prog, "sources": sources},
                    recommendation=(
                        f"Verify execution through additional sources: "
                        f"AmCache, SRUM, BAM/DAM"
                    ),
                ))
            elif len(sources) >= 3:
                # High consistency — but check if timestamps align
                self.alerts.append(IntegrityAlert(
                    severity=AlertSeverity.INFO,
                    artifact_type="cross-source",
                    artifact_path="multiple",
                    check_name="multi_source_confirmed",
                    description=(
                        f"Program '{prog}' confirmed across {len(sources)} "
                        f"sources: {', '.join(sources)}. "
                        f"Note: sophisticated generation can plant consistent "
                        f"evidence across all sources."
                    ),
                    evidence={"program": prog, "sources": sources},
                    recommendation="Verify timestamp consistency across sources",
                ))

        return self.alerts
