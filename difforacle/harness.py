"""
DiffOracle — Automated parser differential finder for forensic tools.

Runs the same forensic artifact through multiple tools and compares
their output. Discovers cases where tools produce contradictory
interpretations of identical evidence.
"""

import subprocess
import json
import os
import csv
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


class ToolType(Enum):
    SLEUTHKIT = "sleuthkit"
    AUTOPSY = "autopsy"
    PLASO = "plaso"
    VOLATILITY3 = "volatility3"
    REGRIPPER = "regripper"


class ArtifactType(Enum):
    DISK_IMAGE = "disk_image"
    MFT = "mft"
    EVTX = "evtx"
    REGISTRY = "registry"
    MEMORY = "memory"
    SQLITE = "sqlite"


@dataclass
class ToolResult:
    """Result from running a single forensic tool on an artifact."""
    tool: ToolType
    artifact_type: ArtifactType
    raw_output: str
    parsed_records: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    runtime_seconds: float = 0.0


@dataclass
class Differential:
    """A discovered parser differential between two tools."""
    artifact_path: str
    artifact_type: ArtifactType
    tool_a: ToolType
    tool_b: ToolType
    field_name: str
    value_a: str
    value_b: str
    record_id: str
    severity: str  # "critical", "high", "medium", "low"
    description: str


class ToolRunner:
    """Run forensic tools and capture their output."""

    def __init__(self):
        self.tool_paths: dict[ToolType, str] = {}
        self._detect_tools()

    def _detect_tools(self) -> None:
        tools = {
            ToolType.SLEUTHKIT: ["icat", "fls", "mmls", "istat"],
            ToolType.PLASO: ["log2timeline.py", "log2timeline"],
            ToolType.VOLATILITY3: ["vol", "vol.py", "volatility3"],
            ToolType.REGRIPPER: ["rip.pl", "regripper"],
        }
        for tool_type, binaries in tools.items():
            for binary in binaries:
                path = self._which(binary)
                if path:
                    self.tool_paths[tool_type] = path
                    break

    @staticmethod
    def _which(binary: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["which", binary],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def run_sleuthkit_fls(self, image_path: str, offset: int = 0) -> ToolResult:
        """Run Sleuthkit fls (file listing) on a disk image."""
        start = datetime.now()
        try:
            cmd = ["fls", "-r", "-m", "/", "-o", str(offset), image_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            elapsed = (datetime.now() - start).total_seconds()

            records = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 11:
                        records.append({
                            "md5": parts[0],
                            "name": parts[1],
                            "inode": parts[2],
                            "mode": parts[3],
                            "uid": parts[4],
                            "gid": parts[5],
                            "size": parts[6],
                            "atime": parts[7],
                            "mtime": parts[8],
                            "ctime": parts[9],
                            "crtime": parts[10] if len(parts) > 10 else "",
                        })

            return ToolResult(
                tool=ToolType.SLEUTHKIT,
                artifact_type=ArtifactType.DISK_IMAGE,
                raw_output=result.stdout,
                parsed_records=records,
                error=result.stderr if result.returncode != 0 else None,
                runtime_seconds=elapsed,
            )
        except Exception as e:
            return ToolResult(
                tool=ToolType.SLEUTHKIT,
                artifact_type=ArtifactType.DISK_IMAGE,
                raw_output="",
                error=str(e),
            )

    def run_plaso(self, image_path: str) -> ToolResult:
        """Run Plaso/log2timeline on an image or artifact."""
        start = datetime.now()
        try:
            plaso_bin = self.tool_paths.get(ToolType.PLASO, "log2timeline.py")
            plaso_db = tempfile.mktemp(suffix=".plaso")

            cmd = [plaso_bin, "--status_view", "none", plaso_db, image_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            elapsed = (datetime.now() - start).total_seconds()

            # Extract timeline with psort
            records = []
            csv_out = tempfile.mktemp(suffix=".csv")
            psort_cmd = ["psort.py", "-o", "l2tcsv", "-w", csv_out, plaso_db]
            psort_result = subprocess.run(
                psort_cmd, capture_output=True, text=True, timeout=300
            )

            if os.path.exists(csv_out):
                with open(csv_out, "r") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        records.append(dict(row))
                os.unlink(csv_out)
            if os.path.exists(plaso_db):
                os.unlink(plaso_db)

            return ToolResult(
                tool=ToolType.PLASO,
                artifact_type=ArtifactType.DISK_IMAGE,
                raw_output=result.stdout,
                parsed_records=records,
                error=result.stderr if result.returncode != 0 else None,
                runtime_seconds=elapsed,
            )
        except Exception as e:
            return ToolResult(
                tool=ToolType.PLASO,
                artifact_type=ArtifactType.DISK_IMAGE,
                raw_output="",
                error=str(e),
            )

    def run_volatility3(self, dump_path: str, plugin: str = "windows.pslist") -> ToolResult:
        """Run Volatility3 on a memory dump."""
        start = datetime.now()
        try:
            vol_bin = self.tool_paths.get(ToolType.VOLATILITY3, "vol")
            cmd = [vol_bin, "-f", dump_path, "-r", "json", plugin]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            elapsed = (datetime.now() - start).total_seconds()

            records = []
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        records = data
                    elif isinstance(data, dict) and "rows" in data:
                        records = data["rows"]
                except json.JSONDecodeError:
                    pass

            return ToolResult(
                tool=ToolType.VOLATILITY3,
                artifact_type=ArtifactType.MEMORY,
                raw_output=result.stdout,
                parsed_records=records,
                error=result.stderr if result.returncode != 0 else None,
                runtime_seconds=elapsed,
            )
        except Exception as e:
            return ToolResult(
                tool=ToolType.VOLATILITY3,
                artifact_type=ArtifactType.MEMORY,
                raw_output="",
                error=str(e),
            )


class DiffOracle:
    """Compare outputs across forensic tools and find differentials."""

    def __init__(self):
        self.runner = ToolRunner()
        self.differentials: list[Differential] = []

    def compare_disk_tools(self, image_path: str) -> list[Differential]:
        """Compare Sleuthkit vs Plaso on a disk image."""
        tsk_result = self.runner.run_sleuthkit_fls(image_path)
        plaso_result = self.runner.run_plaso(image_path)

        diffs = self._find_timestamp_diffs(
            tsk_result, plaso_result, image_path, ArtifactType.DISK_IMAGE
        )
        self.differentials.extend(diffs)
        return diffs

    def compare_memory_tools(
        self, dump_path: str, plugins: list[str] = None
    ) -> list[Differential]:
        """Compare Volatility3 outputs across different plugins/profiles."""
        if plugins is None:
            plugins = ["windows.pslist", "windows.psscan"]

        results = []
        for plugin in plugins:
            result = self.runner.run_volatility3(dump_path, plugin)
            results.append((plugin, result))

        diffs = []
        if len(results) >= 2:
            # Compare pslist vs psscan — hidden processes show as differentials
            for i in range(len(results)):
                for j in range(i + 1, len(results)):
                    plugin_a, result_a = results[i]
                    plugin_b, result_b = results[j]

                    pids_a = {r.get("PID", r.get("pid")) for r in result_a.parsed_records}
                    pids_b = {r.get("PID", r.get("pid")) for r in result_b.parsed_records}

                    for pid in pids_a - pids_b:
                        diffs.append(Differential(
                            artifact_path=dump_path,
                            artifact_type=ArtifactType.MEMORY,
                            tool_a=ToolType.VOLATILITY3,
                            tool_b=ToolType.VOLATILITY3,
                            field_name="process_presence",
                            value_a=f"PID {pid} found by {plugin_a}",
                            value_b=f"PID {pid} NOT found by {plugin_b}",
                            record_id=str(pid),
                            severity="critical",
                            description=(
                                f"Process with PID {pid} visible in {plugin_a} "
                                f"but not {plugin_b} — potential hidden/unlinked process"
                            ),
                        ))

        self.differentials.extend(diffs)
        return diffs

    def _find_timestamp_diffs(
        self,
        result_a: ToolResult,
        result_b: ToolResult,
        artifact_path: str,
        artifact_type: ArtifactType,
    ) -> list[Differential]:
        """Compare timestamp interpretations between two tool results."""
        diffs = []

        # Index by filename/inode
        records_a = {r.get("name", r.get("inode", "")): r for r in result_a.parsed_records}
        records_b = {r.get("name", r.get("inode", "")): r for r in result_b.parsed_records}

        time_fields = ["atime", "mtime", "ctime", "crtime", "timestamp", "date"]
        common_keys = set(records_a.keys()) & set(records_b.keys())

        for key in common_keys:
            rec_a = records_a[key]
            rec_b = records_b[key]

            for tf in time_fields:
                val_a = rec_a.get(tf, "")
                val_b = rec_b.get(tf, "")

                if val_a and val_b and val_a != val_b:
                    diffs.append(Differential(
                        artifact_path=artifact_path,
                        artifact_type=artifact_type,
                        tool_a=result_a.tool,
                        tool_b=result_b.tool,
                        field_name=tf,
                        value_a=str(val_a),
                        value_b=str(val_b),
                        record_id=key,
                        severity=self._assess_severity(tf, val_a, val_b),
                        description=(
                            f"Timestamp '{tf}' for '{key}' differs: "
                            f"{result_a.tool.value}={val_a} vs {result_b.tool.value}={val_b}"
                        ),
                    ))

        return diffs

    @staticmethod
    def _assess_severity(field_name: str, val_a: str, val_b: str) -> str:
        if field_name in ("mtime", "crtime"):
            return "critical"
        elif field_name in ("atime", "ctime"):
            return "high"
        return "medium"

    def generate_report(self, output_path: str) -> str:
        """Generate a differential analysis report."""
        lines = [
            "# DiffOracle — Parser Differential Report",
            f"Generated: {datetime.now().isoformat()}",
            f"Total differentials found: {len(self.differentials)}",
            "",
        ]

        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for d in self.differentials:
            by_severity.get(d.severity, by_severity["low"]).append(d)

        for severity in ["critical", "high", "medium", "low"]:
            group = by_severity[severity]
            if group:
                lines.append(f"## {severity.upper()} ({len(group)})")
                lines.append("")
                for d in group:
                    lines.append(f"### {d.description}")
                    lines.append(f"- Artifact: `{d.artifact_path}`")
                    lines.append(f"- Tool A ({d.tool_a.value}): `{d.value_a}`")
                    lines.append(f"- Tool B ({d.tool_b.value}): `{d.value_b}`")
                    lines.append(f"- Record: `{d.record_id}`")
                    lines.append("")

        report = "\n".join(lines)
        with open(output_path, "w") as f:
            f.write(report)
        return output_path

    def to_json(self) -> str:
        return json.dumps(
            [
                {
                    "artifact": d.artifact_path,
                    "type": d.artifact_type.value,
                    "tool_a": d.tool_a.value,
                    "tool_b": d.tool_b.value,
                    "field": d.field_name,
                    "value_a": d.value_a,
                    "value_b": d.value_b,
                    "record_id": d.record_id,
                    "severity": d.severity,
                    "description": d.description,
                }
                for d in self.differentials
            ],
            indent=2,
        )
