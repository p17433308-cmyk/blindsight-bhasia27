"""
DiffOracle Report — Generate differential analysis reports.
"""

import json
from datetime import datetime
from typing import Optional
from .harness import Differential


def generate_markdown_report(
    differentials: list[Differential],
    title: str = "DiffOracle Parser Differential Report",
    output_path: Optional[str] = None,
) -> str:
    lines = [
        f"# {title}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total differentials: {len(differentials)}",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    counts = {}
    for d in differentials:
        counts[d.severity] = counts.get(d.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low"]:
        if sev in counts:
            lines.append(f"| {sev.upper()} | {counts[sev]} |")

    lines.extend(["", "## Differentials", ""])

    for i, d in enumerate(differentials, 1):
        lines.extend([
            f"### #{i} [{d.severity.upper()}] {d.field_name}",
            f"**Artifact:** `{d.artifact_path}`",
            f"**Record:** `{d.record_id}`",
            "",
            f"| Tool | Value |",
            f"|------|-------|",
            f"| {d.tool_a.value} | `{d.value_a}` |",
            f"| {d.tool_b.value} | `{d.value_b}` |",
            "",
            f"> {d.description}",
            "",
            "---",
            "",
        ])

    report = "\n".join(lines)
    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
    return report


def generate_json_report(
    differentials: list[Differential],
    output_path: Optional[str] = None,
) -> str:
    data = {
        "generated": datetime.now().isoformat(),
        "total": len(differentials),
        "differentials": [
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
            for d in differentials
        ],
    }

    report = json.dumps(data, indent=2)
    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
    return report
