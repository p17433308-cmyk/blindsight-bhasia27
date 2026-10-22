"""
BlindSight Validator — Report generation.
"""

import json
from datetime import datetime
from typing import Optional
from .integrity import IntegrityAlert, AlertSeverity


def generate_validation_report(
    alerts: list[IntegrityAlert],
    title: str = "BlindSight Evidence Integrity Report",
    output_path: Optional[str] = None,
) -> str:
    counts = {}
    for a in alerts:
        counts[a.severity.value] = counts.get(a.severity.value, 0) + 1

    verdict = "CLEAN"
    if counts.get("critical", 0) > 0:
        verdict = "COMPROMISED — CRITICAL indicators of evidence generation"
    elif counts.get("high", 0) > 0:
        verdict = "SUSPICIOUS — High-confidence anomalies detected"
    elif counts.get("medium", 0) > 0:
        verdict = "REVIEW — Anomalies warrant further investigation"

    lines = [
        f"# {title}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total alerts: {len(alerts)}",
        "",
        f"## Verdict: {verdict}",
        "",
        "## Alert Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            lines.append(f"| {sev.upper()} | {counts[sev]} |")

    lines.extend(["", "## Detailed Alerts", ""])

    for i, alert in enumerate(
        sorted(alerts, key=lambda a: list(AlertSeverity).index(a.severity)), 1
    ):
        lines.extend([
            f"### #{i} [{alert.severity.value.upper()}] {alert.check_name}",
            f"**Type:** {alert.artifact_type}",
            f"**Path:** `{alert.artifact_path}`",
            "",
            alert.description,
            "",
        ])
        if alert.recommendation:
            lines.append(f"**Recommendation:** {alert.recommendation}")
            lines.append("")
        if alert.evidence:
            lines.append(f"**Evidence:** `{json.dumps(alert.evidence)}`")
            lines.append("")
        lines.extend(["---", ""])

    report = "\n".join(lines)
    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
    return report


def generate_json_report(
    alerts: list[IntegrityAlert],
    output_path: Optional[str] = None,
) -> str:
    data = {
        "generated": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "alerts": [
            {
                "severity": a.severity.value,
                "type": a.artifact_type,
                "path": a.artifact_path,
                "check": a.check_name,
                "description": a.description,
                "evidence": a.evidence,
                "recommendation": a.recommendation,
            }
            for a in alerts
        ],
    }
    report = json.dumps(data, indent=2)
    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
    return report
