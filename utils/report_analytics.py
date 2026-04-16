"""Build visualization data from scanner JSON reports."""

from __future__ import annotations

from typing import Any


SEVERITY_LABELS = ["High", "Medium", "Low"]
SEVERITY_COLORS = {
    "High": "#b3261e",
    "Medium": "#8a5a00",
    "Low": "#1f7a4d",
}
CATEGORY_LABELS = {
    "hardcoded_secret": "Hardcoded secrets",
    "risky_function": "Risky functions",
    "prompt_leak": "Prompt leak indicators",
}
RISK_LEVELS = ["High", "Medium", "Low"]


def validate_report(report: Any) -> dict[str, Any]:
    """Validate the expected scanner report shape."""
    if not isinstance(report, dict):
        raise ValueError("JSON report must be an object.")

    required_keys = {"target", "scanned_files", "total_findings", "files"}
    if not required_keys.issubset(report):
        raise ValueError("JSON report is missing required scanner fields.")

    if not isinstance(report["files"], list):
        raise ValueError("JSON report field 'files' must be a list.")

    for file_report in report["files"]:
        if not isinstance(file_report, dict):
            raise ValueError("Each file report must be an object.")
        file_keys = {"file_path", "score", "risk_level", "findings"}
        if not file_keys.issubset(file_report):
            raise ValueError("A file report is missing required fields.")
        if not isinstance(file_report["findings"], list):
            raise ValueError("File report field 'findings' must be a list.")

        for finding in file_report["findings"]:
            if not isinstance(finding, dict):
                raise ValueError("Each finding must be an object.")
            finding_keys = {"line_number", "category", "issue_type", "severity", "message"}
            if not finding_keys.issubset(finding):
                raise ValueError("A finding is missing required fields.")

    return report


def _percent(value: int, total: int) -> int:
    """Return a rounded integer percentage."""
    if total <= 0:
        return 0
    return round((value / total) * 100)


def _severity_donut_style(severity_counts: dict[str, int], total: int) -> str:
    """Build a CSS conic-gradient for severity distribution."""
    if total <= 0:
        return "background: #eaf3ee;"

    cursor = 0
    segments = []
    for severity in SEVERITY_LABELS:
        count = severity_counts.get(severity, 0)
        if count == 0:
            continue

        next_cursor = cursor + (count / total) * 100
        color = SEVERITY_COLORS[severity]
        segments.append(f"{color} {cursor:.2f}% {next_cursor:.2f}%")
        cursor = next_cursor

    return f"background: conic-gradient({', '.join(segments)});"


def build_report_analytics(report: dict[str, Any]) -> dict[str, Any]:
    """Create chart-ready analytics for a scanner report."""
    validate_report(report)

    severity_counts = {severity: 0 for severity in SEVERITY_LABELS}
    category_counts = {label: 0 for label in CATEGORY_LABELS.values()}
    risk_counts = {risk_level: 0 for risk_level in RISK_LEVELS}

    for file_report in report["files"]:
        risk_level = file_report.get("risk_level", "Low")
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1

        for finding in file_report["findings"]:
            severity = finding.get("severity", "Low")
            if severity in severity_counts:
                severity_counts[severity] += 1

            category = finding.get("category", "")
            category_label = CATEGORY_LABELS.get(category, category.replace("_", " ").title())
            category_counts[category_label] = category_counts.get(category_label, 0) + 1

    reported_file_count = len(report["files"])
    clean_file_count = max(int(report.get("scanned_files", 0)) - reported_file_count, 0)
    risk_counts["Low"] += clean_file_count

    total_findings = sum(severity_counts.values())
    severity_items = [
        {
            "label": severity,
            "count": count,
            "percent": _percent(count, total_findings),
            "color": SEVERITY_COLORS[severity],
        }
        for severity, count in severity_counts.items()
    ]

    max_category_count = max(category_counts.values(), default=0)
    category_items = [
        {
            "label": label,
            "count": count,
            "percent": _percent(count, max_category_count),
        }
        for label, count in category_counts.items()
        if count > 0
    ]

    risky_files = sorted(
        [
            {
                "file_path": file_report["file_path"],
                "score": int(file_report.get("score", 0)),
                "risk_level": file_report.get("risk_level", "Low"),
                "finding_count": len(file_report.get("findings", [])),
            }
            for file_report in report["files"]
        ],
        key=lambda item: (item["score"], item["finding_count"]),
        reverse=True,
    )[:5]
    max_file_score = max((file_report["score"] for file_report in risky_files), default=0)

    top_files = [
        {
            **file_report,
            "percent": _percent(file_report["score"], max_file_score),
        }
        for file_report in risky_files
        if file_report["score"] > 0 or file_report["finding_count"] > 0
    ]

    risk_items = [
        {
            "label": risk_level,
            "count": count,
            "percent": _percent(count, int(report.get("scanned_files", 0))),
        }
        for risk_level, count in risk_counts.items()
    ]

    return {
        "has_findings": total_findings > 0,
        "severity_items": severity_items,
        "severity_donut_style": _severity_donut_style(severity_counts, total_findings),
        "category_items": category_items,
        "top_files": top_files,
        "risk_items": risk_items,
    }
