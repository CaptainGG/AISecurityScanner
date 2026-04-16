"""Human-readable and JSON reporting helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def format_text_report(report: dict[str, Any], quiet: bool = False) -> str:
    """Format a scanner report for terminal output or text download."""
    scanned_files = report["scanned_files"]
    total_findings = report["total_findings"]
    lines = [
        "AI Code Security Scanner",
        "=" * 25,
        f"Target: {report['target']}",
        f"Files scanned: {scanned_files}",
        f"Findings: {total_findings}",
    ]

    if scanned_files == 0:
        lines.extend(
            [
                "",
                "No supported files found. Supported types: .py, .json, .env, .txt, .md",
            ]
        )
        return "\n".join(lines)

    if quiet:
        return "\n".join(lines)

    if total_findings == 0:
        lines.extend(["", "No issues found."])
        return "\n".join(lines)

    lines.extend(["", "Findings", "-" * 8])

    for file_report in report["files"]:
        lines.append("")
        lines.append(
            f"{file_report['file_path']} "
            f"(score: {file_report['score']}, risk: {file_report['risk_level']})"
        )
        for finding in file_report["findings"]:
            lines.append(
                "  "
                f"Line {finding['line_number']}: "
                f"[{finding['severity']}] "
                f"{finding['category']} - {finding['issue_type']}"
            )
            lines.append(f"    {finding['message']}")

    return "\n".join(lines)


def print_report(report: dict[str, Any], quiet: bool = False) -> None:
    """Print a terminal report."""
    print(format_text_report(report, quiet=quiet))


def write_json_report(report: dict[str, Any], output_path: Path) -> None:
    """Write a JSON report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
