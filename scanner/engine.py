"""Scanning engine that coordinates file loading and detectors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.prompt_leak import detect_prompt_leaks
from scanner.risks import detect_risky_code
from scanner.scoring import score_findings
from scanner.secrets import detect_secrets
from utils.file_loader import collect_supported_files, read_text_lines


def scan_text(label: str, content: str, suffix: str, file_name: str | None = None) -> dict[str, Any]:
    """Scan text content without reading or writing a file."""
    display_name = file_name or label
    lines = content.splitlines()
    findings = []
    findings.extend(detect_secrets(lines))
    findings.extend(detect_risky_code(lines, suffix.lower()))
    findings.extend(detect_prompt_leaks(lines, suffix.lower(), display_name))

    for finding in findings:
        finding["file_path"] = label

    score, risk_level = score_findings(findings)
    return {
        "file_path": label,
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
    }


def build_text_report(target: str, items: list[dict[str, str]]) -> dict[str, Any]:
    """Build a scanner report from in-memory text items."""
    file_reports = [
        scan_text(
            label=item["label"],
            content=item["content"],
            suffix=item["suffix"],
            file_name=item.get("file_name"),
        )
        for item in items
    ]
    total_findings = sum(len(file_report["findings"]) for file_report in file_reports)

    return {
        "target": target,
        "scanned_files": len(file_reports),
        "total_findings": total_findings,
        "files": file_reports,
    }


def scan_path(target: Path) -> dict[str, Any]:
    """Scan a file or directory and return a structured report."""
    if not target.exists():
        raise FileNotFoundError(f"path does not exist: {target}")

    files = collect_supported_files(target)
    file_reports: list[dict[str, Any]] = []
    total_findings = 0

    for file_path in files:
        lines = read_text_lines(file_path)
        file_report = scan_text(
            label=str(file_path),
            content="\n".join(lines),
            suffix=file_path.suffix.lower(),
            file_name=file_path.name,
        )
        total_findings += len(file_report["findings"])

        if file_report["findings"]:
            file_reports.append(file_report)

    return {
        "target": str(target),
        "scanned_files": len(files),
        "total_findings": total_findings,
        "files": file_reports,
    }
