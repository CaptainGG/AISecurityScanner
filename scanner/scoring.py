"""Simple file-level risk scoring."""

from __future__ import annotations

from typing import Any


CATEGORY_POINTS = {
    "hardcoded_secret": 5,
    "risky_function": 3,
    "prompt_leak": 2,
}


def score_findings(findings: list[dict[str, Any]]) -> tuple[int, str]:
    """Calculate a numeric score and risk label for a file."""
    score = sum(CATEGORY_POINTS.get(finding.get("category", ""), 0) for finding in findings)

    if score >= 10:
        return score, "High"
    if score >= 5:
        return score, "Medium"
    return score, "Low"
