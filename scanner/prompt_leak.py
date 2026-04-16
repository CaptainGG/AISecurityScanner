"""Prompt leak and sensitive AI-comment detection rules."""

from __future__ import annotations

import re
from typing import Any


PROMPT_LEAK_PATTERN = re.compile(
    r"\b(user asked|internal prompt|system prompt|do not share|confidential|secret|token)\b",
    re.IGNORECASE,
)

TEXT_SUFFIXES = {".md", ".txt"}


def _is_env_file(suffix: str, file_name: str) -> bool:
    return suffix == ".env" or file_name.lower() == ".env"


def _is_obvious_text_context(line: str, suffix: str, file_name: str) -> bool:
    """Return True when a line is likely prose, a comment, or a string literal."""
    stripped = line.strip()

    if not stripped:
        return False

    if suffix in TEXT_SUFFIXES:
        return True

    if _is_env_file(suffix, file_name):
        return stripped.startswith("#")

    if suffix == ".py":
        return (
            stripped.startswith("#")
            or stripped.startswith(('"""', "'''"))
            or stripped.endswith(('"""', "'''"))
            or bool(re.search(r"[\"'].*[\"']", stripped))
        )

    if suffix == ".json":
        return bool(re.search(r'"[^"]*(user asked|internal prompt|system prompt|do not share|confidential|secret|token)[^"]*"', stripped, re.IGNORECASE))

    return False


def detect_prompt_leaks(
    lines: list[str], suffix: str, file_name: str = ""
) -> list[dict[str, Any]]:
    """Detect prompt leak indicators in comments and obvious text content."""
    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(lines, start=1):
        if not _is_obvious_text_context(line, suffix, file_name):
            continue

        match = PROMPT_LEAK_PATTERN.search(line)
        if match:
            findings.append(
                {
                    "line_number": line_number,
                    "category": "prompt_leak",
                    "issue_type": "Prompt leak indicator",
                    "severity": "Medium",
                    "message": f"Prompt leak indicator found: {match.group(1).lower()}.",
                }
            )

    return findings
