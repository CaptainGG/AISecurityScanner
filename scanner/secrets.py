"""Regex-based secret detection rules."""

from __future__ import annotations

import re
from typing import Any


SECRET_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "OpenAI API key",
        "High",
        "Potential OpenAI-style API key found.",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "AWS access key",
        "High",
        "Potential AWS access key found.",
    ),
    (
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b"),
        "Bearer token",
        "High",
        "Potential bearer token found.",
    ),
    (
        re.compile(
            r"\b(password|passwd|api[_-]?key|secret|token|access[_-]?token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']",
            re.IGNORECASE,
        ),
        "Credential assignment",
        "High",
        "Potential hardcoded credential assignment found.",
    ),
    (
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        "Email address",
        "Low",
        "Email address found.",
    ),
]


def detect_secrets(lines: list[str]) -> list[dict[str, Any]]:
    """Detect likely secrets and sensitive values in text lines."""
    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(lines, start=1):
        for pattern, issue_type, severity, message in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "line_number": line_number,
                        "category": "hardcoded_secret",
                        "issue_type": issue_type,
                        "severity": severity,
                        "message": message,
                    }
                )

    return findings
