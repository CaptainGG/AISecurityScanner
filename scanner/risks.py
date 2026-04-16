"""Risky Python code detection rules."""

from __future__ import annotations

import re
from typing import Any


RISK_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\beval\s*\("), "eval()", "Use of eval() can execute untrusted code."),
    (re.compile(r"\bexec\s*\("), "exec()", "Use of exec() can execute untrusted code."),
    (
        re.compile(r"\bpickle\.load\s*\("),
        "pickle.load()",
        "Loading pickle data can execute code from untrusted input.",
    ),
    (
        re.compile(r"\bos\.system\s*\("),
        "os.system()",
        "Shell command execution can be dangerous with untrusted input.",
    ),
    (
        re.compile(r"\bsubprocess\.Popen\s*\("),
        "subprocess.Popen()",
        "Subprocess execution should be reviewed for command injection risk.",
    ),
    (
        re.compile(r"\bsubprocess\.run\s*\(.*shell\s*=\s*True"),
        "subprocess.run(shell=True)",
        "subprocess.run() with shell=True can allow command injection.",
    ),
]


def detect_risky_code(lines: list[str], suffix: str) -> list[dict[str, Any]]:
    """Detect risky function calls in Python files."""
    if suffix != ".py":
        return []

    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(lines, start=1):
        for pattern, issue_type, message in RISK_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "line_number": line_number,
                        "category": "risky_function",
                        "issue_type": issue_type,
                        "severity": "Medium",
                        "message": message,
                    }
                )

    return findings
