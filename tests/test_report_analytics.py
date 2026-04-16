import pytest

from utils.report_analytics import build_report_analytics, validate_report


def _sample_report():
    return {
        "target": "sample",
        "scanned_files": 2,
        "total_findings": 3,
        "files": [
            {
                "file_path": "app.py",
                "score": 8,
                "risk_level": "Medium",
                "findings": [
                    {
                        "line_number": 1,
                        "category": "hardcoded_secret",
                        "issue_type": "Credential assignment",
                        "severity": "High",
                        "message": "Potential hardcoded credential assignment found.",
                    },
                    {
                        "line_number": 2,
                        "category": "risky_function",
                        "issue_type": "eval()",
                        "severity": "Medium",
                        "message": "Use of eval() can execute untrusted code.",
                    },
                ],
            },
            {
                "file_path": "notes.md",
                "score": 2,
                "risk_level": "Low",
                "findings": [
                    {
                        "line_number": 3,
                        "category": "prompt_leak",
                        "issue_type": "Prompt leak indicator",
                        "severity": "Low",
                        "message": "Prompt leak indicator found.",
                    }
                ],
            },
        ],
    }


def test_build_report_analytics_counts_severity() -> None:
    analytics = build_report_analytics(_sample_report())
    severity_counts = {item["label"]: item["count"] for item in analytics["severity_items"]}
    assert severity_counts == {"High": 1, "Medium": 1, "Low": 1}


def test_build_report_analytics_counts_categories() -> None:
    analytics = build_report_analytics(_sample_report())
    category_counts = {item["label"]: item["count"] for item in analytics["category_items"]}
    assert category_counts["Hardcoded secrets"] == 1
    assert category_counts["Risky functions"] == 1
    assert category_counts["Prompt leak indicators"] == 1


def test_build_report_analytics_sorts_top_files() -> None:
    analytics = build_report_analytics(_sample_report())
    assert analytics["top_files"][0]["file_path"] == "app.py"
    assert analytics["top_files"][0]["score"] == 8


def test_build_report_analytics_handles_empty_report() -> None:
    analytics = build_report_analytics(
        {"target": "empty", "scanned_files": 0, "total_findings": 0, "files": []}
    )
    assert analytics["has_findings"] is False
    assert analytics["category_items"] == []
    assert analytics["top_files"] == []


def test_validate_report_rejects_wrong_shape() -> None:
    with pytest.raises(ValueError):
        validate_report({"target": "bad"})
