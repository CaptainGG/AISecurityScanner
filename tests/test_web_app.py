import json
from io import BytesIO

from web_app import _is_supported_name, _suffix_for_name, app


def test_upload_name_support_matches_scanner_types() -> None:
    assert _is_supported_name("app.py") is True
    assert _is_supported_name(".env") is True
    assert _is_supported_name("notes.pdf") is False


def test_suffix_for_upload_name() -> None:
    assert _suffix_for_name("config.env") == ".env"
    assert _suffix_for_name("README.md") == ".md"


def test_scan_route_accepts_github_url(monkeypatch) -> None:
    def fake_scan_github_repository(repo_url: str):
        return {
            "target": repo_url,
            "scanned_files": 1,
            "total_findings": 0,
            "files": [],
        }

    monkeypatch.setattr("web_app.scan_github_repository", fake_scan_github_repository)

    client = app.test_client()
    response = client.post(
        "/scan",
        data={"github_url": "https://github.com/owner/repo"},
    )

    assert response.status_code == 200
    assert b"Security Report" in response.data


def test_visualize_json_upload_renders_dashboard() -> None:
    report = {
        "target": "uploaded",
        "scanned_files": 1,
        "total_findings": 1,
        "files": [
            {
                "file_path": "app.py",
                "score": 3,
                "risk_level": "Low",
                "findings": [
                    {
                        "line_number": 1,
                        "category": "risky_function",
                        "issue_type": "eval()",
                        "severity": "Medium",
                        "message": "Use of eval() can execute untrusted code.",
                    }
                ],
            }
        ],
    }

    client = app.test_client()
    response = client.post(
        "/visualize-json",
        data={"report_json": (BytesIO(json.dumps(report).encode("utf-8")), "report.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert b"Severity mix" in response.data
    assert b"Risky functions" in response.data


def test_visualize_json_rejects_malformed_json() -> None:
    client = app.test_client()
    response = client.post(
        "/visualize-json",
        data={"report_json": (BytesIO(b"{not-json"), "report.json")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"The uploaded file is not valid JSON." in response.data


def test_visualize_json_rejects_wrong_shape() -> None:
    client = app.test_client()
    response = client.post(
        "/visualize-json",
        data={"report_json": (BytesIO(b'{"target": "bad"}'), "report.json")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"JSON report is missing required scanner fields." in response.data
