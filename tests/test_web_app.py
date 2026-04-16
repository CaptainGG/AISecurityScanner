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
