from scanner.engine import build_text_report, scan_text
from scanner.engine import scan_github_repository


class _FakeDownloadedRepo:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type, exc, traceback):
        return False


def test_scan_text_detects_risky_python() -> None:
    report = scan_text("pasted-code.py", "result = eval(user_input)", ".py")
    assert report["findings"][0]["issue_type"] == "eval()"
    assert report["score"] == 3


def test_scan_text_detects_env_secret() -> None:
    report = scan_text(".env", 'password = "super-secret-value"', ".env", ".env")
    assert report["findings"][0]["category"] == "hardcoded_secret"
    assert report["risk_level"] == "Medium"


def test_build_text_report_keeps_clean_items() -> None:
    report = build_text_report(
        "web upload",
        [
            {
                "label": "notes.txt",
                "file_name": "notes.txt",
                "suffix": ".txt",
                "content": "ordinary release notes",
            }
        ],
    )
    assert report["scanned_files"] == 1
    assert report["total_findings"] == 0
    assert report["files"][0]["file_path"] == "notes.txt"


def test_scan_github_repository_uses_relative_paths(monkeypatch, tmp_path) -> None:
    repo_root = tmp_path / "repo-main"
    repo_root.mkdir()
    (repo_root / "app.py").write_text("result = eval(user_input)", encoding="utf-8")

    monkeypatch.setattr(
        "scanner.engine.downloaded_github_repository",
        lambda repo_url: _FakeDownloadedRepo(repo_root),
    )

    report = scan_github_repository("https://github.com/owner/repo")
    assert report["target"] == "https://github.com/owner/repo"
    assert report["scanned_files"] == 1
    assert report["files"][0]["file_path"] == "app.py"
