from scanner.engine import build_text_report, scan_text


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
