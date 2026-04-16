from web_app import _is_supported_name, _suffix_for_name


def test_upload_name_support_matches_scanner_types() -> None:
    assert _is_supported_name("app.py") is True
    assert _is_supported_name(".env") is True
    assert _is_supported_name("notes.pdf") is False


def test_suffix_for_upload_name() -> None:
    assert _suffix_for_name("config.env") == ".env"
    assert _suffix_for_name("README.md") == ".md"
