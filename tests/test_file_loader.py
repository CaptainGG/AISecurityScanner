import pytest

from utils.file_loader import collect_supported_files


def test_collect_supported_files_skips_ignored_directories(tmp_path) -> None:
    (tmp_path / "app.py").write_text("print('ok')", encoding="utf-8")
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "ignored.py").write_text("print('skip')", encoding="utf-8")

    files = collect_supported_files(tmp_path)
    assert [path.name for path in files] == ["app.py"]


def test_collect_supported_files_enforces_max_files(tmp_path) -> None:
    (tmp_path / "one.py").write_text("print('one')", encoding="utf-8")
    (tmp_path / "two.py").write_text("print('two')", encoding="utf-8")

    with pytest.raises(ValueError):
        collect_supported_files(tmp_path, max_files=1)
