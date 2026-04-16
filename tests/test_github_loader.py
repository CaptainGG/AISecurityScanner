from io import BytesIO
from zipfile import ZipFile

import pytest

from utils.github_loader import (
    GitHubRepositoryError,
    extract_archive,
    parse_github_url,
)


def _zip_bytes(files: dict[str, str]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


def test_parse_normal_repo_url() -> None:
    repo_ref = parse_github_url("https://github.com/owner/repo")
    assert repo_ref.owner == "owner"
    assert repo_ref.repo == "repo"
    assert repo_ref.branch is None


def test_parse_repo_url_with_trailing_slash() -> None:
    repo_ref = parse_github_url("https://github.com/owner/repo/")
    assert repo_ref.owner == "owner"
    assert repo_ref.repo == "repo"


def test_parse_branch_url() -> None:
    repo_ref = parse_github_url("https://github.com/owner/repo/tree/develop")
    assert repo_ref.branch == "develop"


def test_parse_invalid_url() -> None:
    with pytest.raises(GitHubRepositoryError):
        parse_github_url("https://example.com/owner/repo")


def test_extract_archive_returns_repo_root(tmp_path) -> None:
    archive_bytes = _zip_bytes(
        {
            "repo-main/app.py": "print('hello')",
            "repo-main/README.md": "# demo",
        }
    )
    repo_root = extract_archive(archive_bytes, tmp_path)
    assert repo_root.name == "repo-main"
    assert (repo_root / "app.py").exists()


def test_extract_archive_rejects_unsafe_paths(tmp_path) -> None:
    archive_bytes = _zip_bytes({"../evil.py": "print('bad')"})
    with pytest.raises(GitHubRepositoryError):
        extract_archive(archive_bytes, tmp_path)
