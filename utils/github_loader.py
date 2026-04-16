"""Download public GitHub repositories as temporary ZIP archives."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile


MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_REPO_FILES = 1000


class GitHubRepositoryError(ValueError):
    """Raised when a GitHub repository cannot be downloaded or scanned."""


@dataclass(frozen=True)
class GitHubRepoRef:
    """Parsed GitHub repository reference."""

    owner: str
    repo: str
    branch: str | None = None


def parse_github_url(repo_url: str) -> GitHubRepoRef:
    """Parse a public GitHub repository URL."""
    parsed = urlparse(repo_url.strip())
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        raise GitHubRepositoryError("Enter a valid GitHub repository URL.")

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise GitHubRepositoryError("GitHub URL must include an owner and repository name.")

    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    branch = None

    if len(parts) >= 4 and parts[2] == "tree":
        branch = unquote("/".join(parts[3:]).strip("/"))

    if not owner or not repo:
        raise GitHubRepositoryError("GitHub URL must include an owner and repository name.")

    return GitHubRepoRef(owner=owner, repo=repo, branch=branch)


def build_archive_url(repo_ref: GitHubRepoRef) -> str:
    """Build a GitHub ZIP archive URL."""
    if repo_ref.branch:
        branch = quote(repo_ref.branch, safe="/")
        archive_ref = f"refs/heads/{branch}"
    else:
        archive_ref = "HEAD"

    return f"https://github.com/{repo_ref.owner}/{repo_ref.repo}/archive/{archive_ref}.zip"


def download_archive(archive_url: str, max_bytes: int = MAX_ARCHIVE_BYTES) -> bytes:
    """Download a ZIP archive with a maximum size guard."""
    request = Request(
        archive_url,
        headers={"User-Agent": "AI-Code-Security-Scanner"},
    )

    try:
        with urlopen(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise GitHubRepositoryError("Repository archive is too large to scan.")

            archive_bytes = response.read(max_bytes + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise GitHubRepositoryError("Repository or branch was not found.") from exc
        raise GitHubRepositoryError(f"GitHub returned HTTP {exc.code}.") from exc
    except URLError as exc:
        raise GitHubRepositoryError(f"Could not download repository: {exc.reason}") from exc

    if len(archive_bytes) > max_bytes:
        raise GitHubRepositoryError("Repository archive is too large to scan.")

    return archive_bytes


def _safe_member_path(member_name: str) -> PurePosixPath:
    """Validate a ZIP member path before extraction."""
    normalized_name = member_name.replace("\\", "/")
    member_path = PurePosixPath(normalized_name)

    if member_path.is_absolute() or any(part in {"", ".", ".."} for part in member_path.parts):
        raise GitHubRepositoryError("Repository archive contains an unsafe file path.")

    return member_path


def extract_archive(archive_bytes: bytes, destination: Path) -> Path:
    """Safely extract a GitHub ZIP archive and return the repository root."""
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()

    try:
        with ZipFile(BytesIO(archive_bytes)) as archive:
            members = archive.infolist()
            if not members:
                raise GitHubRepositoryError("Repository archive is empty.")

            for member in members:
                member_path = _safe_member_path(member.filename)
                target_path = (destination / Path(*member_path.parts)).resolve()
                if destination_root not in target_path.parents and target_path != destination_root:
                    raise GitHubRepositoryError("Repository archive contains an unsafe file path.")
                archive.extract(member, destination)
    except BadZipFile as exc:
        raise GitHubRepositoryError("Downloaded repository archive is not a valid ZIP file.") from exc

    extracted_items = list(destination.iterdir())
    if len(extracted_items) == 1 and extracted_items[0].is_dir():
        return extracted_items[0]

    return destination


@contextmanager
def downloaded_github_repository(repo_url: str) -> Iterator[Path]:
    """Download and extract a public GitHub repository into a temporary directory."""
    repo_ref = parse_github_url(repo_url)
    archive_url = build_archive_url(repo_ref)
    archive_bytes = download_archive(archive_url)

    with TemporaryDirectory(prefix="ai-code-security-scanner-") as temp_dir:
        yield extract_archive(archive_bytes, Path(temp_dir))
