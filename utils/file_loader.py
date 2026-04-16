"""File discovery and safe text loading utilities."""

from __future__ import annotations

from pathlib import Path


SUPPORTED_EXTENSIONS = {".py", ".json", ".env", ".txt", ".md"}
DEFAULT_IGNORED_DIRS = {
    ".git",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "node_modules",
    "venv",
}


def is_supported_file(path: Path) -> bool:
    """Return True when a file should be scanned."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    return suffix in SUPPORTED_EXTENSIONS or name == ".env"


def _is_ignored(path: Path, ignored_dirs: set[str]) -> bool:
    """Return True when a path is inside an ignored directory."""
    return any(part in ignored_dirs for part in path.parts)


def collect_supported_files(
    target: Path,
    ignored_dirs: set[str] | None = None,
    max_files: int | None = None,
) -> list[Path]:
    """Collect supported files from a file or directory."""
    ignored = ignored_dirs or DEFAULT_IGNORED_DIRS

    if target.is_file():
        return [target] if is_supported_file(target) else []

    files = sorted(
        path
        for path in target.rglob("*")
        if path.is_file() and is_supported_file(path) and not _is_ignored(path.relative_to(target), ignored)
    )

    if max_files is not None and len(files) > max_files:
        raise ValueError(f"too many supported files found: {len(files)} exceeds {max_files}")

    return files


def read_text_lines(path: Path) -> list[str]:
    """Read a text file safely and return its lines."""
    return path.read_text(encoding="utf-8", errors="replace").splitlines()
