"""File discovery and safe text loading utilities."""

from __future__ import annotations

from pathlib import Path


SUPPORTED_EXTENSIONS = {".py", ".json", ".env", ".txt", ".md"}


def is_supported_file(path: Path) -> bool:
    """Return True when a file should be scanned."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    return suffix in SUPPORTED_EXTENSIONS or name == ".env"


def collect_supported_files(target: Path) -> list[Path]:
    """Collect supported files from a file or directory."""
    if target.is_file():
        return [target] if is_supported_file(target) else []

    return sorted(
        path
        for path in target.rglob("*")
        if path.is_file() and is_supported_file(path)
    )


def read_text_lines(path: Path) -> list[str]:
    """Read a text file safely and return its lines."""
    return path.read_text(encoding="utf-8", errors="replace").splitlines()
