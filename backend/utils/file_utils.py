"""Small filesystem helpers shared by the scanner and validator."""

from __future__ import annotations

from pathlib import Path


def is_binary(path: Path, sample_size: int = 8192) -> bool:
    """Heuristic binary check: a NUL byte in the head of the file."""
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(sample_size)
    except OSError:
        return True


def read_text_safe(path: Path) -> str | None:
    """Read text, trying UTF-8 then latin-1. Returns None on failure."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except (OSError, UnicodeDecodeError):
            continue
    return None


def safe_relative_path(root: Path, path: Path) -> str | None:
    """Relative POSIX path, or None if the path escapes the root."""
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return path.relative_to(root).as_posix()
