"""Repository scanner: safe file discovery with ignore rules and limits.

Walks a cloned repository and decides which files are worth analyzing.
Generated, vendored, binary, and oversized files are skipped. Symlinks are
never followed. Nothing is executed.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings
from models.schemas import AnalyzedFile
from utils.constants import (
    IGNORED_DIRS,
    IGNORED_EXTENSIONS,
    LANGUAGE_BY_EXTENSION,
)
from utils.file_utils import is_binary, read_text_safe, safe_relative_path

logger = logging.getLogger(__name__)


class RepositoryTooLargeError(Exception):
    """Raised when a repository exceeds the configured analysis budget.

    Carries a stable machine-readable ``code`` so the API can return a
    structured error instead of a partial, silent result.
    """

    code = "REPOSITORY_TOO_LARGE"


class AnalysisTimeoutError(Exception):
    """Raised when the analysis wall-clock budget is exhausted."""

    code = "ANALYSIS_TIMEOUT"


def analysis_deadline() -> float | None:
    """Wall-clock deadline (monotonic seconds) for the analysis pipeline.

    Reads ``CODEAUDIT_ANALYSIS_WALL_CLOCK_SECONDS``; returns None when
    unset, meaning the pipeline runs without deadline checks.
    """
    raw = os.environ.get("CODEAUDIT_ANALYSIS_WALL_CLOCK_SECONDS", "").strip()
    if not raw:
        return None
    try:
        budget = float(raw)
    except ValueError:
        return None
    if budget <= 0:
        return None
    return time.monotonic() + budget


def check_deadline(deadline: float | None) -> None:
    """Raise AnalysisTimeoutError if a deadline has passed. No-op when None."""
    if deadline is not None and time.monotonic() > deadline:
        raise AnalysisTimeoutError(
            "Repository analysis exceeded its wall-clock budget."
        )


def detect_language(path: Path) -> str | None:
    """Language from file extension. None for unrecognized files."""
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


@dataclass
class ScanResult:
    files: list[AnalyzedFile] = field(default_factory=list)
    skipped: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)
    # relative_path -> file content, populated only for analyzed files.
    contents: dict[str, str] = field(default_factory=dict)


def _record_skip(result: ScanResult, reason: str) -> None:
    result.skipped += 1
    result.skipped_reasons[reason] = result.skipped_reasons.get(reason, 0) + 1


def scan_repository(root: Path, deadline: float | None = None) -> ScanResult:
    """Discover analyzable files under root. Never follows symlinks."""
    result = ScanResult()
    total_bytes = 0

    for path in sorted(root.rglob("*")):
        check_deadline(deadline)
        if path.is_symlink():
            _record_skip(result, "symlink")
            continue
        if not path.is_file():
            continue

        rel = safe_relative_path(root, path)
        if rel is None:
            _record_skip(result, "outside_root")
            continue

        # Ignore configured directories at any depth.
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts[:-1]):
            _record_skip(result, "ignored_dir")
            continue

        if path.suffix.lower() in IGNORED_EXTENSIONS:
            _record_skip(result, "ignored_extension")
            continue

        try:
            size = path.stat().st_size
        except OSError:
            _record_skip(result, "stat_failed")
            continue

        if size == 0:
            _record_skip(result, "empty")
            continue
        if size > settings.max_file_size_bytes:
            _record_skip(result, "too_large")
            continue
        if is_binary(path):
            _record_skip(result, "binary")
            continue
        if len(result.files) >= settings.max_files:
            # Hard budget breach: fail loudly with a structured error rather
            # than returning a partial, silent result.
            raise RepositoryTooLargeError(
                f"Repository exceeds the file-count budget ({settings.max_files} files). "
                "Increase CODEAUDIT_MAX_FILES or analyze a smaller scope."
            )
        if total_bytes + size > settings.max_total_bytes:
            raise RepositoryTooLargeError(
                f"Repository exceeds the analysis payload budget "
                f"({settings.max_total_bytes} bytes). Increase "
                "CODEAUDIT_MAX_TOTAL_BYTES or analyze a smaller scope."
            )

        content = read_text_safe(path)
        if content is None:
            _record_skip(result, "unreadable")
            continue

        language = detect_language(path)
        result.files.append(
            AnalyzedFile(relative_path=rel, language=language, size_bytes=size)
        )
        result.contents[rel] = content
        total_bytes += size

    logger.info(
        "Scan complete: %d files analyzed, %d skipped (%s)",
        len(result.files),
        result.skipped,
        result.skipped_reasons,
    )
    return result


def supports_deep_analysis(language: str | None) -> bool:
    """Whether deep (AST) analysis is available for this language.

    Delegates to the language analyzer registry, which is built from
    DEEP_ANALYSIS_LANGUAGES — one source of truth, no drift.
    """
    from services.languages.registry import get_analyzer

    return get_analyzer(language) is not None
