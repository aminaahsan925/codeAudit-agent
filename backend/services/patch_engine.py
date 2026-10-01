"""Patch engine: deterministic, fail-closed application of fix proposals.

Only this module ever turns a model's FixChange into bytes on disk, and it
only writes inside a caller-supplied repository root (the isolated
temporary workspace — never the original repository). Rules:

  * every change is validated BEFORE anything is written;
  * the referenced file must exist (exact, case-sensitive match);
  * the line range must be valid;
  * old_text must match the actual content at that range (exact, or
    whitespace-fuzzy only for trailing/blank-line whitespace — the line
    anchor itself is never fuzzy);
  * path traversal, absolute paths, and escapes from the repository root
    are rejected;
  * v1 scope: only the finding's own file may be modified;
  * overlapping changes in one proposal are rejected;
  * each change is re-verified against disk immediately before writing.

Invalid changes are recorded as RejectedChange entries; valid ones are
applied. If nothing could be applied, the caller maps that to PATCH_REJECTED.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from models.schemas import AppliedChange, FixChange, RejectedChange

logger = logging.getLogger(__name__)

# Bounded excerpts stored in AppliedChange records (never whole files).
_EXCERPT_CHARS = 2000


@dataclass
class PatchOutcome:
    applied: list[AppliedChange] = field(default_factory=list)
    rejected: list[RejectedChange] = field(default_factory=list)


def _is_safe_relative_path(path: str) -> bool:
    """No absolute paths, no traversal segments, no empty paths."""
    if not path or not path.strip():
        return False
    posix = PurePosixPath(path.replace("\\", "/"))
    if posix.is_absolute():
        return False
    if ".." in posix.parts:
        return False
    return True


def _ws_loose(text: str) -> str:
    """Whitespace-loose normalization: strip trailing whitespace per line and
    drop leading/trailing blank lines. Used only as a fallback when the
    exact old_text does not match — the line anchor stays exact."""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def _range_text(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1 : end])


def validate_change(
    change: FixChange, contents: dict[str, str], finding_file: str
) -> str | None:
    """Return None when the change is safe to apply, else a rejection reason."""
    if not _is_safe_relative_path(change.file):
        return "invalid_path"
    if change.file != finding_file:
        # v1 scope: a fix may only touch the finding's own file.
        return "unrelated_file"
    content = contents.get(change.file)
    if content is None:
        return "file_not_found"
    lines = content.replace("\r\n", "\n").split("\n")
    # Tolerate a trailing-newline artifact: a file ending in "\n" splits to
    # a final empty element that is not a real line.
    real_lines = len(lines) - 1 if lines and lines[-1] == "" else len(lines)
    if change.start_line > real_lines or change.end_line > real_lines:
        return "line_out_of_range"
    actual = _range_text(lines, change.start_line, change.end_line)
    wanted = change.old_text.replace("\r\n", "\n")
    if actual == wanted:
        return None
    if _ws_loose(actual) == _ws_loose(wanted):
        return None
    return "old_text_mismatch"


def validate_changes(
    changes: list[FixChange], contents: dict[str, str], finding_file: str
) -> tuple[list[FixChange], list[RejectedChange]]:
    """Validate a proposal's changes in order. Overlapping ranges are
    rejected (fail-closed): the later change loses."""
    valid: list[FixChange] = []
    rejected: list[RejectedChange] = []
    claimed: list[tuple[int, int]] = []

    def _rejected(change: FixChange, reason: str) -> None:
        rejected.append(
            RejectedChange(
                file=change.file,
                start_line=change.start_line,
                end_line=change.end_line,
                reason=reason,
            )
        )

    for change in changes:
        reason = validate_change(change, contents, finding_file)
        if reason is not None:
            _rejected(change, reason)
            continue
        if any(
            not (change.end_line < s or change.start_line > e) for s, e in claimed
        ):
            _rejected(change, "overlapping_change")
            continue
        claimed.append((change.start_line, change.end_line))
        valid.append(change)
    return valid, rejected


def _write_change(repo_root: Path, change: FixChange) -> AppliedChange:
    """Apply one pre-validated change. Re-verifies old_text against disk."""
    raw = repo_root / change.file
    # Check the link itself, before resolve() dissolves it into its target.
    if raw.is_symlink():
        raise ValueError(f"refusing to write through symlink: {change.file}")
    target = raw.resolve()
    root = repo_root.resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"refusing to write outside repository root: {change.file}")
    original = target.read_text(encoding="utf-8")
    lines = original.replace("\r\n", "\n").split("\n")
    actual = _range_text(lines, change.start_line, change.end_line)
    wanted = change.old_text.replace("\r\n", "\n")
    if actual != wanted and _ws_loose(actual) != _ws_loose(wanted):
        raise ValueError(
            f"old_text no longer matches disk at {change.file}:"
            f"{change.start_line}-{change.end_line}"
        )
    new_text = change.new_text.replace("\r\n", "\n")
    new_lines = lines[: change.start_line - 1] + new_text.split("\n") + lines[change.end_line :]
    new_content = "\n".join(new_lines)
    if original.endswith("\n") and not new_content.endswith("\n"):
        new_content += "\n"
    target.write_text(new_content, encoding="utf-8")
    before_excerpt = actual[:_EXCERPT_CHARS]
    after_excerpt = new_text[:_EXCERPT_CHARS]
    return AppliedChange(
        file=change.file,
        start_line=change.start_line,
        end_line=change.end_line,
        lines_changed=change.end_line - change.start_line + 1,
        before=before_excerpt,
        after=after_excerpt,
    )


def apply_validated_changes(
    changes: list[FixChange], repo_root: Path
) -> PatchOutcome:
    """Apply pre-validated changes inside repo_root. Never touches anything
    outside repo_root. A disk-level mismatch aborts that change loudly.

    Changes are applied bottom-up (highest line number first): ranges are
    non-overlapping (validate_changes rejects overlaps), so rewriting a later
    range never disturbs the line anchors of an earlier one.
    """
    outcome = PatchOutcome()
    ordered = sorted(changes, key=lambda c: (c.start_line, c.end_line), reverse=True)
    for change in ordered:
        try:
            outcome.applied.append(_write_change(repo_root, change))
        except (OSError, ValueError) as exc:
            logger.warning("Patch application failed for %s: %s", change.file, exc)
            outcome.rejected.append(
                RejectedChange(
                    file=change.file,
                    start_line=change.start_line,
                    end_line=change.end_line,
                    reason="apply_failed",
                )
            )
    return outcome
