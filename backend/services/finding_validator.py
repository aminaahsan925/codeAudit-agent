"""Finding validator: the evidence hard gate.

Every finding — deterministic today, AI-produced in later phases — must
prove itself against the actual repository content:
  1. the referenced file exists in the scanned set,
  2. the referenced line exists in that file,
  3. the cited evidence matches the actual line content.

A finding that fails any check is dropped from the validated set (reported
separately as unverified) rather than silently passed through.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from models.schemas import Finding, ValidatedFinding

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    validated: list[ValidatedFinding] = field(default_factory=list)
    dropped: list[Finding] = field(default_factory=list)
    drop_reasons: dict[str, int] = field(default_factory=dict)


def _normalize(text: str) -> str:
    return " ".join(text.split())


def validate_findings(
    findings: list[Finding], contents: dict[str, str]
) -> ValidationResult:
    """Validate findings against scanned file contents (the hard gate)."""
    result = ValidationResult()

    for finding in findings:
        content = contents.get(finding.file)
        if content is None:
            result.dropped.append(finding)
            result.drop_reasons["file_not_found"] = result.drop_reasons.get("file_not_found", 0) + 1
            continue

        lines = content.splitlines()
        if not 1 <= finding.line <= len(lines):
            result.dropped.append(finding)
            result.drop_reasons["line_out_of_range"] = result.drop_reasons.get("line_out_of_range", 0) + 1
            continue

        actual = _normalize(lines[finding.line - 1])
        claimed = _normalize(finding.evidence or "")
        if not claimed or claimed not in actual and actual not in claimed:
            # Evidence must correspond to the cited line (whitespace-insensitive,
            # allowing the evidence to be a substring of a long line).
            result.dropped.append(finding)
            result.drop_reasons["evidence_mismatch"] = result.drop_reasons.get("evidence_mismatch", 0) + 1
            continue

        result.validated.append(
            ValidatedFinding(**finding.model_dump(), validation="passed")
        )

    if result.dropped:
        logger.warning(
            "Validator dropped %d finding(s): %s",
            len(result.dropped),
            result.drop_reasons,
        )
    return result
