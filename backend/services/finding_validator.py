"""Finding validator: the evidence hard gate.

Every finding — deterministic today, AI-produced in later phases — must
prove itself against the actual repository content:
  1. the referenced file exists in the scanned set,
  2. the referenced line exists in that file,
  3. the cited evidence matches the actual line content.

A finding that fails any check is dropped from the validated set (reported
separately as unverified) rather than silently passed through.

Phase 4: findings marked ``sensitive`` (secret material) carry redacted
evidence by design, so the verbatim substring check cannot apply. For
those, every literal fragment of the redacted evidence must appear in
order in the cited line — anchoring the finding without ever requiring
the raw secret value.
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


def _redacted_contains(actual: str, claimed: str) -> bool:
    """Redaction-aware evidence check for sensitive findings.

    The claimed evidence contains ``****`` redactions, so it can never be
    a verbatim substring of the real line. Instead, split the claim on the
    redaction marker and require every literal fragment to appear in the
    actual line, in order, with at least one non-empty fragment. This
    proves the finding is anchored to the cited line without ever
    requiring the raw secret value.
    """
    from services.supplychain.redaction import REDACTION_MARKER

    fragments = [frag for frag in claimed.split(REDACTION_MARKER) if frag.strip()]
    if not fragments:
        return False
    pos = 0
    for frag in fragments:
        idx = actual.find(frag, pos)
        if idx == -1:
            return False
        pos = idx + len(frag)
    return True


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
        # Evidence must be (a substring of) the actual cited line, compared
        # whitespace-insensitively. The reverse containment (the real line
        # being a substring of the claimed evidence) is NOT accepted: it would
        # let hallucinated extra text ride along with a genuine line.
        #
        # Phase 4: sensitive findings carry REDACTED evidence (the raw secret
        # never appears in a finding). For those, a verbatim substring check
        # is impossible by design; instead every literal fragment of the
        # redacted evidence must appear in order in the real line.
        if not claimed:
            result.dropped.append(finding)
            result.drop_reasons["evidence_mismatch"] = result.drop_reasons.get("evidence_mismatch", 0) + 1
            continue
        if finding.sensitive:
            ok = _redacted_contains(actual, claimed)
        else:
            ok = claimed in actual
        if not ok:
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
