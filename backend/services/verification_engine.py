"""Verification engine: deterministic BEFORE/AFTER comparison.

This module never asks the model whether a fix worked. It reruns the
existing deterministic analyzers (via the caller) on the patched workspace
and compares the results:

  * the original finding is identified across runs by (detector, file,
    category, nearby line) — never by exact line alone, since a fix may
    legitimately shift line numbers;
  * the original evidence snippet is checked against the AFTER content;
  * findings present AFTER but not BEFORE, in files the patch touched, are
    reported as newly introduced.

Statuses:
  VERIFIED             original gone, evidence gone, nothing new introduced
  PARTIALLY_VERIFIED   same detector still fires on the file nearby — the
                       issue changed/moved but may persist
  NOT_VERIFIED         the original finding (by identity) is still present
  NEW_ISSUE_INTRODUCED original gone but the patch introduced a verified
                       finding in the affected scope
  CANNOT_VERIFY        the AFTER state cannot establish resolution (e.g. the
                       patched file is no longer analyzable)
PATCH_REJECTED is assigned by the remediation engine when no change could
be applied — verification never runs in that case.
"""

from __future__ import annotations

import logging

from models.schemas import (
    Finding,
    VerificationResult,
    VerificationStatus,
)

logger = logging.getLogger(__name__)

# Line tolerance for matching a finding across BEFORE/AFTER runs.
_MATCH_TOLERANCE = 2
# Wider window: the same detector firing on the same file further away
# means "changed, not conclusively solved".
_WIDE_TOLERANCE = 10


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _same_issue(a: Finding, b: Finding, tolerance: int) -> bool:
    return (
        a.detector == b.detector
        and a.file == b.file
        and a.category == b.category
        and abs(a.line - b.line) <= tolerance
    )


def _evidence_present(
    contents: dict[str, str], path: str, line: int, evidence: str, tolerance: int
) -> bool:
    """Is the (whitespace-normalized) evidence still a substring of a nearby
    line in the given file contents? Mirrors the hard gate's containment
    rule, without trusting any model output."""
    content = contents.get(path)
    if content is None:
        return False
    claimed = _normalize(evidence or "")
    if not claimed:
        return False
    lines = content.splitlines()
    lo = max(1, line - tolerance)
    hi = min(len(lines), line + tolerance)
    for lineno in range(lo, hi + 1):
        if claimed in _normalize(lines[lineno - 1]):
            return True
    return False


def verify_fix(
    *,
    finding: Finding,
    before_findings: list[Finding],
    before_contents: dict[str, str],
    after_findings: list[Finding],
    after_contents: dict[str, str],
    changed_files: list[str],
) -> VerificationResult:
    """Deterministically verify one patched finding. Pure function."""
    finding_present_before = any(f.id == finding.id for f in before_findings)
    evidence_present_before = _evidence_present(
        before_contents, finding.file, finding.line, finding.evidence, _MATCH_TOLERANCE
    )

    if finding.file not in after_contents:
        return VerificationResult(
            status=VerificationStatus.CANNOT_VERIFY,
            original_finding_id=finding.id,
            finding_present_before=finding_present_before,
            finding_present_after=False,
            original_evidence_present_before=evidence_present_before,
            original_evidence_present_after=False,
            verified=False,
            reason=(
                f"Patched file {finding.file} is not present in the AFTER "
                "scan; resolution cannot be established."
            ),
        )

    exact_match = next(
        (
            f
            for f in after_findings
            if _same_issue(f, finding, _MATCH_TOLERANCE)
        ),
        None,
    )
    finding_present_after = exact_match is not None
    evidence_present_after = _evidence_present(
        after_contents, finding.file, finding.line, finding.evidence, _MATCH_TOLERANCE
    )

    # Newly introduced: AFTER findings in the patch's affected scope with no
    # BEFORE counterpart under the same identity rule.
    new_findings: list[Finding] = []
    for after in after_findings:
        if after.file not in changed_files:
            continue
        if any(_same_issue(after, b, _MATCH_TOLERANCE) for b in before_findings):
            continue
        new_findings.append(after)
    new_ids = [f.id for f in new_findings]

    if (
        not finding_present_after
        and not evidence_present_after
        and new_findings
    ):
        status = VerificationStatus.NEW_ISSUE_INTRODUCED
        reason = (
            "The original finding no longer appears, but the patch introduced "
            f"{len(new_findings)} new verified finding(s) in the changed files: "
            + ", ".join(new_ids)
        )
    elif finding_present_after:
        status = VerificationStatus.NOT_VERIFIED
        reason = (
            f"The original finding is still reported after the patch "
            f"({exact_match.id if exact_match else finding.id})."
        )
        if new_findings:
            reason += f" Additionally, {len(new_findings)} new finding(s) appeared: " + ", ".join(new_ids)
    elif any(
        _same_issue(f, finding, _WIDE_TOLERANCE) for f in after_findings
    ):
        status = VerificationStatus.PARTIALLY_VERIFIED
        reason = (
            "The same detector still reports the issue on the same file outside "
            "the expected location; the issue changed but cannot be conclusively "
            "considered solved."
        )
    elif evidence_present_after:
        status = VerificationStatus.CANNOT_VERIFY
        reason = (
            "The original evidence text is still present but the detector no "
            "longer reports the finding; the available analyzers cannot "
            "establish whether the issue was resolved."
        )
    else:
        status = VerificationStatus.VERIFIED
        reason = (
            "The original finding and its evidence no longer appear in the "
            "AFTER analysis, and no new verified findings were introduced in "
            "the changed files."
        )

    logger.info(
        "Verification for %s: %s (before=%s, after=%s, new=%d)",
        finding.id,
        status.value,
        finding_present_before,
        finding_present_after,
        len(new_findings),
    )
    return VerificationResult(
        status=status,
        original_finding_id=finding.id,
        finding_present_before=finding_present_before,
        finding_present_after=finding_present_after,
        original_evidence_present_before=evidence_present_before,
        original_evidence_present_after=evidence_present_after,
        new_findings_introduced=new_ids,
        verified=status == VerificationStatus.VERIFIED,
        reason=reason,
    )
