"""Typed remediation errors: the Phase 3 error contract.

AI-layer failures reuse the Phase 2 typed errors in services.ai_errors
(and their sanitized SAFE_MESSAGES) — they are not duplicated here. These
codes cover failures of the remediation machinery itself: the requested
finding does not exist, or the isolated workspace could not be prepared.

Patch-level problems (invalid file, old_text mismatch, traversal, ...) are
NOT exceptions: they are recorded as RejectedChange entries and surface as
the PATCH_REJECTED verification status, fail-closed.
"""

from __future__ import annotations


class RemediationError(Exception):
    """Base class for remediation-machinery failures."""

    code = "REMEDIATION_ERROR"

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.code)
        self.message = message or self.code


class RemediationFindingNotFound(RemediationError):
    """The requested finding_id is not present in the analysis result."""

    code = "REMEDIATION_FINDING_NOT_FOUND"


class RemediationWorkspaceError(RemediationError):
    """The isolated temporary workspace could not be created or cleaned up."""

    code = "REMEDIATION_WORKSPACE_ERROR"


# Sanitized, user-safe messages. The API exposes only these — never paths,
# stack traces, or internals.
SAFE_MESSAGES = {
    RemediationFindingNotFound.code: "The requested finding was not found in the analysis result.",
    RemediationWorkspaceError.code: "The isolated remediation workspace could not be prepared.",
    RemediationError.code: "Remediation failed.",
}
