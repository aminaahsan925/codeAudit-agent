"""Verification agent: coordinates deterministic BEFORE/AFTER verification.

The actual verification is ALWAYS deterministic, via
services/verification_engine.py over the rerun analyzer output. This agent:

  * invokes the verification engine with the before/after evidence
  * records the verdict with full traceability metadata
  * writes a deterministic, human-readable explanation of the verdict

Nemotron never overrides the deterministic verifier: there is no model
call on this path at all in the current phase (the "explanation" is
generated from the engine's structured reason, which keeps the
verification stage fully auditable and cost-free).
"""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, Field

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
)
from agents.registry import VERIFICATION_AGENT
from models.schemas import Finding, VerificationResult, VerificationStatus

from services import verification_engine

logger = logging.getLogger(__name__)


class VerificationAgentResult(BaseModel):
    """Deterministic verification verdict plus agent metadata."""

    agent_name: str = VERIFICATION_AGENT
    verification: VerificationResult
    # Deterministic explanation of the verdict (no model involved).
    explanation: str = ""
    execution_metadata: AgentExecutionMetadata


def _explain(verification: VerificationResult) -> str:
    status = verification.status
    if status == VerificationStatus.VERIFIED:
        return (
            "The original finding's evidence no longer appears in the "
            "patched workspace and no new verified issues were introduced "
            "in the changed files. Deterministic BEFORE/AFTER comparison "
            "confirms the fix."
        )
    if status == VerificationStatus.NOT_VERIFIED:
        return (
            "The original finding (or its evidence) is still present after "
            f"patching. {verification.reason}"
        )
    if status == VerificationStatus.PARTIALLY_VERIFIED:
        return (
            "The original issue appears addressed but a related detector "
            f"still fires nearby. {verification.reason}"
        )
    if status == VerificationStatus.NEW_ISSUE_INTRODUCED:
        return (
            "The original issue is gone, but the patch introduced new "
            "verified findings in the changed scope: "
            f"{', '.join(verification.new_findings_introduced)}. "
            "The fix is not safe as proposed."
        )
    if status == VerificationStatus.PATCH_REJECTED:
        return (
            "No patch was applied: the Patch Guard rejected every proposed "
            f"change. {verification.reason}"
        )
    return (
        "Verification could not be established deterministically. "
        f"{verification.reason}"
    )


class VerificationAgent:
    """Coordinates verification; the engine decides, the agent reports."""

    name = VERIFICATION_AGENT

    def verify(
        self,
        *,
        finding: Finding,
        before_findings: list[Finding],
        before_contents: dict[str, str],
        after_findings: list[Finding],
        after_contents: dict[str, str],
        changed_files: list[str],
    ) -> VerificationAgentResult:
        """Run deterministic verification and explain the verdict."""
        started = time.monotonic()
        verification = verification_engine.verify_fix(
            finding=finding,
            before_findings=before_findings,
            before_contents=before_contents,
            after_findings=after_findings,
            after_contents=after_contents,
            changed_files=changed_files,
        )
        logger.info(
            "Verification agent: finding=%s verdict=%s",
            finding.id,
            verification.status.value,
        )
        return VerificationAgentResult(
            verification=verification,
            explanation=_explain(verification),
            execution_metadata=AgentExecutionMetadata(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
        )


__all__ = ["VerificationAgent", "VerificationAgentResult"]
