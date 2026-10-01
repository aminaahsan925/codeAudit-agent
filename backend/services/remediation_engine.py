"""Remediation engine: the FIND -> FIX -> VERIFY loop.

Nemotron proposes. CodeAudit validates. The patch engine applies only
validated changes inside an isolated temporary workspace. The deterministic
analyzer verifies. The original repository is never modified.

Flow per finding (remediate_finding):
    1. locate the finding in the BEFORE analysis result (else 404)
    2. build a bounded fix context from real repository evidence
    3. ask the AI provider for a structured fix proposal (graceful on failure)
    4. stamp traceability deterministically (finding_id/provider/model/prompt)
    5. validate every proposed change with the deterministic patch engine
    6. copy the repository into an isolated temporary workspace
    7. apply only validated changes inside the workspace
    8. rerun the deterministic pipeline (AI disabled) on the workspace
    9. verify BEFORE vs AFTER with the verification engine
    10. return the remediation result; the workspace is always cleaned up

Batch remediation (remediate_findings) processes each finding independently
against the original repository — fixes are never chained in v1 — and is
hard-capped by CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.config import settings
from models.schemas import (
    AnalysisResult,
    FindingSource,
    FixDecision,
    RemediationResult,
    RemediationStatus,
    VerificationResult,
    VerificationStatus,
)
from services import patch_engine, repository_scanner, risk_engine, verification_engine
from services.ai_errors import (
    AIError,
    AIOutputInvalid,
    AIProviderNotConfigured,
    AIUpstreamError,
    SAFE_MESSAGES as AI_SAFE_MESSAGES,
)
from services.ai_provider import AIProvider, StubAIProvider
from services.fix_context_builder import build_fix_context
from services.nemotron_service import NemotronService
from services.orchestrator import AnalysisOrchestrator
from services.remediation_errors import (
    RemediationFindingNotFound,
    RemediationWorkspaceError,
)

logger = logging.getLogger(__name__)


@contextmanager
def temporary_workspace(repo_dir: Path) -> Iterator[Path]:
    """Yield an isolated copy of repo_dir for patch application.

    The original directory is never modified; the copy is removed
    afterwards, even on failure. Version-control metadata (.git) is not
    copied — verification needs source content, not history. Symlinks are
    preserved as links (the scanner never follows them).
    """
    tmp = Path(tempfile.mkdtemp(prefix="codeaudit-remediation-"))
    dest = tmp / "workspace"
    try:
        shutil.copytree(
            repo_dir,
            dest,
            ignore=shutil.ignore_patterns(".git"),
            symlinks=True,
        )
    except Exception as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RemediationWorkspaceError(
            f"could not prepare isolated workspace: {exc}"
        ) from exc
    try:
        yield dest
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class RemediationEngine:
    """Orchestrates safe, verified remediation of validated findings."""

    def __init__(self, ai_provider: AIProvider | None = None) -> None:
        # None means "auto": real NemotronService when configured, else None
        # (every AI call then degrades to "unavailable" gracefully).
        if ai_provider is None:
            ai_provider = self._default_ai_provider()
        self._ai_provider = ai_provider
        # Deterministic-only pipeline for AFTER analysis: verification must
        # never depend on model output.
        self._verify_orchestrator = AnalysisOrchestrator(
            ai_provider=StubAIProvider()
        )

    @staticmethod
    def _default_ai_provider() -> AIProvider | None:
        if not settings.ai_enabled:
            logger.info("AI remediation disabled by CODEAUDIT_AI_ENABLED=false")
            return None
        service = NemotronService()
        if not service.is_configured:
            logger.info(
                "AI remediation disabled: NEBIUS_API_KEY/NEMOTRON_MODEL not set"
            )
            return None
        return service

    def _ai_outcome(
        self, status: RemediationStatus, code: str, finding_id: str, risk_before
    ) -> RemediationResult:
        return RemediationResult(
            status=status,
            finding_id=finding_id,
            error_code=code,
            error_message=AI_SAFE_MESSAGES.get(code, code),
            risk_before=risk_before,
        )

    def _patch_rejected(
        self,
        finding_id: str,
        proposal,
        rejected,
        reason: str,
        risk_before,
    ) -> RemediationResult:
        verification = VerificationResult(
            status=VerificationStatus.PATCH_REJECTED,
            original_finding_id=finding_id,
            finding_present_before=True,
            finding_present_after=False,
            original_evidence_present_before=True,
            original_evidence_present_after=False,
            verified=False,
            reason=reason,
        )
        return RemediationResult(
            status=RemediationStatus.PATCH_REJECTED,
            finding_id=finding_id,
            proposal=proposal,
            verification=verification,
            changes_rejected=list(rejected),
            risk_before=risk_before,
        )

    def remediate_finding(
        self, finding_id: str, repo_dir: Path, before: AnalysisResult
    ) -> RemediationResult:
        """Run one FIND -> FIX -> VERIFY cycle. Never modifies repo_dir."""
        target = next((f for f in before.findings if f.id == finding_id), None)
        if target is None:
            raise RemediationFindingNotFound(
                f"finding {finding_id!r} is not in the analysis result"
            )

        deterministic_before = [
            f for f in before.findings if f.source == FindingSource.DETERMINISTIC
        ]
        risk_before = risk_engine.calculate_risk(deterministic_before)

        scan = repository_scanner.scan_repository(repo_dir)
        contents = scan.contents
        if target.file not in contents:
            logger.warning(
                "Remediation cannot verify: finding file %s not in scanned contents",
                target.file,
            )
            return RemediationResult(
                status=RemediationStatus.CANNOT_VERIFY,
                finding_id=target.id,
                risk_before=risk_before,
            )

        provider = self._ai_provider
        if provider is None:
            return self._ai_outcome(
                RemediationStatus.UNAVAILABLE,
                AIProviderNotConfigured.code,
                target.id,
                risk_before,
            )

        parsed, _ = self._verify_orchestrator.parse(scan)
        fix_context = build_fix_context(target, contents, parsed)

        try:
            fix_result = provider.propose_fix(target, fix_context)
        except AIProviderNotConfigured as exc:
            return self._ai_outcome(
                RemediationStatus.UNAVAILABLE, exc.code, target.id, risk_before
            )
        except AIError as exc:
            return self._ai_outcome(
                RemediationStatus.FAILED, exc.code, target.id, risk_before
            )
        except Exception:  # noqa: BLE001 - AI bugs must not break remediation
            logger.exception("Unexpected AI provider failure during remediation")
            return self._ai_outcome(
                RemediationStatus.FAILED, AIUpstreamError.code, target.id, risk_before
            )

        if fix_result.status == "disabled":
            return self._ai_outcome(
                RemediationStatus.UNAVAILABLE,
                AIProviderNotConfigured.code,
                target.id,
                risk_before,
            )
        if fix_result.status in ("failed", "unavailable"):
            code = fix_result.error_code or AIUpstreamError.code
            return self._ai_outcome(
                RemediationStatus.FAILED
                if fix_result.status == "failed"
                else RemediationStatus.UNAVAILABLE,
                code,
                target.id,
                risk_before,
            )
        if fix_result.proposal is None:
            return self._ai_outcome(
                RemediationStatus.FAILED, AIOutputInvalid.code, target.id, risk_before
            )

        # Traceability is stamped by the system, never trusted from the model.
        proposal = fix_result.proposal.model_copy(
            update={
                "finding_id": target.id,
                "provider": fix_result.provider_name
                or getattr(provider, "name", ""),
                "model": fix_result.model or "",
                "prompt_version": fix_result.prompt_version or "",
            }
        )

        if proposal.decision == FixDecision.CANNOT_FIX:
            return RemediationResult(
                status=RemediationStatus.NOT_VERIFIED,
                finding_id=target.id,
                proposal=proposal,
                risk_before=risk_before,
            )

        valid, rejected = patch_engine.validate_changes(
            proposal.changes, contents, target.file
        )
        if not valid:
            return self._patch_rejected(
                target.id,
                proposal,
                rejected,
                "Every proposed change failed patch validation; nothing was applied.",
                risk_before,
            )

        with temporary_workspace(repo_dir) as workspace:
            outcome = patch_engine.apply_validated_changes(valid, workspace)
            if not outcome.applied:
                return self._patch_rejected(
                    target.id,
                    proposal,
                    list(rejected) + list(outcome.rejected),
                    "No proposed change could be applied in the isolated "
                    "workspace; the original repository was not modified.",
                    risk_before,
                )

            after = self._verify_orchestrator.run_on_local_path(
                workspace,
                owner=before.repository.owner,
                name=before.repository.name,
            )
            after_contents = repository_scanner.scan_repository(workspace).contents
            deterministic_after = [
                f
                for f in after.findings
                if f.source == FindingSource.DETERMINISTIC
            ]
            verification = verification_engine.verify_fix(
                finding=target,
                before_findings=deterministic_before,
                before_contents=contents,
                after_findings=deterministic_after,
                after_contents=after_contents,
                changed_files=[a.file for a in outcome.applied],
            )
            risk_after = risk_engine.calculate_risk(deterministic_after)

            return RemediationResult(
                status=RemediationStatus(verification.status.value),
                finding_id=target.id,
                proposal=proposal,
                verification=verification,
                changes_applied=list(outcome.applied),
                changes_rejected=list(rejected) + list(outcome.rejected),
                risk_before=risk_before,
                risk_after=risk_after,
            )

    def remediate_findings(
        self,
        finding_ids: list[str],
        repo_dir: Path,
        before: AnalysisResult,
    ) -> list[RemediationResult]:
        """Remediate several findings, each independently against the original
        repository (fixes are never chained in v1). Hard-capped."""
        cap = max(0, settings.max_remediations_per_request)
        return [
            self.remediate_finding(fid, repo_dir, before)
            for fid in finding_ids[:cap]
        ]
