"""Analysis orchestrator: one honest agent-with-tools boundary.

The orchestrator owns the analysis flow and exposes each stage as a
tool-style method (fetch_repo, scan_files, parse, analyze_static,
validate_findings, score_risk). In Phase 3, Nemotron reasoning will drive
these same tools instead of the fixed pipeline below — no architectural
surgery required.

The fixed Phase 1 pipeline:
    validate request -> fetch_repo -> scan_files -> parse
        -> analyze_static -> validate_findings -> score_risk -> result
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from models.schemas import (
    AnalysisResult,
    AnalysisSummary,
    AIStatus,
    AIStatusValue,
    Finding,
    ParsedFile,
    RepositoryMetadata,
    RiskResult,
    ValidatedFinding,
)
from services import (
    finding_validator,
    github_service,
    repository_scanner,
    risk_engine,
    static_analyzer,
)
from services.ai_context_builder import build_ai_context
from services.ai_errors import (
    AIError,
    AIProviderNotConfigured,
    AIUpstreamError,
    SAFE_MESSAGES,
)
from services.ai_provider import AIProvider
from services.ai_result_processor import merge_ai_results
from services.code_parser import parse_file
from services.nemotron_service import NemotronService
from services.repository_scanner import ScanResult, supports_deep_analysis
from app.config import settings

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Coordinates the Phase 2 analysis pipeline over tool-style stages.

    The fixed pipeline:
        validate request -> fetch_repo -> scan_files -> parse
            -> analyze_static -> ai_investigation (optional, graceful)
            -> validate_findings (evidence hard gate over everything)
            -> deduplicate -> score_risk -> result
    """

    def __init__(self, ai_provider: AIProvider | None = None) -> None:
        # None means "auto": use the real NemotronService when it is
        # configured, otherwise run deterministic-only (AI disabled).
        # Tests inject a fake provider; production never sees the stub.
        if ai_provider is None:
            ai_provider = self._default_ai_provider()
        self._ai_provider = ai_provider

    @staticmethod
    def _default_ai_provider() -> AIProvider | None:
        if not settings.ai_enabled:
            logger.info("AI investigation disabled by CODEAUDIT_AI_ENABLED=false")
            return None
        service = NemotronService()
        if not service.is_configured:
            logger.info(
                "AI investigation disabled: NEBIUS_API_KEY/NEMOTRON_MODEL not set"
            )
            return None
        return service

    # -- Tools -----------------------------------------------------------
    # Each tool does one thing and is independently testable. Phase 3's
    # reasoning layer will call these directly.

    def fetch_repo(self, repository_url: str, dest: Path) -> github_service.RepoReference:
        ref = github_service.validate_github_url(repository_url)
        github_service.clone_repository(ref, dest)
        return ref

    def scan_files(self, repo_dir: Path) -> ScanResult:
        return repository_scanner.scan_repository(repo_dir)

    def parse(self, scan: ScanResult) -> tuple[list[ParsedFile], int]:
        parsed: list[ParsedFile] = []
        failed = 0
        for analyzed in scan.files:
            if not supports_deep_analysis(analyzed.language):
                continue
            content = scan.contents.get(analyzed.relative_path, "")
            result = parse_file(analyzed.relative_path, analyzed.language, content)
            if result is None:
                continue
            if result.parse_error:
                failed += 1
            parsed.append(result)
        return parsed, failed

    def analyze_static(self, scan: ScanResult) -> list[Finding]:
        findings: list[Finding] = []
        for analyzed in scan.files:
            if not supports_deep_analysis(analyzed.language):
                continue
            content = scan.contents.get(analyzed.relative_path, "")
            findings.extend(static_analyzer.analyze_content(analyzed.relative_path, content))
        findings.sort(key=lambda f: (f.file, f.line, f.detector))
        return findings

    def validate_findings(
        self, findings: list[Finding], scan: ScanResult
    ) -> tuple[list[ValidatedFinding], int]:
        result = finding_validator.validate_findings(findings, scan.contents)
        return result.validated, len(result.dropped)

    def investigate_with_ai(
        self,
        validated: list[ValidatedFinding],
        scan: ScanResult,
        parsed: list[ParsedFile],
        repository: RepositoryMetadata,
    ) -> tuple[list[ValidatedFinding], AIStatus]:
        """Optional AI stage: enrich deterministic findings, add AI-discovered
        ones. Never raises: any AI failure degrades to deterministic-only with
        the failure recorded in the returned AIStatus (never a 500)."""
        provider = self._ai_provider
        if provider is None:
            return validated, AIStatus(status=AIStatusValue.DISABLED)

        started = time.monotonic()
        deterministic_count = len(validated)

        def _degraded(status: AIStatusValue, code: str) -> tuple[list[ValidatedFinding], AIStatus]:
            logger.warning("AI investigation degraded (%s); deterministic results kept", code)
            return validated, AIStatus(
                status=status,
                provider=getattr(provider, "name", ""),
                deterministic_findings=deterministic_count,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code=code,
                error_message=SAFE_MESSAGES.get(code, code),
            )

        try:
            context = build_ai_context(scan, parsed, validated, repository)
            result = provider.investigate(validated, context)
        except AIProviderNotConfigured as exc:
            return _degraded(AIStatusValue.UNAVAILABLE, exc.code)
        except AIError as exc:
            return _degraded(AIStatusValue.FAILED, exc.code)
        except Exception:  # noqa: BLE001 - AI bugs must not kill deterministic analysis
            logger.exception("Unexpected AI provider failure; degrading gracefully")
            return _degraded(AIStatusValue.FAILED, AIUpstreamError.code)

        if result.status == "disabled":
            return validated, AIStatus(
                status=AIStatusValue.DISABLED,
                provider=result.provider_name or getattr(provider, "name", ""),
                deterministic_findings=deterministic_count,
            )
        if result.status in ("failed", "unavailable"):
            code = result.error_code or AIUpstreamError.code
            return _degraded(
                AIStatusValue.FAILED if result.status == "failed" else AIStatusValue.UNAVAILABLE,
                code,
            )

        # Deterministic handling of model output: apply assessments,
        # deduplicate candidates against deterministic anchors.
        merged = merge_ai_results(validated, result)

        # Every AI-discovered candidate faces the same evidence hard gate.
        gate = finding_validator.validate_findings(merged.new_candidates, scan.contents)
        ai_validated = gate.validated
        ai_dropped = len(gate.dropped)

        final = list(merged.enriched) + ai_validated
        final.sort(key=lambda f: (f.file, f.line, f.source.value, f.detector))

        ai_status = AIStatus(
            status=AIStatusValue.ENABLED,
            provider=result.provider_name or getattr(provider, "name", ""),
            model=result.model or None,
            prompt_version=result.prompt_version or None,
            model_calls=result.model_calls,
            context_chars=result.context_chars,
            deterministic_findings=deterministic_count,
            findings_enriched=merged.enriched_count,
            ai_findings_accepted=len(ai_validated),
            ai_findings_dropped=ai_dropped,
            duplicates_merged=merged.duplicates_merged,
            duration_ms=result.duration_ms or int((time.monotonic() - started) * 1000),
        )
        if merged.ignored_assessments or gate.dropped:
            logger.info(
                "AI stage: %d enriched, %d accepted, %d gate-dropped, %d duplicates merged, "
                "%d assessments ignored",
                merged.enriched_count,
                len(ai_validated),
                ai_dropped,
                merged.duplicates_merged,
                merged.ignored_assessments,
            )
        return final, ai_status

    def score_risk(self, findings: list[Finding]) -> RiskResult:
        return risk_engine.calculate_risk(findings)

    # -- Fixed Phase 1 pipeline ------------------------------------------

    def _analyze(self, repo_dir: Path, repository: RepositoryMetadata) -> AnalysisResult:
        """Shared pipeline core: scan -> parse -> analyze -> validate -> score."""
        scan = self.scan_files(repo_dir)
        parsed, failed_parse = self.parse(scan)
        deep_analyzed = sum(1 for p in parsed if p.parse_error is None)
        unsupported = sum(
            1 for a in scan.files if not supports_deep_analysis(a.language)
        )
        raw_findings = self.analyze_static(scan)
        validated, dropped = self.validate_findings(raw_findings, scan)
        # Phase 2: optional Nemotron reasoning over the deterministic evidence.
        # Degrades gracefully — deterministic findings always survive.
        final_findings, ai_status = self.investigate_with_ai(
            validated, scan, parsed, repository
        )
        ai_dropped = ai_status.ai_findings_dropped
        risk = self.score_risk(final_findings)

        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for finding in final_findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
            by_category[finding.category.value] = by_category.get(finding.category.value, 0) + 1

        summary = AnalysisSummary(
            files_discovered=len(scan.files) + scan.skipped,
            files_scanned=len(scan.files),
            files_deep_analyzed=deep_analyzed,
            files_unsupported=unsupported,
            files_skipped=scan.skipped,
            files_failed_parse=failed_parse,
            findings_total=len(final_findings),
            findings_dropped=dropped + ai_dropped,
            findings_by_severity=by_severity,
            findings_by_category=by_category,
            skip_reasons=dict(scan.skipped_reasons),
        )
        result = AnalysisResult(
            repository=repository,
            summary=summary,
            findings=final_findings,
            risk=risk,
            ai=ai_status,
        )
        logger.info(
            "Analysis completed: %d scanned (%d deep-analyzed, %d unsupported, "
            "%d skipped, %d failed parse), %d findings, risk %d/10 (%s), "
            "ai=%s",
            summary.files_scanned,
            summary.files_deep_analyzed,
            summary.files_unsupported,
            summary.files_skipped,
            summary.files_failed_parse,
            summary.findings_total,
            risk.score,
            risk.level,
            ai_status.status.value,
        )
        return result

    def run(self, repository_url: str, repo_dir: Path) -> AnalysisResult:
        """Run the full pipeline against an already-cloned repo directory."""
        logger.info("Analysis started for %s", repository_url)
        ref = github_service.validate_github_url(repository_url)
        metadata = github_service.fetch_metadata(ref)
        return self._analyze(
            repo_dir,
            RepositoryMetadata(
                owner=ref.owner,
                name=ref.name,
                url=ref.url,
                default_branch=metadata.get("default_branch"),
                description=metadata.get("description"),
            ),
        )

    # -- Local analysis (tests / controlled fixtures) ---------------------

    def run_on_local_path(self, repo_dir: Path, owner: str = "local", name: str = "fixture") -> AnalysisResult:
        """Same pipeline, but against a local directory (no network)."""
        return self._analyze(
            repo_dir,
            RepositoryMetadata(owner=owner, name=name, url=f"file://{repo_dir}"),
        )
