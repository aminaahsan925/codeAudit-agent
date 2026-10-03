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
from services.languages.base import ParsedSource
from services.languages.registry import get_analyzer
from services.provider_factory import build_ai_provider
from services.repository_scanner import ScanResult, supports_deep_analysis

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
        # None means "auto": use the configured AI provider (Nebius
        # default, Groq opt-in) when it is configured, otherwise run
        # deterministic-only (AI disabled).
        # Tests inject a fake provider; production never sees the stub.
        if ai_provider is None:
            ai_provider = self._default_ai_provider()
        self._ai_provider = ai_provider

    @staticmethod
    def _default_ai_provider() -> AIProvider | None:
        # Auto: configured provider (Nebius default, Groq opt-in). None
        # means deterministic-only, exactly as before.
        return build_ai_provider()

    # -- Tools -----------------------------------------------------------
    # Each tool does one thing and is independently testable. Phase 3's
    # reasoning layer will call these directly.

    def fetch_repo(self, repository_url: str, dest: Path) -> github_service.RepoReference:
        ref = github_service.validate_github_url(repository_url)
        github_service.clone_repository(ref, dest)
        return ref

    def scan_files(
        self, repo_dir: Path, deadline: float | None = None
    ) -> ScanResult:
        return repository_scanner.scan_repository(repo_dir, deadline=deadline)

    def parse(
        self, scan: ScanResult, deadline: float | None = None
    ) -> tuple[list[ParsedFile], dict[str, ParsedSource], int]:
        """Parse every deep-analysis file.

        Returns (parsed_files, parsed_sources, failed_count). The
        ``parsed_sources`` map (relative_path -> ParsedSource, carrying the
        native parse tree) is passed to :meth:`analyze_static` so analysis
        reuses the already-parsed trees instead of parsing every file a
        second time.
        """
        parsed: list[ParsedFile] = []
        sources: dict[str, ParsedSource] = {}
        failed = 0
        for analyzed in scan.files:
            repository_scanner.check_deadline(deadline)
            # Per-language routing through the analyzer registry. Python
            # behavior is unchanged: the Python analyzer delegates to the
            # same code_parser / static_analyzer modules as before.
            analyzer = get_analyzer(analyzed.language)
            if analyzer is None:
                continue
            content = scan.contents.get(analyzed.relative_path, "")
            source: ParsedSource = analyzer.parse_source(content, analyzed.relative_path)
            sources[source.relative_path] = source
            result = ParsedFile(
                relative_path=source.relative_path,
                language=source.language,
                symbols=source.symbols,
                parse_error=source.parse_error,
            )
            if result.parse_error:
                failed += 1
            parsed.append(result)
        return parsed, sources, failed

    def analyze_static(
        self,
        scan: ScanResult,
        sources: dict[str, ParsedSource] | None = None,
        deadline: float | None = None,
    ) -> list[Finding]:
        """Run deterministic detectors over every deep-analysis file.

        When ``sources`` (from :meth:`parse`) is given, each analyzer
        consumes the already-parsed tree instead of re-parsing the file.
        Without it, each file is parsed once inside ``analyze_file`` —
        the legacy behavior, kept for standalone/test use.

        Phase 4: after the language analyzers, the supply-chain stage runs
        on every scanned file (secret detection is cross-cutting; manifest /
        Dockerfile / workflow / compose analyzers run by file kind). The
        advisory source is built once per call, not per file.
        """
        from services.supplychain.dispatch import (
            analyze_supplychain_file,
            get_advisory_source,
        )

        findings: list[Finding] = []
        for analyzed in scan.files:
            repository_scanner.check_deadline(deadline)
            analyzer = get_analyzer(analyzed.language)
            if analyzer is None:
                continue
            content = scan.contents.get(analyzed.relative_path, "")
            source = sources.get(analyzed.relative_path) if sources else None
            if source is not None:
                findings.extend(
                    analyzer.analyze_parsed(analyzed.relative_path, content, source)
                )
            else:
                findings.extend(analyzer.analyze_file(analyzed.relative_path, content))
        # Phase 4: supply-chain stage (never breaks the language results).
        advisory_source = get_advisory_source()
        for analyzed in scan.files:
            repository_scanner.check_deadline(deadline)
            content = scan.contents.get(analyzed.relative_path, "")
            if not content:
                continue
            findings.extend(
                analyze_supplychain_file(
                    analyzed.relative_path, content, advisory_source
                )
            )
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
        deadline = repository_scanner.analysis_deadline()
        scan = self.scan_files(repo_dir, deadline=deadline)
        parsed, sources, failed_parse = self.parse(scan, deadline=deadline)
        # Phase 4: files covered by a structural supply-chain analyzer
        # (manifests, Dockerfiles, workflows, compose files) count as
        # deep-analyzed rather than unsupported. Secret scanning is a
        # cross-cutting pass over every file and does not change buckets.
        from services.supplychain.dispatch import (
            get_advisory_source,
            supplychain_covered_files,
        )
        from services.supplychain.sbom import build_sbom_for_scan

        sc_covered = supplychain_covered_files(
            [a.relative_path for a in scan.files]
        )
        parsed_paths = {p.relative_path for p in parsed}
        deep_analyzed = sum(1 for p in parsed if p.parse_error is None) + len(
            sc_covered - parsed_paths
        )
        unsupported = sum(
            1
            for a in scan.files
            if not supports_deep_analysis(a.language)
            and a.relative_path not in sc_covered
        )
        raw_findings = self.analyze_static(scan, sources, deadline=deadline)
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
        # Phase 4: SBOM attached to the result metadata. Built from the same
        # manifest parsers as dependency analysis; advisory status recorded
        # inside the SBOM so consumers see data freshness.
        try:
            advisory_source = get_advisory_source()
            result.sbom = build_sbom_for_scan(
                scan.contents,
                repository,
                advisory_status=advisory_source.status,
                advisory_generated_at=advisory_source.generated_at,
            )
        except Exception:  # noqa: BLE001 — SBOM must never break analysis
            logger.exception("SBOM generation failed; continuing without it")
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
