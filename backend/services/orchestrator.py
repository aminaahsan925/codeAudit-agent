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
from pathlib import Path

from models.schemas import (
    AnalysisResult,
    AnalysisSummary,
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
from services.code_parser import parse_file
from services.repository_scanner import ScanResult, supports_deep_analysis

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Coordinates the Phase 1 analysis pipeline over tool-style stages."""

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
        risk = self.score_risk(validated)

        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for finding in validated:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
            by_category[finding.category.value] = by_category.get(finding.category.value, 0) + 1

        summary = AnalysisSummary(
            files_discovered=len(scan.files) + scan.skipped,
            files_scanned=len(scan.files),
            files_deep_analyzed=deep_analyzed,
            files_unsupported=unsupported,
            files_skipped=scan.skipped,
            files_failed_parse=failed_parse,
            findings_total=len(validated),
            findings_dropped=dropped,
            findings_by_severity=by_severity,
            findings_by_category=by_category,
            skip_reasons=dict(scan.skipped_reasons),
        )
        result = AnalysisResult(
            repository=repository,
            summary=summary,
            findings=validated,
            risk=risk,
        )
        logger.info(
            "Analysis completed: %d scanned (%d deep-analyzed, %d unsupported, "
            "%d skipped, %d failed parse), %d findings, risk %d/10 (%s)",
            summary.files_scanned,
            summary.files_deep_analyzed,
            summary.files_unsupported,
            summary.files_skipped,
            summary.files_failed_parse,
            summary.findings_total,
            risk.score,
            risk.level,
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
