"""Finding fusion agent: deterministic merge with provenance.

Combines the specialists' validated outputs and the evidence agent's
reviewed output into the final finding list. Deterministic where possible:

  * starts from the validated deterministic findings (the anchors)
  * applies the evidence agent's enrichments by finding id (AI reasoning
    attached; the anchor's id/file/line/evidence/detector never rewritten)
  * adds AI-discovered findings that passed the evidence hard gate
  * deduplicates on (file, line, detector), keeping the deterministic
    anchor whenever two records collide
  * stamps provenance: detected_by / reviewed_by (never claims
    participation that did not happen)

The fusion agent never calls the model and never invents findings.
"""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, Field

from agents.contracts import (
    AgentContext,
    AgentExecutionMetadata,
    AgentStatus,
    SpecialistAgentResult,
)
from agents.evidence_agent import EvidenceAgentResult
from agents.registry import (
    EVIDENCE_AGENT,
    FUSION_AGENT,
    PERFORMANCE_AGENT,
    QUALITY_AGENT,
    SECURITY_AGENT,
)
from models.schemas import (
    Category,
    Finding,
    FindingProvenance,
    FindingSource,
    ValidatedFinding,
)

logger = logging.getLogger(__name__)

_CATEGORY_AGENT = {
    Category.SECURITY: SECURITY_AGENT,
    Category.PERFORMANCE: PERFORMANCE_AGENT,
    Category.QUALITY: QUALITY_AGENT,
}


def _dedup_key(f: Finding) -> tuple[str, int, str]:
    return (f.file, f.line, f.detector)


class FusionResult(BaseModel):
    """Final fused findings with per-finding provenance."""

    agent_name: str = FUSION_AGENT
    findings: list[ValidatedFinding] = Field(default_factory=list)
    duplicates_removed: int = 0
    deterministic_count: int = 0
    ai_accepted_count: int = 0
    execution_metadata: AgentExecutionMetadata


class FindingFusionAgent:
    """Deterministic fusion of specialist + evidence outputs."""

    name = FUSION_AGENT

    def fuse(
        self,
        ctx: AgentContext,
        specialists: list[SpecialistAgentResult] | None = None,
        evidence: EvidenceAgentResult | None = None,
    ) -> FusionResult:
        started = time.monotonic()

        # 1. Deterministic anchors: every validated finding, keyed for dedup.
        fused: dict[tuple[str, int, str], ValidatedFinding] = {}
        for finding in ctx.validated_findings:
            key = _dedup_key(finding)
            if key not in fused:
                agent = _CATEGORY_AGENT.get(finding.category, "static_analyzer")
                # Preserve any provenance already stamped upstream (e.g. a
                # specialist's reviewed_by from a budgeted AI review); ensure
                # detected_by is always populated.
                base = finding.provenance
                detected_by = list(base.detected_by) if base and base.detected_by else [agent]
                if agent not in detected_by:
                    detected_by.append(agent)
                fused[key] = finding.model_copy(
                    update={
                        "provenance": FindingProvenance(
                            detected_by=detected_by,
                            reviewed_by=list(base.reviewed_by) if base else [],
                            fixed_by=list(base.fixed_by) if base else [],
                            verified_by=list(base.verified_by) if base else [],
                        )
                    }
                )

        # 2. Evidence enrichments replace anchors by id (same anchor fields).
        reviewed_ids: set[str] = set()
        if evidence is not None and evidence.status == "enabled":
            enriched_by_id = {f.id: f for f in evidence.enriched}
            for key, current in list(fused.items()):
                enriched = enriched_by_id.get(current.id)
                if enriched is None:
                    continue
                # Preserve the deterministic anchor; attach AI reasoning only.
                updates: dict = {}
                if enriched.ai_reasoning:
                    updates["ai_reasoning"] = enriched.ai_reasoning
                    updates["enriched_by"] = enriched.enriched_by
                    updates["prompt_version"] = enriched.prompt_version
                if enriched.suggested_fix and not current.suggested_fix:
                    updates["suggested_fix"] = enriched.suggested_fix
                if updates:
                    fused[key] = current.model_copy(update=updates)
                reviewed_ids.add(current.id)
                provenance = fused[key].provenance or FindingProvenance(
                    detected_by=[_CATEGORY_AGENT.get(current.category, "static_analyzer")]
                )
                if EVIDENCE_AGENT not in provenance.reviewed_by:
                    provenance.reviewed_by.append(EVIDENCE_AGENT)
                fused[key] = fused[key].model_copy(
                    update={"provenance": provenance}
                )

            # 3. AI-discovered findings that passed the hard gate.
            for accepted in evidence.accepted:
                key = _dedup_key(accepted)
                if key in fused:
                    continue  # anchor wins; never duplicate
                fused[key] = accepted.model_copy(
                    update={
                        "provenance": FindingProvenance(
                            detected_by=[EVIDENCE_AGENT],
                            reviewed_by=[EVIDENCE_AGENT],
                        )
                    }
                )

        findings = sorted(
            fused.values(), key=lambda f: (f.file, f.line, f.source.value, f.detector)
        )
        duplicates_removed = (
            len(ctx.validated_findings)
            + (len(evidence.accepted) if evidence and evidence.status == "enabled" else 0)
            - len(findings)
        )
        ai_count = sum(1 for f in findings if f.source == FindingSource.AI)

        return FusionResult(
            findings=findings,
            duplicates_removed=max(0, duplicates_removed),
            deterministic_count=len(findings) - ai_count,
            ai_accepted_count=ai_count,
            execution_metadata=AgentExecutionMetadata(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                duration_ms=int((time.monotonic() - started) * 1000),
                findings_count=len(findings),
            ),
        )


__all__ = ["FindingFusionAgent", "FusionResult"]
