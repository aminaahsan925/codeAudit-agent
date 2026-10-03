"""Finding construction for live website scans.

Live-scan findings share the repository Finding contract (id, severity,
evidence, rule_id, CWE, provenance) but are clearly marked
``source="live-scan"``. They are built directly from observed HTTP
responses — never through the repository evidence validator (there is no
repository). ``file`` holds the URL path as the locator; ``url`` holds
the full URL; ``line`` is 0 (not applicable to a live response).
"""

from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from models.schemas import Category, Confidence, Finding, FindingSource, Severity

from services.languages.rule_registry import get_rule_by_id


def _url_path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "/"


def make_live_finding(
    *,
    rule_id: str,
    url: str,
    title: str,
    description: str,
    evidence: str,
    severity: Severity,
    confidence: Confidence,
    suggested_fix: str | None = None,
) -> Finding:
    """Build one live-scan finding stamped from the rule registry."""
    rule = get_rule_by_id(rule_id)
    detector = rule.detector if rule else "live_scan"
    cwe_ids = list(rule.cwe_ids) if rule else []
    return Finding(
        id=f"live-{uuid.uuid4().hex[:12]}",
        category=Category.SECURITY,
        severity=severity,
        title=title,
        description=description,
        file=_url_path(url),
        line=0,
        evidence=evidence,
        suggested_fix=suggested_fix,
        confidence=confidence,
        source=FindingSource.LIVE_SCAN,
        detector=detector,
        rule_id=rule_id,
        cwe_ids=cwe_ids,
        url=url,
        provenance=None,
    )
