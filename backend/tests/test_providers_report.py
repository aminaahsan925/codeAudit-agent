"""Tests for the AI provider boundary and report generator."""

import pytest

from services.ai_provider import AIProviderNotConfigured, StubAIProvider
from services.nemotron_service import NemotronService
from services.report_generator import ReportGenerator
from tests.fakes import FakeOpenAIClient


def test_nemotron_unconfigured_raises_cleanly():
    service = NemotronService(api_key="", model="")
    assert not service.is_configured
    with pytest.raises(AIProviderNotConfigured):
        service.investigate([], {})


def test_nemotron_configured_uses_injected_client():
    import json

    from services.ai_context_builder import AIContext

    payload = json.dumps({"assessments": [], "new_findings": []})
    client = FakeOpenAIClient(response_text=payload)
    service = NemotronService(
        api_key="fake-key", model="fake-model", client_factory=lambda: client
    )
    assert service.is_configured
    result = service.investigate([], AIContext(repo_owner="o", repo_name="r"))
    assert result.status == "enabled"
    assert result.provider_name == "nemotron"


def test_stub_provider_returns_disabled_result():
    stub = StubAIProvider()
    assert stub.name == "stub"
    result = stub.investigate(["a", "b"], {})
    assert result.status == "disabled"
    assert result.assessments == [] and result.candidates == []


def test_report_generator_markdown(fixtures_dir):
    from pathlib import Path
    import shutil
    import tempfile

    from services.orchestrator import AnalysisOrchestrator

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "demo"
        shutil.copytree(fixtures_dir / "sql_injection_example", root)
        result = AnalysisOrchestrator().run_on_local_path(root)

    md = ReportGenerator().to_markdown(result)
    assert "CodeAudit Report" in md
    assert "Potential SQL injection" in md
    assert "users.py" in md
    # 2 SQL findings x (60 x 0.7 x 1.0) = 84 points -> score 1/10, low.
    assert "Risk: 1/10 (low)" in md
    d = ReportGenerator().to_dict(result)
    assert d["summary"]["findings_total"] == 2
