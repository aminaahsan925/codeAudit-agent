"""Tests for the AI provider boundary and report generator (interfaces only)."""

import pytest

from services.ai_provider import AIProviderNotConfigured, StubAIProvider
from services.nemotron_service import NemotronService
from services.report_generator import ReportGenerator


def test_nemotron_unconfigured_raises_cleanly():
    service = NemotronService(api_key="", model="")
    assert not service.is_configured
    with pytest.raises(AIProviderNotConfigured):
        service.investigate([], {})


def test_nemotron_configured_but_phase1_refuses_live_call():
    service = NemotronService(api_key="fake-key", model="some-model")
    assert service.is_configured
    with pytest.raises(NotImplementedError):
        service.investigate([], {})


def test_stub_provider_passes_through():
    stub = StubAIProvider()
    assert stub.name == "stub"
    assert stub.investigate(["a", "b"], {}) == ["a", "b"]


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
    assert "Risk:" in md
    d = ReportGenerator().to_dict(result)
    assert d["summary"]["findings_total"] == 2
