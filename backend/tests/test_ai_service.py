"""Tests for NemotronService: the live Token Factory client (hermetic).

Every test injects a FakeOpenAIClient — no network, no API key. Covers the
full error contract (§32), structured-output parsing (§15-17), and model
catalog diagnostics (§43).
"""

from __future__ import annotations

import json

import httpx
import openai
import pytest

from services.ai_context_builder import AIContext
from services.ai_errors import (
    AIInvalidResponse,
    AIModelUnavailable,
    AIOutputInvalid,
    AIProviderNotConfigured,
    AIRateLimited,
    AIRequestTimeout,
    AIUpstreamError,
)
from services.nemotron_service import NemotronService
from tests.fakes import FakeOpenAIClient


def _service(client: FakeOpenAIClient, **kwargs) -> NemotronService:
    return NemotronService(
        api_key="test-key",
        model="test-model",
        client_factory=lambda: client,
        **kwargs,
    )


def _context() -> AIContext:
    return AIContext(repo_owner="o", repo_name="r")


def _sdk_error(cls, status: int):
    req = httpx.Request("POST", "http://tf.test/v1/chat/completions")
    return cls("boom", response=httpx.Response(status, request=req), body=None)


VALID_JSON = json.dumps(
    {
        "assessments": [
            {
                "finding_id": "sql_string_construction:users.py:4",
                "verdict": "confirmed",
                "confidence": "high",
                "reasoning": "EVIDENCE: line builds SQL by concatenation. INFERENCE: injectable.",
                "suggested_fix": "Use parameterized queries.",
            }
        ],
        "new_findings": [
            {
                "title": "Potential command injection",
                "category": "security",
                "severity": "high",
                "file": "users.py",
                "line": 12,
                "evidence": "os.system(cmd)",
                "description": "Shell command built from input.",
                "confidence": "medium",
                "reasoning": "EVIDENCE shows os.system with a variable.",
            }
        ],
    }
)


def test_unconfigured_raises_cleanly():
    service = NemotronService(api_key="", model="")
    assert not service.is_configured
    with pytest.raises(AIProviderNotConfigured):
        service.investigate([], _context())


def test_successful_investigation():
    client = FakeOpenAIClient(response_text=VALID_JSON)
    result = _service(client).investigate([], _context())
    assert result.status == "enabled"
    assert result.provider_name == "nemotron"
    assert result.model == "test-model"
    assert result.model_calls == 1
    assert len(result.assessments) == 1
    assert result.assessments[0].verdict.value == "confirmed"
    assert len(result.candidates) == 1
    assert result.candidates[0].file == "users.py"
    # Request construction: JSON mode, low temperature, bounded output.
    kwargs = client.last_create_kwargs
    assert kwargs["model"] == "test-model"
    assert kwargs["response_format"] == {"type": "json_object"}
    assert kwargs["temperature"] == 0.2
    assert kwargs["max_tokens"] == 2000


def test_fenced_json_recovered():
    client = FakeOpenAIClient(response_text=f'```json\n{VALID_JSON}\n```')
    result = _service(client).investigate([], _context())
    assert result.status == "enabled"
    assert len(result.candidates) == 1


def test_plain_fenced_json_recovered():
    client = FakeOpenAIClient(response_text=f'```\n{VALID_JSON}\n```')
    result = _service(client).investigate([], _context())
    assert len(result.candidates) == 1


def test_malformed_json_rejected():
    client = FakeOpenAIClient(response_text="this is not json {")
    with pytest.raises(AIOutputInvalid):
        _service(client).investigate([], _context())


def test_non_object_json_rejected():
    client = FakeOpenAIClient(response_text='[{"assessments": []}]')
    with pytest.raises(AIOutputInvalid):
        _service(client).investigate([], _context())


def test_invalid_schema_rejected_fail_closed():
    bad = json.dumps({"assessments": [{"finding_id": "x"}], "new_findings": []})
    client = FakeOpenAIClient(response_text=bad)
    with pytest.raises(AIOutputInvalid):
        _service(client).investigate([], _context())


def test_invalid_severity_rejected():
    payload = json.loads(VALID_JSON)
    payload["new_findings"][0]["severity"] = "catastrophic"
    client = FakeOpenAIClient(response_text=json.dumps(payload))
    with pytest.raises(AIOutputInvalid):
        _service(client).investigate([], _context())


def test_path_traversal_rejected():
    payload = json.loads(VALID_JSON)
    payload["new_findings"][0]["file"] = "../../etc/passwd"
    client = FakeOpenAIClient(response_text=json.dumps(payload))
    with pytest.raises(AIOutputInvalid):
        _service(client).investigate([], _context())


def test_absolute_path_rejected():
    payload = json.loads(VALID_JSON)
    payload["new_findings"][0]["file"] = "/etc/passwd"
    client = FakeOpenAIClient(response_text=json.dumps(payload))
    with pytest.raises(AIOutputInvalid):
        _service(client).investigate([], _context())


def test_enum_casing_normalized_not_rejected():
    payload = json.loads(VALID_JSON)
    payload["new_findings"][0]["severity"] = "HIGH"
    payload["new_findings"][0]["category"] = "Security"
    payload["assessments"][0]["verdict"] = "Confirmed"
    client = FakeOpenAIClient(response_text=json.dumps(payload))
    result = _service(client).investigate([], _context())
    assert result.candidates[0].severity.value == "high"
    assert result.assessments[0].verdict.value == "confirmed"


def test_backslash_path_normalized():
    payload = json.loads(VALID_JSON)
    payload["new_findings"][0]["file"] = "pkg\\users.py"
    client = FakeOpenAIClient(response_text=json.dumps(payload))
    result = _service(client).investigate([], _context())
    assert result.candidates[0].file == "pkg/users.py"


def test_empty_content_rejected():
    client = FakeOpenAIClient(response_text="   ")
    with pytest.raises(AIInvalidResponse):
        _service(client).investigate([], _context())


def test_timeout_mapped():
    client = FakeOpenAIClient(exc=openai.APITimeoutError(request=None))
    with pytest.raises(AIRequestTimeout):
        _service(client).investigate([], _context())


def test_rate_limit_mapped():
    client = FakeOpenAIClient(exc=_sdk_error(openai.RateLimitError, 429))
    with pytest.raises(AIRateLimited):
        _service(client).investigate([], _context())


def test_auth_failure_mapped_to_model_unavailable():
    client = FakeOpenAIClient(exc=_sdk_error(openai.AuthenticationError, 401))
    with pytest.raises(AIModelUnavailable):
        _service(client).investigate([], _context())


def test_unknown_model_mapped_to_model_unavailable():
    client = FakeOpenAIClient(exc=_sdk_error(openai.NotFoundError, 404))
    with pytest.raises(AIModelUnavailable):
        _service(client).investigate([], _context())


def test_server_error_mapped_to_upstream():
    client = FakeOpenAIClient(exc=_sdk_error(openai.APIStatusError, 503))
    with pytest.raises(AIUpstreamError):
        _service(client).investigate([], _context())


def test_connection_error_mapped_to_upstream():
    req = httpx.Request("POST", "http://tf.test/v1/chat/completions")
    client = FakeOpenAIClient(exc=openai.APIConnectionError(request=req))
    with pytest.raises(AIUpstreamError):
        _service(client).investigate([], _context())


def test_error_messages_are_sanitized():
    # Typed errors carry short static messages, never raw SDK internals.
    client = FakeOpenAIClient(exc=_sdk_error(openai.AuthenticationError, 401))
    with pytest.raises(AIModelUnavailable) as exc_info:
        _service(client).investigate([], _context())
    assert "test-key" not in str(exc_info.value)


def test_check_model_availability_happy_path():
    client = FakeOpenAIClient(model_ids=("nemotron-3-ultra", "other-model"))
    service = NemotronService(
        api_key="k", model="nemotron-3-ultra", client_factory=lambda: client
    )
    result = service.check_model_availability()
    assert result.reachable and result.authenticated
    assert result.model_available
    assert "nemotron-3-ultra" in result.models


def test_check_distinguishes_auth_ok_from_model_missing():
    client = FakeOpenAIClient(model_ids=("some-other-model",))
    service = NemotronService(
        api_key="k", model="nemotron-3-ultra", client_factory=lambda: client
    )
    result = service.check_model_availability()
    assert result.authenticated and not result.model_available


def test_check_auth_failure():
    client = FakeOpenAIClient(
        models_exc=_sdk_error(openai.AuthenticationError, 401)
    )
    service = NemotronService(
        api_key="bad", model="m", client_factory=lambda: client
    )
    result = service.check_model_availability()
    assert not result.authenticated
    assert result.error_code == AIModelUnavailable.code


def test_check_without_key_reports_not_configured():
    service = NemotronService(api_key="", model="m")
    result = service.check_model_availability()
    assert result.error_code == AIProviderNotConfigured.code
