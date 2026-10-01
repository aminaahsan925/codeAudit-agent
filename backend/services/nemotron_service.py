"""Nemotron service: real NVIDIA Nemotron via Nebius Token Factory.

Production AIProvider implementation using the official OpenAI-compatible
client against the Token Factory ``/v1`` API. Responsibilities:

  * client creation (lazy; injectable factory for hermetic tests)
  * request construction via versioned prompts
  * timeout + bounded retries (SDK-level, transient failures only)
  * response extraction + robust JSON parsing (strict -> fenced -> reject)
  * normalization + Pydantic validation of the structured output contract
  * typed AI errors (never raw SDK exceptions, never credential leakage)
  * token/payload safeguards via the budgeted AIContext (never the whole repo)

It does NOT clone repos, discover files, compute risk, mutate the
filesystem, or generate PDFs. The model identifier is configuration
(NEMOTRON_MODEL), resolved against the live /v1/models catalog — never
hardcoded from an old guide.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from app.config import Settings, settings
from models.schemas import AIInvestigationResponse, Finding, FixProposal
from services.ai_context_builder import AIContext
from services.fix_context_builder import FixContext
from services.ai_errors import (
    AIError,
    AIInvalidResponse,
    AIModelUnavailable,
    AIOutputInvalid,
    AIProviderNotConfigured,
    AIRateLimited,
    AIRequestTimeout,
    AIUpstreamError,
    SAFE_MESSAGES,
)
from services.ai_provider import AIInvestigationResult, FixProposalResult
from services.prompts import (
    CODEAUDIT_REMEDIATION_PROMPT_V1,
    build_fix_messages,
    build_investigation_messages,
)

logger = logging.getLogger(__name__)


def _build_http_client() -> Any:
    """Build the httpx client for the OpenAI-compatible SDK.

    Uses trust_env=False with an explicit proxy so exotic NO_PROXY entries
    (e.g. bracketed IPv6 literals, as found in some sandboxes) cannot crash
    client construction — httpx fails parsing those when it builds its
    proxy map from the environment. Egress behavior is otherwise unchanged:
    the configured HTTPS proxy is still used when present, and TLS is
    verified against SSL_CERT_FILE/REQUESTS_CA_BUNDLE when set (the sandbox
    egress proxy terminates TLS with its own CA, mirroring curl's
    CURL_CA_BUNDLE behavior).
    """
    import os

    import httpx

    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    verify: Any = (
        os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE") or True
    )
    if proxy:
        return httpx.Client(trust_env=False, proxy=proxy, verify=verify)
    return httpx.Client(trust_env=False, verify=verify)

_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


@dataclass
class ModelCheckResult:
    """Outcome of a /v1/models diagnostic (never raises for diagnostics)."""

    reachable: bool = False
    authenticated: bool = False
    model_available: bool = False
    models: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


class NemotronService:
    """AIProvider implementation for NVIDIA Nemotron via Nebius Token Factory."""

    name = "nemotron"

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        *,
        client_factory: Callable[[], Any] | None = None,
        cfg: Settings | None = None,
    ) -> None:
        cfg = cfg or settings
        self.api_key = api_key or cfg.nebius_api_key
        self.model = model or cfg.nemotron_model
        self.base_url = base_url or cfg.nebius_base_url
        self.temperature = cfg.ai_temperature
        self.max_tokens = cfg.ai_max_tokens
        self.timeout_s = cfg.ai_timeout_seconds
        self.max_retries = cfg.ai_max_retries
        self.fix_temperature = cfg.fix_temperature
        self.fix_max_tokens = cfg.fix_max_tokens
        self.fix_max_changes = max(1, cfg.fix_max_changes)
        self.response_format = (cfg.ai_response_format or "json_object").strip().lower()
        self._client_factory = client_factory or self._default_client_factory
        self._client: Any | None = None

    # -- configuration ---------------------------------------------------

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.model)

    def _default_client_factory(self) -> Any:
        # Lazy import: hermetic tests inject a fake factory and never need
        # the real SDK; production installs it via requirements.txt.
        from openai import OpenAI

        return OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout_s,
            max_retries=self.max_retries,
            http_client=_build_http_client(),
        )

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    # -- diagnostics ------------------------------------------------------

    def check_model_availability(self) -> ModelCheckResult:
        """Verify Token Factory reachability, auth, and model presence.

        Distinguishes "authentication succeeds" from "the selected model is
        available" (§43). Never raises; never exposes the API key.
        """
        if not self.api_key:
            return ModelCheckResult(
                error_code=AIProviderNotConfigured.code,
                error_message=SAFE_MESSAGES[AIProviderNotConfigured.code],
            )
        try:
            listing = self._get_client().models.list()
        except Exception as exc:  # noqa: BLE001 - mapped below, never leaks
            code = self._classify_sdk_error(exc).code
            logger.warning("Model catalog check failed: %s", code)
            return ModelCheckResult(
                error_code=code, error_message=SAFE_MESSAGES.get(code, code)
            )
        ids = sorted({m.id for m in listing.data if getattr(m, "id", None)})
        return ModelCheckResult(
            reachable=True,
            authenticated=True,
            model_available=bool(self.model) and self.model in ids,
            models=ids,
        )

    # -- investigation -----------------------------------------------------

    def investigate(
        self, findings: list[Finding], context: AIContext
    ) -> AIInvestigationResult:
        """Run one bounded Nemotron investigation over deterministic evidence."""
        if not self.is_configured:
            raise AIProviderNotConfigured(
                "NemotronService is not configured: set NEBIUS_API_KEY and "
                "NEMOTRON_MODEL to enable AI investigation."
            )
        started = time.monotonic()
        builder = context.message_builder or build_investigation_messages
        messages = builder(context)
        context_chars = len(messages[1]["content"])
        prompt_version = context.prompt_version

        try:
            response = self._get_client().chat.completions.create(
                **self._completion_kwargs(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            )
        except Exception as exc:  # noqa: BLE001 - mapped to typed errors
            raise self._classify_sdk_error(exc) from exc

        text = self._extract_content(response)
        payload = self._parse_structured_output(text)
        parsed = self._validate_output(payload)

        duration_ms = int((time.monotonic() - started) * 1000)
        logger.info(
            "Nemotron investigation: model=%s prompt=%s duration_ms=%d "
            "context_chars=%d assessments=%d candidates=%d repo=%s/%s",
            self.model,
            prompt_version,
            duration_ms,
            context_chars,
            len(parsed.assessments),
            len(parsed.new_findings),
            context.repo_owner,
            context.repo_name,
        )
        return AIInvestigationResult(
            status="enabled",
            assessments=parsed.assessments,
            candidates=parsed.new_findings,
            model_calls=1,
            context_chars=context_chars,
            duration_ms=duration_ms,
            provider_name=self.name,
            model=self.model,
            prompt_version=prompt_version,
        )

    def propose_fix(self, finding: Finding, context: FixContext) -> FixProposalResult:
        """Ask Nemotron for one structured, minimal remediation proposal.

        Advisory only: the returned proposal still faces the deterministic
        patch engine (validation), an isolated workspace (application), and
        the deterministic analyzer (verification) before anything is trusted.
        """
        if not self.is_configured:
            raise AIProviderNotConfigured(
                "NemotronService is not configured: set NEBIUS_API_KEY and "
                "NEMOTRON_MODEL to enable AI remediation."
            )
        started = time.monotonic()
        messages = build_fix_messages(finding, context)
        context_chars = len(messages[1]["content"])
        prompt_version = CODEAUDIT_REMEDIATION_PROMPT_V1

        try:
            response = self._get_client().chat.completions.create(
                **self._completion_kwargs(
                    model=self.model,
                    messages=messages,
                    temperature=self.fix_temperature,
                    max_tokens=self.fix_max_tokens,
                )
            )
        except Exception as exc:  # noqa: BLE001 - mapped to typed errors
            raise self._classify_sdk_error(exc) from exc

        text = self._extract_content(response)
        payload = self._parse_structured_output(text)
        proposal = self._validate_fix_output(payload, finding.id)

        duration_ms = int((time.monotonic() - started) * 1000)
        logger.info(
            "Nemotron fix proposal: model=%s prompt=%s duration_ms=%d "
            "context_chars=%d decision=%s changes=%d finding=%s",
            self.model,
            prompt_version,
            duration_ms,
            context_chars,
            proposal.decision.value,
            len(proposal.changes),
            finding.id,
        )
        return FixProposalResult(
            status="enabled",
            proposal=proposal,
            model_calls=1,
            context_chars=context_chars,
            duration_ms=duration_ms,
            provider_name=self.name,
            model=self.model,
            prompt_version=prompt_version,
        )

    # -- internals ----------------------------------------------------------

    def _completion_kwargs(
        self,
        *,
        model: str,
        messages: list[dict],
        temperature: float,
        max_tokens: int,
    ) -> dict:
        """Build chat.completions.create kwargs.

        response_format=json_object is sent by default. Some reasoning-model
        deployments reject it — set CODEAUDIT_AI_RESPONSE_FORMAT=none to omit
        it (the versioned prompts still demand JSON-only output, and the
        parser recovers fenced JSON deterministically).
        """
        kwargs: dict = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self.response_format == "json_object":
            kwargs["response_format"] = {"type": "json_object"}
        return kwargs

    @staticmethod
    def _extract_content(response: Any) -> str:
        """Extract usable text from a chat completion response.

        Reasoning models (e.g. NVIDIA Nemotron) commonly return the actual
        answer in ``message.reasoning_content`` while ``message.content`` is
        empty or None. Prefer ``content``; fall back to ``reasoning_content``.
        Anything else is fail-closed: raise instead of inventing output.
        """
        message = None
        try:
            choices = response.choices
            message = choices[0].message if choices else None
        except (AttributeError, IndexError, TypeError):
            message = None
        text = None
        if message is not None:
            for attr in ("content", "reasoning_content"):
                try:
                    candidate = getattr(message, attr, None)
                except (AttributeError, TypeError):
                    candidate = None
                if isinstance(candidate, str) and candidate.strip():
                    text = candidate
                    break
        if not isinstance(text, str) or not text.strip():
            raise AIInvalidResponse("Model returned empty or unusable content.")
        return text

    @staticmethod
    def _parse_structured_output(text: str) -> dict:
        """JSON extraction hierarchy: strict -> fenced recovery -> reject."""
        stripped = text.strip()
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            match = _FENCED_JSON_RE.search(stripped)
            if not match:
                raise AIOutputInvalid(
                    "Model output is not valid JSON (and not fenced JSON)."
                ) from None
            try:
                data = json.loads(match.group(1))
            except json.JSONDecodeError:
                raise AIOutputInvalid(
                    "Model output is not valid JSON, even after fence recovery."
                ) from None
        if not isinstance(data, dict):
            raise AIOutputInvalid("Model output must be a JSON object.")
        return data

    @staticmethod
    def _normalize_payload(data: dict) -> dict:
        """Deterministic normalization BEFORE Pydantic validation (§54).

        Lowercases enum strings, strips whitespace, normalizes path
        separators. Rejects path traversal / absolute / empty paths outright:
        fail-closed, never silently repaired.
        """
        normalized = dict(data)
        for key in ("assessments", "new_findings"):
            items = normalized.get(key, [])
            if not isinstance(items, list):
                raise AIOutputInvalid(f"Model output field {key!r} must be a list.")
            cleaned = []
            for item in items:
                if not isinstance(item, dict):
                    raise AIOutputInvalid(
                        f"Model output field {key!r} must contain objects."
                    )
                entry = {
                    k: (v.strip() if isinstance(v, str) else v)
                    for k, v in item.items()
                }
                for enum_key in ("category", "severity", "confidence", "verdict"):
                    if isinstance(entry.get(enum_key), str):
                        entry[enum_key] = entry[enum_key].lower()
                if "file" in entry and isinstance(entry["file"], str):
                    path = entry["file"].replace("\\", "/").strip()
                    if (
                        not path
                        or path.startswith("/")
                        or ".." in path.split("/")
                    ):
                        raise AIOutputInvalid(
                            "Model output contains an invalid file path."
                        )
                    entry["file"] = path
                cleaned.append(entry)
            normalized[key] = cleaned
        return normalized

    def _validate_output(self, data: dict) -> AIInvestigationResponse:
        from pydantic import ValidationError

        try:
            normalized = self._normalize_payload(data)
            return AIInvestigationResponse.model_validate(normalized)
        except (AIOutputInvalid, ValidationError) as exc:
            logger.warning("Nemotron output failed validation: %s", type(exc).__name__)
            if isinstance(exc, AIOutputInvalid):
                raise
            raise AIOutputInvalid(
                "Model output failed schema validation."
            ) from exc

    @staticmethod
    def _normalize_fix_payload(data: dict, max_changes: int) -> dict:
        """Deterministic normalization BEFORE Pydantic validation of a fix.

        Lowercases the decision string, strips whitespace, normalizes path
        separators. Rejects path traversal / absolute / empty paths and
        over-long change lists outright: fail-closed, never silently
        repaired. File case is preserved (repository paths may be
        case-sensitive).
        """
        normalized = dict(data)
        if isinstance(normalized.get("decision"), str):
            normalized["decision"] = normalized["decision"].strip().lower()
        changes = normalized.get("changes", [])
        if not isinstance(changes, list):
            raise AIOutputInvalid("Model output field 'changes' must be a list.")
        if len(changes) > max_changes:
            raise AIOutputInvalid(
                f"Model proposed {len(changes)} changes (limit {max_changes})."
            )
        cleaned = []
        for item in changes:
            if not isinstance(item, dict):
                raise AIOutputInvalid(
                    "Model output field 'changes' must contain objects."
                )
            entry = {
                k: (v.strip() if isinstance(v, str) else v)
                for k, v in item.items()
            }
            if "file" in entry and isinstance(entry["file"], str):
                path = entry["file"].replace("\\", "/").strip()
                if (
                    not path
                    or path.startswith("/")
                    or ".." in path.split("/")
                ):
                    raise AIOutputInvalid(
                        "Model output contains an invalid file path."
                    )
                entry["file"] = path
            cleaned.append(entry)
        normalized["changes"] = cleaned
        return normalized

    def _validate_fix_output(self, data: dict, finding_id: str) -> FixProposal:
        from pydantic import ValidationError

        try:
            normalized = self._normalize_fix_payload(data, self.fix_max_changes)
            # Traceability is stamped by the system: any model-supplied
            # finding_id is discarded and replaced with the finding the model
            # was actually asked about.
            normalized["finding_id"] = finding_id
            return FixProposal.model_validate(normalized)
        except (AIOutputInvalid, ValidationError) as exc:
            logger.warning(
                "Nemotron fix output failed validation: %s", type(exc).__name__
            )
            if isinstance(exc, AIOutputInvalid):
                raise
            raise AIOutputInvalid(
                "Model fix output failed schema validation."
            ) from exc

    @staticmethod
    def _classify_sdk_error(exc: Exception) -> AIError:
        """Map SDK exceptions to typed AI errors. Import is lazy so hermetic
        tests can exercise this with stub exception types."""
        try:
            import openai as _openai
        except ImportError:  # pragma: no cover - prod always has the SDK
            return AIUpstreamError(f"AI client unavailable: {type(exc).__name__}")

        message = SAFE_MESSAGES[AIUpstreamError.code]
        if isinstance(exc, _openai.APITimeoutError):
            return AIRequestTimeout(SAFE_MESSAGES[AIRequestTimeout.code])
        if isinstance(exc, _openai.RateLimitError):
            return AIRateLimited(SAFE_MESSAGES[AIRateLimited.code])
        if isinstance(exc, _openai.AuthenticationError):
            return AIModelUnavailable(
                "Token Factory rejected the API key; check NEBIUS_API_KEY."
            )
        if isinstance(exc, _openai.NotFoundError):
            return AIModelUnavailable(
                "Token Factory does not know this model; check NEMOTRON_MODEL."
            )
        if isinstance(exc, _openai.APIConnectionError):
            return AIUpstreamError("Could not reach the Token Factory endpoint.")
        if isinstance(exc, _openai.APIStatusError):
            if exc.status_code is not None and exc.status_code >= 500:
                return AIUpstreamError(
                    "Token Factory returned a server error (5xx)."
                )
            return AIUpstreamError(message)
        logger.warning("Unexpected AI client error: %s", type(exc).__name__)
        return AIUpstreamError(message)
