"""Webhook notifications (Phase 8).

Fires an HMAC-SHA256-signed JSON POST to ``CODEAUDIT_WEBHOOK_URL`` when a
scan/analysis completes. Best-effort by design: a failing webhook never
fails the request — failures are logged and swallowed.

Payload shape::
    {
      "event": "scan.completed",
      "kind": "repo_analysis" | "website_scan",
      "project_id": ...,
      "run_id": ...,
      "findings_count": ...,
      "risk_score": ... | None,
    }

Signed with header ``X-CodeAudit-Signature: sha256=<hex>`` using
``CODEAUDIT_WEBHOOK_SECRET``, plus ``X-CodeAudit-Event`` for routing.
No credentials, tokens, or secret finding values are ever included.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

import httpx

logger = logging.getLogger(__name__)

_SIGNATURE_HEADER = "X-CodeAudit-Signature"
_EVENT_HEADER = "X-CodeAudit-Event"
_TIMEOUT_SECONDS = 5.0


def sign_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256 hex signature for a webhook body."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def send_webhook(
    url: str,
    secret: str,
    event: str,
    payload: dict,
    *,
    timeout: float = _TIMEOUT_SECONDS,
) -> bool:
    """POST a signed webhook. Returns True on 2xx, False otherwise.

    Never raises: network/DNS/TLS errors are logged and return False.
    """
    body = json.dumps({"event": event, **payload}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        _SIGNATURE_HEADER: f"sha256={sign_payload(secret, body)}",
        _EVENT_HEADER: event,
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, content=body, headers=headers)
        if 200 <= response.status_code < 300:
            return True
        logger.warning(
            "Webhook to %s returned HTTP %d for event %s",
            url,
            response.status_code,
            event,
        )
        return False
    except Exception:
        logger.warning("Webhook to %s failed for event %s", url, event, exc_info=True)
        return False
