#!/usr/bin/env python3
"""Manual live smoke test for the Nemotron/Token Factory integration.

Sends one tiny controlled prompt and verifies a usable response comes back.
This is NOT part of the pytest suite (it needs a real API key and network).

Usage (from backend/):
    NEBIUS_API_KEY=... NEMOTRON_MODEL=... python scripts/smoke_nemotron.py

Exit codes: 0 = live call succeeded; 2 = not configured (skipped);
1 = configured but the call failed.

Never prints the API key or the full prompt/response.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.nemotron_service import NemotronService  # noqa: E402


TINY_PROMPT = (
    "Reply with exactly this JSON and nothing else: "
    '{"assessments": [], "new_findings": []}'
)


def main() -> int:
    service = NemotronService()
    print(f"base_url: {service.base_url}")
    print(f"api_key set: {bool(service.api_key)}")
    print(f"model: {service.model or '(not configured)'}")
    if not service.is_configured:
        print("SKIP: NEBIUS_API_KEY and NEMOTRON_MODEL are required.")
        return 2
    try:
        response = service._get_client().chat.completions.create(
            model=service.model,
            messages=[{"role": "user", "content": TINY_PROMPT}],
            temperature=0,
            max_tokens=64,
            response_format={"type": "json_object"},
        )
        text = response.choices[0].message.content or ""
        data = json.loads(text)
        assert isinstance(data, dict), "response is not a JSON object"
        print(f"OK: live call succeeded in {len(text)} chars; valid JSON object.")
        return 0
    except Exception as exc:  # noqa: BLE001 - smoke test reports, never leaks
        typed = service._classify_sdk_error(exc)
        print(f"FAIL: {typed.code}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
