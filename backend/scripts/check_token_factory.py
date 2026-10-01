#!/usr/bin/env python3
"""Diagnose Nebius Token Factory connectivity and model availability.

Resolves the real Nemotron model identifier at runtime against the live
/v1/models catalog — do NOT hardcode a model id from an old guide.

Usage (from backend/):
    python scripts/check_token_factory.py
    python scripts/check_token_factory.py --model <candidate-id>

Exit codes: 0 = configured model available; 1 = reachable but the
configured model is not in the catalog; 2 = auth/network/config problem.

Never prints the API key (only whether one is set).
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.nemotron_service import NemotronService  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Token Factory model availability.")
    parser.add_argument("--model", default="", help="Override NEMOTRON_MODEL for this check.")
    args = parser.parse_args()

    service = NemotronService(model=args.model)
    print(f"base_url: {service.base_url}")
    print(f"api_key set: {bool(service.api_key)}")
    print(f"model: {service.model or '(not configured)'}")

    result = service.check_model_availability()
    print(f"reachable: {result.reachable}")
    print(f"authenticated: {result.authenticated}")
    if result.error_code:
        print(f"error: {result.error_code} — {result.error_message}")
        return 2
    print(f"catalog models ({len(result.models)}):")
    for model_id in result.models:
        marker = "  <-- configured" if model_id == service.model else ""
        print(f"  - {model_id}{marker}")
    print(f"configured model available: {result.model_available}")
    return 0 if result.model_available else 1


if __name__ == "__main__":
    raise SystemExit(main())
