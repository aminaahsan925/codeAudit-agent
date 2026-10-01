"""Shared pytest fixtures for the CodeAudit backend test suite."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def client() -> TestClient:
    from app.main import app

    return TestClient(app)
