"""API tests for POST /remediate and POST /remediate/batch (hermetic).

The clone step is monkeypatched to copy a controlled fixture tree (no
network), the AI provider is a FakeAIProvider injected into the app's
remediation engine, and metadata is stubbed like in test_api.py.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main as app_main
from agents.supervisor_agent import SupervisorAgent
from models.schemas import (
    FixChange,
    FixDecision,
    FixProposal,
    VerificationStatus,
)
from services import github_service
from services.remediation_engine import RemediationEngine
from tests.fakes import FakeAIProvider

SQLI = "sql_string_construction:app.py:9"
EXEC_LINE = '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
GOOD_FIX = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
URL = "https://github.com/demo/vuln-app"


def _good_proposal() -> FixProposal:
    return FixProposal(
        finding_id=SQLI,
        decision=FixDecision.FIX,
        reasoning="parameterize",
        changes=[
            FixChange(
                file="app.py",
                start_line=9,
                end_line=9,
                old_text=EXEC_LINE,
                new_text=GOOD_FIX,
                rationale="fix",
            )
        ],
        expected_effect="finding eliminated",
        verification_notes="rerun the analyzer",
    )


@pytest.fixture()
def remediate_client(
    client: TestClient, fixtures_dir: Path, monkeypatch
) -> TestClient:
    def fake_clone(ref, dest: Path):
        shutil.copytree(fixtures_dir / "remediation_sqli", dest)
        return dest

    monkeypatch.setattr(
        app_main.orchestrator,
        "fetch_repo",
        lambda url, dest: fake_clone(github_service.validate_github_url(url), dest),
    )
    monkeypatch.setattr(
        github_service, "fetch_metadata", lambda ref: {"default_branch": "main"}
    )
    # Multi-agent upgrade: /remediate routes through the supervisor, which
    # enforces AI budgets per its mode. Inject a supervisor wired to the
    # fake provider in economy mode (one budgeted remediation call); free
    # mode would force the stub provider and return UNAVAILABLE by design.
    monkeypatch.setattr(
        app_main,
        "supervisor",
        SupervisorAgent(
            orchestrator=app_main.orchestrator,
            ai_provider=FakeAIProvider(fix_proposal=_good_proposal()),
            default_mode="economy",
        ),
    )
    return client


def test_remediate_happy_path(remediate_client: TestClient):
    response = remediate_client.post(
        "/remediate", json={"repository_url": URL, "finding_id": SQLI}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verified"
    assert body["finding_id"] == SQLI
    assert body["verification"]["verified"] is True
    assert body["proposal"]["finding_id"] == SQLI
    assert len(body["changes_applied"]) == 1


def test_remediate_unknown_finding_is_404(remediate_client: TestClient):
    response = remediate_client.post(
        "/remediate", json={"repository_url": URL, "finding_id": "nope:x:1"}
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "REMEDIATION_FINDING_NOT_FOUND"


def test_remediate_rejects_invalid_url(remediate_client: TestClient):
    response = remediate_client.post(
        "/remediate", json={"repository_url": "not-a-url", "finding_id": SQLI}
    )
    assert response.status_code == 422


def test_remediate_batch_happy_path(remediate_client: TestClient):
    response = remediate_client.post(
        "/remediate/batch",
        json={"repository_url": URL, "finding_ids": [SQLI]},
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["status"] == "verified"


def test_remediate_batch_over_cap_is_400(remediate_client: TestClient):
    response = remediate_client.post(
        "/remediate/batch",
        json={"repository_url": URL, "finding_ids": [SQLI] * 4},
    )
    assert response.status_code == 400
    assert "limit" in response.json()["detail"]


def test_remediate_unavailable_provider(remediate_client: TestClient, monkeypatch):
    # Multi-agent upgrade: the supervisor owns the remediation path; a
    # disabled provider must surface as UNAVAILABLE through the Fix agent.
    monkeypatch.setattr(
        app_main,
        "supervisor",
        SupervisorAgent(
            orchestrator=app_main.orchestrator,
            ai_provider=FakeAIProvider(fix_status="disabled"),
            default_mode="economy",
        ),
    )
    response = remediate_client.post(
        "/remediate", json={"repository_url": URL, "finding_id": SQLI}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"
