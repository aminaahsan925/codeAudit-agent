"""API tests: validation, error mapping, and POST /analyze (hermetic).

POST /analyze never touches the network in tests: the clone step is
monkeypatched to copy a controlled fixture tree instead.
"""

import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from app import main as app_main
from services import github_service


def test_analyze_rejects_invalid_url(client: TestClient):
    response = client.post("/analyze", json={"repository_url": "not-a-url"})
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "INVALID_REPOSITORY_URL"


def test_analyze_rejects_missing_url(client: TestClient):
    response = client.post("/analyze", json={})
    assert response.status_code == 422


def test_analyze_rejects_non_github_host(client: TestClient):
    response = client.post("/analyze", json={"repository_url": "https://gitlab.com/o/r"})
    assert response.status_code == 422


def _fake_clone(ref, dest: Path, fixtures_dir: Path, fixture: str):
    """Stand-in for clone_repository: copy a fixture tree, no network."""
    shutil.copytree(fixtures_dir / fixture, dest)
    return dest


def test_analyze_end_to_end_hermetic(client: TestClient, fixtures_dir, monkeypatch):
    def fake_clone(ref, dest):
        return _fake_clone(ref, dest, fixtures_dir, "sql_injection_example")

    monkeypatch.setattr(app_main.orchestrator, "fetch_repo", lambda url, dest: fake_clone(
        github_service.validate_github_url(url), dest
    ))
    # Metadata is best-effort and network-bound; the live path was verified
    # manually against the real GitHub API. Keep the suite hermetic.
    monkeypatch.setattr(
        github_service, "fetch_metadata", lambda ref: {"default_branch": "main"}
    )

    response = client.post(
        "/analyze", json={"repository_url": "https://github.com/demo/vuln-app"}
    )
    assert response.status_code == 200
    body = response.json()

    assert body["repository"]["owner"] == "demo"
    assert body["repository"]["name"] == "vuln-app"
    assert body["summary"]["files_scanned"] == 1
    assert body["summary"]["files_discovered"] == 1
    assert body["summary"]["files_deep_analyzed"] == 1
    assert body["summary"]["files_unsupported"] == 0
    assert body["summary"]["files_failed_parse"] == 0
    assert body["summary"]["findings_total"] == 2

    detectors = {f["detector"] for f in body["findings"]}
    assert detectors == {"sql_string_construction"}

    finding = body["findings"][0]
    assert finding["file"] == "users.py"
    assert finding["evidence"] in (
        '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        '    cursor.execute(f"SELECT * FROM products WHERE name LIKE \'%{term}%\'")',
    )
    assert finding["source"] == "deterministic"
    assert finding["severity"] == "high"

    # Transparent risk accounting is part of the response.
    # 2 SQL findings x (60 x 0.7 x 1.0) = 84 points -> min(10, round(0.84)) = 1.
    assert body["risk"]["score"] == 1
    assert body["risk"]["level"] == "low"
    assert "formula" in body["risk"]["breakdown"]
    assert body["risk"]["breakdown"]["findings_counted"] == 2


def test_analyze_clone_failure_maps_to_502(client: TestClient, monkeypatch):
    def boom(url, dest):
        raise github_service.CloneFailedError("no network in tests")

    monkeypatch.setattr(app_main.orchestrator, "fetch_repo", boom)
    response = client.post(
        "/analyze", json={"repository_url": "https://github.com/demo/vuln-app"}
    )
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "CLONE_FAILED"


def test_analyze_too_large_repo_maps_to_413(client: TestClient, monkeypatch):
    from services import repository_scanner

    def boom(url, dest):
        raise repository_scanner.RepositoryTooLargeError("budget exceeded in tests")

    monkeypatch.setattr(app_main.orchestrator, "fetch_repo", boom)
    response = client.post(
        "/analyze", json={"repository_url": "https://github.com/demo/huge-repo"}
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REPOSITORY_TOO_LARGE"


def test_analyze_unexpected_error_maps_to_structured_500(monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    # raise_server_exceptions=False: observe the 500 response the handler
    # produces (Starlette's ServerErrorMiddleware re-raises the original
    # exception to the test client otherwise).
    local_client = TestClient(app, raise_server_exceptions=False)

    def boom(url, dest):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(app_main.orchestrator, "fetch_repo", boom)
    response = local_client.post(
        "/analyze", json={"repository_url": "https://github.com/demo/vuln-app"}
    )
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    # No internals leak into the response.
    assert "kaboom" not in body["error"]["message"]


def test_dropped_findings_surfaced_in_summary(fixtures_dir, monkeypatch):
    """Validator drops are reported in the summary, never silently swallowed."""
    import tempfile

    from models.schemas import (
        Category,
        Confidence,
        Finding,
        FindingSource,
        Severity,
    )
    from services.orchestrator import AnalysisOrchestrator

    ghost = Finding(
        id="ghost",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="t",
        description="d",
        file="ghost.py",
        line=1,
        evidence="nope",
        confidence=Confidence.HIGH,
        source=FindingSource.DETERMINISTIC,
        detector="d",
    )
    orchestrator = AnalysisOrchestrator()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "demo"
        root.mkdir()
        shutil.copytree(fixtures_dir / "safe_python", root / "ok")
        monkeypatch.setattr(orchestrator, "analyze_static", lambda scan: [ghost])
        result = orchestrator.run_on_local_path(root)

    assert result.summary.findings_total == 0
    assert result.summary.findings_dropped == 1
    assert result.findings == []


def test_empty_repo_summary_reconciles(tmp_path):
    from services.orchestrator import AnalysisOrchestrator

    result = AnalysisOrchestrator().run_on_local_path(tmp_path)
    assert result.summary.files_discovered == 0
    assert result.summary.files_scanned == 0
    assert result.summary.files_deep_analyzed == 0
    assert result.summary.files_unsupported == 0
    assert result.summary.files_skipped == 0
    assert result.summary.files_failed_parse == 0
    assert result.summary.findings_total == 0
    assert result.risk.score == 0


def test_orchestrator_full_pipeline_on_fixtures(fixtures_dir):
    """The whole pipeline over the demo fixtures: the acceptance shape."""
    from services.orchestrator import AnalysisOrchestrator

    import tempfile

    orchestrator = AnalysisOrchestrator()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "demo"
        root.mkdir()
        for fx in (
            "safe_python",
            "sql_injection_example",
            "hardcoded_secret_example",
            "xss_example",
            "dangerous_eval_example",
            "invalid_python",
        ):
            shutil.copytree(fixtures_dir / fx, root / fx)
        result = orchestrator.run_on_local_path(root)

    s = result.summary
    assert s.files_discovered == 6
    assert s.files_scanned == 6
    assert s.files_deep_analyzed == 5  # all .py except invalid_python
    assert s.files_unsupported == 0
    assert s.files_skipped == 0
    assert s.files_failed_parse == 1  # invalid_python
    # Reconciliation invariant holds.
    assert s.files_discovered == (
        s.files_deep_analyzed + s.files_unsupported + s.files_skipped + s.files_failed_parse
    )
    assert s.files_scanned == (
        s.files_deep_analyzed + s.files_unsupported + s.files_failed_parse
    )
    detectors = {f.detector for f in result.findings}
    assert {
        "sql_string_construction",
        "hardcoded_secret",
        "unsafe_html_render",
        "dangerous_eval",
        "dangerous_exec",
    } <= detectors
    # Every finding survived the hard-gate validator with real evidence.
    assert all(f.validation == "passed" for f in result.findings)
    assert result.risk.score > 0
