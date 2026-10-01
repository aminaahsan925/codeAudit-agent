"""Tests for analysis file accounting: buckets and the reconciliation invariant.

Every discovered file must land in exactly one terminal bucket:
deep-analyzed, unsupported, skipped, or parse-failed. All hermetic.
"""

import pytest
from pydantic import ValidationError

from models.schemas import AnalysisSummary
from services.orchestrator import AnalysisOrchestrator


def _build_mixed_tree(root):
    """One file per bucket, plus skips of different reasons."""
    (root / "good.py").write_text("x = 1\n")  # deep-analyzed
    (root / "broken.py").write_text("def broken(:\n")  # failed parse
    (root / "app.js").write_text("var x = 1;\n")  # unsupported language
    (root / "mystery.xyz").write_text("???\n")  # unsupported (unknown ext)
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("var d = 1;\n")  # skipped: ignored_dir
    (root / "empty.py").write_text("")  # skipped: empty
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)  # skipped: ignored_extension


def _valid_summary_kwargs(**overrides):
    base = dict(
        files_discovered=8,
        files_scanned=4,
        files_deep_analyzed=1,
        files_unsupported=2,
        files_skipped=4,
        files_failed_parse=1,
        findings_total=0,
        findings_by_severity={},
        findings_by_category={},
    )
    base.update(overrides)
    return base


def test_mixed_tree_buckets_and_invariant(tmp_path):
    _build_mixed_tree(tmp_path)
    result = AnalysisOrchestrator().run_on_local_path(tmp_path)
    s = result.summary

    assert s.files_discovered == 7
    assert s.files_scanned == 4  # good.py, broken.py, app.js, mystery.xyz
    assert s.files_deep_analyzed == 1  # good.py
    assert s.files_unsupported == 2  # app.js, mystery.xyz
    assert s.files_failed_parse == 1  # broken.py
    assert s.files_skipped == 3  # node_modules/dep.js, empty.py, logo.png

    # Skip reasons distinguish *why* files were excluded.
    assert s.skip_reasons.get("ignored_dir") == 1
    assert s.skip_reasons.get("empty") == 1
    assert s.skip_reasons.get("ignored_extension") == 1

    # Reconciliation invariant: every discovered file is in exactly one bucket.
    assert s.files_discovered == (
        s.files_deep_analyzed + s.files_unsupported + s.files_skipped + s.files_failed_parse
    )
    assert s.files_scanned == (
        s.files_deep_analyzed + s.files_unsupported + s.files_failed_parse
    )

    assert s.findings_total == 0
    assert result.risk.score == 0


def test_single_unsupported_file_lands_in_unsupported_bucket(tmp_path):
    (tmp_path / "notes.txt").write_text("hello\n")
    result = AnalysisOrchestrator().run_on_local_path(tmp_path)
    s = result.summary
    assert (s.files_discovered, s.files_scanned) == (1, 1)
    assert s.files_unsupported == 1
    assert s.files_deep_analyzed == 0
    assert s.files_failed_parse == 0
    assert s.files_skipped == 0


def test_summary_rejects_inconsistent_accounting():
    # discovered (8) != deep (1) + unsupported (2) + skipped (4) + failed (0) = 7
    with pytest.raises(ValidationError):
        AnalysisSummary(**_valid_summary_kwargs(files_failed_parse=0))


def test_summary_rejects_inconsistent_scanned_count():
    # scanned (5) != deep (1) + unsupported (2) + failed (1) = 4
    with pytest.raises(ValidationError):
        AnalysisSummary(**_valid_summary_kwargs(files_scanned=5))


def test_summary_accepts_consistent_accounting():
    s = AnalysisSummary(**_valid_summary_kwargs())
    assert s.files_discovered == 8
