"""Tests for the repository scanner: ignore rules, limits, language detection."""

import pytest

from services.repository_scanner import (
    RepositoryTooLargeError,
    detect_language,
    scan_repository,
)


def test_mixed_repository_only_main_analyzed(fixtures_dir):
    result = scan_repository(fixtures_dir / "mixed_repository")
    paths = [f.relative_path for f in result.files]
    assert paths == ["main.py"]
    assert result.skipped >= 2  # node_modules, venv file
    assert result.skipped_reasons.get("ignored_dir", 0) >= 2


def test_detect_language():
    from pathlib import Path

    assert detect_language(Path("a.py")) == "python"
    assert detect_language(Path("a.TS")) == "typescript"
    assert detect_language(Path("a.js")) == "javascript"
    assert detect_language(Path("nope.xyz")) is None


def test_binary_and_empty_skipped(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "empty.py").write_text("")
    (tmp_path / "ok.py").write_text("x = 1\n")
    result = scan_repository(tmp_path)
    assert [f.relative_path for f in result.files] == ["ok.py"]


def test_symlink_not_followed(tmp_path):
    target = tmp_path / "real.py"
    target.write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(target)
    result = scan_repository(tmp_path)
    assert [f.relative_path for f in result.files] == ["real.py"]


def test_file_count_budget_breach_raises(tmp_path, monkeypatch):
    """Exceeding max_files is a structured error, never a silent partial scan."""
    from dataclasses import replace

    import services.repository_scanner as scanner_mod
    from app import config

    monkeypatch.setattr(
        scanner_mod, "settings", replace(config.settings, max_files=2)
    )
    for i in range(4):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    with pytest.raises(RepositoryTooLargeError) as exc_info:
        scan_repository(tmp_path)
    assert exc_info.value.code == "REPOSITORY_TOO_LARGE"


def test_payload_budget_breach_raises(tmp_path, monkeypatch):
    from dataclasses import replace

    import services.repository_scanner as scanner_mod
    from app import config

    monkeypatch.setattr(
        scanner_mod, "settings", replace(config.settings, max_total_bytes=10)
    )
    (tmp_path / "a.py").write_text("x = 1\n" * 100)
    with pytest.raises(RepositoryTooLargeError):
        scan_repository(tmp_path)


def test_file_size_limit_respected(tmp_path, monkeypatch):
    from dataclasses import replace

    import services.repository_scanner as scanner_mod
    from app import config

    monkeypatch.setattr(
        scanner_mod, "settings", replace(config.settings, max_file_size_bytes=10)
    )
    (tmp_path / "big.py").write_text("x = 1\n" * 100)
    (tmp_path / "small.py").write_text("x = 1\n")
    result = scan_repository(tmp_path)
    assert [f.relative_path for f in result.files] == ["small.py"]
    assert result.skipped_reasons.get("too_large") == 1
