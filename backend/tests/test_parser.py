"""Tests for the Python AST parser."""

from services.code_parser import parse_file, parse_python


def test_valid_python_symbols(fixtures_dir):
    content = (fixtures_dir / "safe_python" / "app.py").read_text()
    parsed = parse_python("app.py", content)
    assert parsed.parse_error is None
    kinds = {(s.kind, s.name) for s in parsed.symbols}
    assert ("function", "get_user") in kinds
    assert ("function", "short_helper") in kinds
    assert ("import", "hashlib") in kinds
    assert ("import", "os") in kinds
    assert ("import", "subprocess") in kinds


def test_invalid_python_structured_error(fixtures_dir):
    content = (fixtures_dir / "invalid_python" / "broken.py").read_text()
    parsed = parse_python("broken.py", content)
    assert parsed.parse_error is not None
    assert "SyntaxError" in parsed.parse_error
    assert parsed.symbols == []


def test_unsupported_language_returns_none():
    assert parse_file("a.js", "javascript", "var x = 1;") is None


def test_one_broken_file_does_not_kill_others(fixtures_dir):
    good = parse_file(
        "good.py", "python", (fixtures_dir / "safe_python" / "app.py").read_text()
    )
    bad = parse_file(
        "bad.py", "python", (fixtures_dir / "invalid_python" / "broken.py").read_text()
    )
    assert good is not None and good.parse_error is None
    assert bad is not None and bad.parse_error is not None
