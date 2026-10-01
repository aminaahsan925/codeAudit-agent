"""Tests for the deterministic patch engine (§10-11 of the spec).

Covers acceptance criteria A-G and S: valid changes apply; invalid,
traversal, absolute, ambiguous, and unrelated changes are rejected; and no
write can escape the repository root. Hermetic: no network, no AI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from models.schemas import FixChange
from services import patch_engine

APP = "app.py"
CONTENTS = {
    APP: (
        '"""Fixture only."""\n'
        "\n"
        "import sqlite3\n"
        "\n"
        "\n"
        "def get_user(user_id):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
        "    return cursor.fetchall()\n"
    )
}
EXEC_LINE = '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
FIXED_LINE = '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'


def _change(**kwargs):
    defaults = {
        "file": APP,
        "start_line": 7,
        "end_line": 7,
        "old_text": EXEC_LINE,
        "new_text": FIXED_LINE,
        "rationale": "parameterize the query",
    }
    defaults.update(kwargs)
    return FixChange(**defaults)


# --- Acceptance: valid changes apply ------------------------------------


def test_valid_change_applies_exactly():
    valid, rejected = patch_engine.validate_changes([_change()], CONTENTS, APP)
    assert len(valid) == 1
    assert rejected == []
    assert valid[0].file == APP


def test_old_text_matches_with_whitespace_tolerance():
    change = _change(old_text=EXEC_LINE + "   ")
    valid, rejected = patch_engine.validate_changes([change], CONTENTS, APP)
    assert len(valid) == 1 and not rejected


def test_apply_validated_changes_rewrites_only_the_range(tmp_path: Path):
    (tmp_path / APP).write_text(CONTENTS[APP], encoding="utf-8")
    outcome = patch_engine.apply_validated_changes([_change()], tmp_path)
    assert len(outcome.applied) == 1
    assert outcome.rejected == []
    after = (tmp_path / APP).read_text(encoding="utf-8").splitlines()
    assert after[6] == FIXED_LINE
    # Everything else is byte-identical.
    assert after[:6] == CONTENTS[APP].splitlines()[:6]
    assert after[7:] == CONTENTS[APP].splitlines()[7:]


# --- Rejections ----------------------------------------------------------


def test_change_to_unrelated_file_rejected():
    """(S) A proposal may only touch the finding's own file."""
    change = _change(file="other.py")
    valid, rejected = patch_engine.validate_changes(
        [change], {"other.py": "x\n"}, APP
    )
    assert valid == []
    assert len(rejected) == 1
    assert rejected[0].reason == "unrelated_file"


def test_change_to_nonexistent_file_rejected():
    change = _change(file="missing.py")
    valid, rejected = patch_engine.validate_changes([change], CONTENTS, "missing.py")
    assert valid == []
    assert rejected[0].reason == "file_not_found"


def test_change_with_wrong_old_text_rejected():
    change = _change(old_text="cursor.execute('totally different')")
    valid, rejected = patch_engine.validate_changes([change], CONTENTS, APP)
    assert valid == []
    assert rejected[0].reason == "old_text_mismatch"


def test_change_with_old_text_matching_wrong_range_rejected():
    """(E) old_text exists in the file but NOT at the claimed lines."""
    change = _change(start_line=1, end_line=1, old_text=EXEC_LINE)
    valid, rejected = patch_engine.validate_changes([change], CONTENTS, APP)
    assert valid == []
    assert rejected[0].reason == "old_text_mismatch"


def test_change_with_inverted_line_range_rejected():
    with pytest.raises(ValueError):
        _change(start_line=7, end_line=3)


def test_change_with_out_of_bounds_lines_rejected():
    change = _change(start_line=1, end_line=99)
    valid, rejected = patch_engine.validate_changes([change], CONTENTS, APP)
    assert valid == []
    assert rejected[0].reason == "line_out_of_range"


def test_change_with_empty_new_text_rejected():
    with pytest.raises(ValueError):
        _change(new_text="  ")


def test_path_traversal_rejected():
    """(F) ../../etc/passwd never becomes a valid change."""
    change = _change(file="../../etc/cron.d/evil", start_line=1, end_line=1,
                    old_text="x", new_text="y")
    valid, rejected = patch_engine.validate_changes(
        [change], {"../../etc/cron.d/evil": "x\n"}, "../../etc/cron.d/evil"
    )
    assert valid == []
    assert rejected[0].reason == "invalid_path"


def test_absolute_path_rejected():
    """(G)"""
    change = _change(file="/etc/passwd", start_line=1, end_line=1,
                    old_text="x", new_text="y")
    valid, rejected = patch_engine.validate_changes(
        [change], {"/etc/passwd": "x\n"}, "/etc/passwd"
    )
    assert valid == []
    assert rejected[0].reason == "invalid_path"


def test_overlapping_changes_second_is_rejected():
    first = _change()
    second = _change(start_line=6, end_line=7, old_text="def get_user(user_id):\n" + EXEC_LINE,
                     new_text="x", rationale="overlapping")
    valid, rejected = patch_engine.validate_changes([first, second], CONTENTS, APP)
    assert len(valid) == 1
    assert len(rejected) == 1
    assert rejected[0].reason == "overlapping_change"


def test_partial_application_valid_changes_apply_invalid_rejected():
    good = _change()
    bad = _change(old_text="nope")
    valid, rejected = patch_engine.validate_changes([good, bad], CONTENTS, APP)
    assert len(valid) == 1 and len(rejected) == 1


def test_apply_refuses_symlink(tmp_path: Path):
    real = tmp_path / "real.py"
    real.write_text(CONTENTS[APP], encoding="utf-8")
    link = tmp_path / APP
    link.symlink_to(real)
    outcome = patch_engine.apply_validated_changes([_change()], tmp_path)
    assert outcome.applied == []
    assert len(outcome.rejected) == 1
    assert outcome.rejected[0].reason == "apply_failed"
    # The link target is untouched.
    assert real.read_text(encoding="utf-8") == CONTENTS[APP]


def test_apply_never_escapes_repo_root(tmp_path: Path):
    """Defense in depth: even a pre-'validated' change cannot write outside."""
    escape = FixChange.model_construct(
        file="../escape.py", start_line=1, end_line=1,
        old_text="x", new_text="pwned", rationale="evil",
    )
    outcome = patch_engine.apply_validated_changes([escape], tmp_path)
    assert outcome.applied == []
    assert outcome.rejected[0].reason == "apply_failed"
    assert not (tmp_path.parent / "escape.py").exists()


def test_apply_reverifies_old_text_against_disk(tmp_path: Path):
    """The disk is re-checked at apply time; a raced change is refused."""
    (tmp_path / APP).write_text("something else entirely\n", encoding="utf-8")
    outcome = patch_engine.apply_validated_changes([_change()], tmp_path)
    assert outcome.applied == []
    assert outcome.rejected[0].reason == "apply_failed"
    assert (tmp_path / APP).read_text(encoding="utf-8") == "something else entirely\n"


def test_apply_missing_file_rejected(tmp_path: Path):
    outcome = patch_engine.apply_validated_changes([_change()], tmp_path)
    assert outcome.applied == []
    assert outcome.rejected[0].reason == "apply_failed"
