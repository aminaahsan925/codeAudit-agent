"""Tests for GitHub URL validation and temp-dir handling (no network)."""

import pytest

from services import github_service
from services.github_service import (
    InvalidRepositoryURLError,
    temporary_repo_dir,
    validate_github_url,
)


@pytest.mark.parametrize(
    "url,owner,name",
    [
        ("https://github.com/owner/repo", "owner", "repo"),
        ("https://github.com/owner/repo/", "owner", "repo"),
        ("https://github.com/owner/repo.git", "owner", "repo"),
        ("https://github.com/my-org/my.repo-2", "my-org", "my.repo-2"),
    ],
)
def test_valid_urls(url, owner, name):
    ref = validate_github_url(url)
    assert ref.owner == owner
    assert ref.name == name
    assert ref.url == f"https://github.com/{owner}/{name}"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not a url",
        "https://github.com/onlyowner",
        "https://gitlab.com/owner/repo",
        "http://github.com/owner/repo",  # http, not https
        "https://github.com/owner/repo/extra/path",
        "https://evil.com/owner/repo",
        "rm -rf /",
    ],
)
def test_invalid_urls_rejected(url):
    with pytest.raises(InvalidRepositoryURLError):
        validate_github_url(url)


def test_temporary_repo_dir_cleaned_up():
    with temporary_repo_dir() as tmp:
        assert tmp.exists()
        (tmp / "sentinel").write_text("x")
        saved = tmp
    assert not saved.exists()
