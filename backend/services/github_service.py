"""GitHub repository service: validation, metadata, and safe cloning.

Cloning uses `git clone --depth 1` via subprocess with an argument list
(never shell=True), a configurable timeout, and a caller-managed temporary
directory. No repository code is ever executed.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from app.config import settings

logger = logging.getLogger(__name__)

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


class GitHubError(Exception):
    """Base class for GitHub service errors."""

    code = "GITHUB_ERROR"


class InvalidRepositoryURLError(GitHubError):
    code = "INVALID_REPOSITORY_URL"


class RepositoryNotFoundError(GitHubError):
    code = "REPOSITORY_NOT_FOUND"


class CloneFailedError(GitHubError):
    code = "CLONE_FAILED"


class CloneTimeoutError(GitHubError):
    code = "CLONE_TIMEOUT"


@dataclass(frozen=True)
class RepoReference:
    owner: str
    name: str
    url: str


def validate_github_url(url: str) -> RepoReference:
    """Validate a public GitHub repository URL and extract owner/repo."""
    cleaned = (url or "").strip()
    match = _GITHUB_URL_RE.match(cleaned)
    if not match:
        raise InvalidRepositoryURLError(
            f"Not a valid public GitHub repository URL: {url!r}. "
            "Expected https://github.com/<owner>/<repo>."
        )
    owner = match.group("owner")
    repo = match.group("repo")
    return RepoReference(owner=owner, name=repo, url=f"https://github.com/{owner}/{repo}")


def clone_repository(ref: RepoReference, dest: Path) -> Path:
    """Shallow-clone a repo into dest. Raises typed errors on failure."""
    cmd = ["git", "clone", "--depth", "1", "--no-checkout", ref.url + ".git", str(dest)]
    logger.info("Cloning repository %s (depth 1)", ref.url)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.clone_timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise CloneTimeoutError(
            f"Cloning {ref.url} timed out after {settings.clone_timeout_seconds}s."
        ) from exc
    except OSError as exc:
        raise CloneFailedError(f"Could not start git: {exc}") from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "not found" in stderr.lower() or "repository" in stderr.lower() and "not found" in stderr.lower():
            raise RepositoryNotFoundError(f"Repository not found: {ref.url}")
        if "could not resolve" in stderr.lower() or "network" in stderr.lower():
            raise CloneFailedError(f"Network failure while cloning {ref.url}.")
        raise CloneFailedError(f"Clone failed for {ref.url}: {stderr[:500]}")

    # Checkout the files now that the objects are fetched.
    checkout = subprocess.run(
        ["git", "-C", str(dest), "checkout", "-f"],
        capture_output=True,
        text=True,
        timeout=settings.clone_timeout_seconds,
    )
    if checkout.returncode != 0:
        raise CloneFailedError(f"Checkout failed for {ref.url}: {(checkout.stderr or '').strip()[:500]}")
    return dest


@contextmanager
def temporary_repo_dir() -> Iterator[Path]:
    """Yield a temp dir for a cloned repo; always cleaned up afterwards."""
    tmp = Path(tempfile.mkdtemp(prefix="codeaudit-repo-"))
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def fetch_metadata(ref: RepoReference) -> dict:
    """Best-effort public metadata via PyGithub. Never raises.

    Returns an empty dict when PyGithub is unavailable, the network fails,
    or no token is configured. Metadata is informational only.
    """
    try:
        from github import Github, GithubException
    except ImportError:
        logger.debug("PyGithub not installed; skipping metadata fetch")
        return {}
    try:
        client = Github(settings.github_token or None, timeout=15)
        repo = client.get_repo(f"{ref.owner}/{ref.name}")
        return {
            "default_branch": repo.default_branch,
            "description": (repo.description or "")[:500],
        }
    except Exception as exc:  # noqa: BLE001 - metadata is best-effort by design
        logger.debug("Metadata fetch failed for %s: %s", ref.url, exc)
        return {}
