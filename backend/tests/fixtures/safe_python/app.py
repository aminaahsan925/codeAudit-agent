"""Clean, safe example code. No findings expected here."""

import hashlib
import os
import subprocess


def get_user(user_id: int, cursor) -> dict | None:
    """Parameterized query: the safe pattern."""
    cursor.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def short_helper(name: str) -> str:
    return name.strip().lower()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def run_ls() -> str:
    result = subprocess.run(["ls", "-la"], capture_output=True, text=True, shell=False)
    return result.stdout


def load_api_key() -> str:
    key = os.environ.get("SERVICE_API_KEY", "")
    if not key:
        raise RuntimeError("SERVICE_API_KEY is not set")
    return key
