"""Central constants: ignore rules, language map, safety limits, risk weights.

Everything configurable lives here (or in Settings) instead of being
scattered as magic strings through the codebase.
"""

from __future__ import annotations

# Directories never scanned (dependency installs, VCS metadata, build output).
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        "dist",
        "build",
        "eggs",
        ".eggs",
        "coverage",
        ".coverage",
        "htmlcov",
        ".cache",
        "vendor",
        "target",
        ".idea",
        ".vscode",
    }
)

# File extensions that are never analyzed (binaries, archives, media, locks).
IGNORED_EXTENSIONS = frozenset(
    {
        ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".bin",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".db", ".sqlite", ".sqlite3",
        ".lock",
    }
)

# Extension -> language. Phase 1 performs deep analysis for Python only;
# other languages are recognized so future parsers can plug in.
LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
}

# Only these languages get deep (AST) parsing in Phase 1.
DEEP_ANALYSIS_LANGUAGES = frozenset({"python"})

# --- Risk engine: transparent, auditable weights (heuristic, not validated) ---
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 60,
    "medium": 30,
    "low": 10,
    "info": 1,
}

CONFIDENCE_FACTORS = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
}

# Repository-level risk bands over the 0-100 score.
RISK_BANDS = (
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0, "low"),
)

# Variable-name hints used by the hardcoded-secret detector.
SECRET_NAME_HINTS = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "api_secret", "auth_token", "access_token", "private_key",
    "client_secret", "db_password", "database_password",
)

# Values that look like placeholders, not real secrets.
SECRET_PLACEHOLDER_HINTS = (
    "xxx", "***", "changeme", "example", "your_", "placeholder",
    "todo", "dummy", "test123",
)
