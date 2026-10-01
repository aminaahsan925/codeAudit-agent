"""Deterministic static analyzer: pattern-based detection, no AI involved.

Phase 1 analyzes Python only, with a small set of high-confidence detectors.
Every finding carries the exact source line as evidence. When in doubt the
detector stays silent: false positives are worse than missed weak signals.

Detector registry: each detector is a function
    (tree, lines, relative_path) -> list[Finding]
registered in DETECTORS. Adding a detector means writing one function and
one registry entry.
"""

from __future__ import annotations

import ast
import logging
import re

from models.schemas import Category, Confidence, Finding, FindingSource, Severity
from utils.constants import SECRET_NAME_HINTS, SECRET_PLACEHOLDER_HINTS

logger = logging.getLogger(__name__)


def _line(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip("\n")
    return ""


def _make_finding(
    *,
    detector: str,
    category: Category,
    severity: Severity,
    title: str,
    description: str,
    relative_path: str,
    line: int,
    evidence: str,
    confidence: Confidence,
    suggested_fix: str | None = None,
    column: int | None = None,
) -> Finding:
    finding_id = f"{detector}:{relative_path}:{line}"
    return Finding(
        id=finding_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        file=relative_path,
        line=line,
        column=column,
        evidence=evidence,
        suggested_fix=suggested_fix,
        confidence=confidence,
        source=FindingSource.DETERMINISTIC,
        detector=detector,
    )


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return (
        len(value.strip()) < 4
        or any(hint in lowered for hint in SECRET_PLACEHOLDER_HINTS)
        or lowered.startswith(("os.environ", "getenv"))
    )


def _looks_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SECRET_NAME_HINTS)


# ---------------------------------------------------------------------------
# Security detectors
# ---------------------------------------------------------------------------

def detect_hardcoded_secrets(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    """Assignments like api_key = "sk-live-..." where the name suggests a secret."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        value = node.value.value.strip()
        if not value or _is_placeholder(value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and _looks_secret_name(target.id):
                findings.append(
                    _make_finding(
                        detector="hardcoded_secret",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="Hardcoded secret",
                        description=(
                            f"Variable '{target.id}' looks like a credential but is assigned "
                            "a literal string. Secrets committed to a repository can be "
                            "extracted by anyone with read access."
                        ),
                        relative_path=path,
                        line=node.lineno,
                        evidence=_line(lines, node.lineno),
                        confidence=Confidence.HIGH,
                        suggested_fix=(
                            "Load the secret from an environment variable or a secrets "
                            "manager, and rotate the exposed value."
                        ),
                    )
                )
    return findings


def _is_dynamic_string(node: ast.AST) -> bool:
    """True for string expressions built from non-constant parts."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True  # "SELECT ..." + user_input
    if isinstance(node, ast.JoinedStr):
        return any(not isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True  # "... %s" % value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True  # "...".format(value)
    return False


def detect_sql_string_construction(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    """Dynamic SQL built with concatenation/formatting passed to execute()."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = ""
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if name not in {"execute", "executemany", "raw", "executescript"}:
            continue
        if not node.args or not _is_dynamic_string(node.args[0]):
            continue
        findings.append(
            _make_finding(
                detector="sql_string_construction",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                title="Potential SQL injection",
                description=(
                    "A SQL string is built dynamically (concatenation, f-string, or "
                    "formatting) and passed to a database execute call. If any part "
                    "is user-controlled, this is SQL injection."
                ),
                relative_path=path,
                line=node.lineno,
                evidence=_line(lines, node.lineno),
                confidence=Confidence.MEDIUM,
                suggested_fix=(
                    "Use parameterized queries / prepared statements instead of "
                    "building SQL with string operations."
                ),
            )
        )
    return findings


def _detect_dangerous_call(
    tree: ast.AST,
    lines: list[str],
    path: str,
    *,
    detector: str,
    call_name: str,
    title: str,
    description: str,
    suggested_fix: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
        if name != call_name:
            continue
        dynamic = bool(node.args) and not isinstance(node.args[0], ast.Constant)
        findings.append(
            _make_finding(
                detector=detector,
                category=Category.SECURITY,
                severity=Severity.HIGH if dynamic else Severity.MEDIUM,
                title=title,
                description=description,
                relative_path=path,
                line=node.lineno,
                evidence=_line(lines, node.lineno),
                confidence=Confidence.HIGH if dynamic else Confidence.MEDIUM,
                suggested_fix=suggested_fix,
            )
        )
    return findings


def detect_eval(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    return _detect_dangerous_call(
        tree, lines, path,
        detector="dangerous_eval",
        call_name="eval",
        title="Use of eval()",
        description="eval() executes a string as Python code. With untrusted input this is arbitrary code execution.",
        suggested_fix="Replace eval() with ast.literal_eval() for data, or a proper parser for expressions.",
    )


def detect_exec(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    return _detect_dangerous_call(
        tree, lines, path,
        detector="dangerous_exec",
        call_name="exec",
        title="Use of exec()",
        description="exec() executes a string as Python statements. With untrusted input this is arbitrary code execution.",
        suggested_fix="Restructure the code to avoid dynamic execution; use dispatch dicts or plugins instead.",
    )


def detect_subprocess_shell(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    """subprocess.* calls with shell=True."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if name not in {"run", "call", "Popen", "check_output", "check_call"}:
            continue
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if not shell_true:
            continue
        findings.append(
            _make_finding(
                detector="subprocess_shell_true",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                title="Subprocess with shell=True",
                description=(
                    "A subprocess call uses shell=True, which passes the command through "
                    "a shell and enables shell-injection if any argument is untrusted."
                ),
                relative_path=path,
                line=node.lineno,
                evidence=_line(lines, node.lineno),
                confidence=Confidence.HIGH,
                suggested_fix="Pass the command as a list of arguments and drop shell=True.",
            )
        )
    return findings


def detect_os_system(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in {"system", "popen"}:
            continue
        findings.append(
            _make_finding(
                detector="os_system",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                title="Shell command via os.system/os.popen",
                description=(
                    "os.system()/os.popen() execute strings in a subshell. "
                    "Untrusted input here means shell command injection."
                ),
                relative_path=path,
                line=node.lineno,
                evidence=_line(lines, node.lineno),
                confidence=Confidence.HIGH,
                suggested_fix="Use the subprocess module with an argument list and shell=False.",
            )
        )
    return findings


def detect_weak_crypto(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"md5", "sha1"}:
            findings.append(
                _make_finding(
                    detector="weak_crypto",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    title="Weak hash function",
                    description=(
                        f"hashlib.{func.attr} is cryptographically broken and unsuitable "
                        "for security purposes such as password hashing or integrity checks."
                    ),
                    relative_path=path,
                    line=node.lineno,
                    evidence=_line(lines, node.lineno),
                    confidence=Confidence.HIGH,
                    suggested_fix="Use hashlib.sha256 or better; use bcrypt/argon2/scrypt for passwords.",
                )
            )
    return findings


def detect_unsafe_html_render(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    """Unescaped user-influenced HTML rendering: a classic XSS vector."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if name == "mark_safe":
            dynamic = bool(node.args) and not isinstance(node.args[0], ast.Constant)
            if not dynamic:
                continue
            findings.append(
                _make_finding(
                    detector="unsafe_html_render",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    title="Unescaped HTML via mark_safe()",
                    description=(
                        "mark_safe() marks a dynamically built string as safe HTML. "
                        "If any part is user-controlled, this is cross-site scripting (XSS)."
                    ),
                    relative_path=path,
                    line=node.lineno,
                    evidence=_line(lines, node.lineno),
                    confidence=Confidence.MEDIUM,
                    suggested_fix="Avoid mark_safe() on dynamic content; use template autoescaping instead.",
                )
            )
        elif name == "render_template_string":
            if node.args and _is_dynamic_string(node.args[0]):
                findings.append(
                    _make_finding(
                        detector="unsafe_html_render",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="Dynamic template string rendering",
                        description=(
                            "render_template_string() is called with a dynamically built "
                            "template. If any part is user-controlled, this enables "
                            "cross-site scripting (XSS) and possibly template injection."
                        ),
                        relative_path=path,
                        line=node.lineno,
                        evidence=_line(lines, node.lineno),
                        confidence=Confidence.MEDIUM,
                        suggested_fix="Render from a static template file with autoescaping instead of building templates from strings.",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Quality detectors
# ---------------------------------------------------------------------------

def detect_long_function(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    """Functions longer than the configured threshold (default 50 lines)."""
    from app.config import settings

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        end = node.end_lineno or node.lineno
        length = end - node.lineno + 1
        if length > settings.max_function_lines:
            findings.append(
                _make_finding(
                    detector="long_function",
                    category=Category.QUALITY,
                    severity=Severity.LOW,
                    title="Overly long function",
                    description=(
                        f"Function '{node.name}' spans {length} lines "
                        f"(threshold {settings.max_function_lines}). Long functions are "
                        "harder to review, test, and maintain."
                    ),
                    relative_path=path,
                    line=node.lineno,
                    evidence=_line(lines, node.lineno),
                    confidence=Confidence.HIGH,
                    suggested_fix="Split the function into smaller, single-purpose helpers.",
                )
            )
    return findings


def detect_bare_except(tree: ast.AST, lines: list[str], path: str) -> list[Finding]:
    """Bare `except:` clauses that swallow everything including KeyboardInterrupt."""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(
                _make_finding(
                    detector="bare_except",
                    category=Category.QUALITY,
                    severity=Severity.LOW,
                    title="Bare except clause",
                    description=(
                        "A bare 'except:' catches everything, including KeyboardInterrupt "
                        "and SystemExit, hiding real failures."
                    ),
                    relative_path=path,
                    line=node.lineno,
                    evidence=_line(lines, node.lineno),
                    confidence=Confidence.HIGH,
                    suggested_fix="Catch specific exception types instead of using a bare except.",
                )
            )
    return findings


DETECTORS = (
    detect_hardcoded_secrets,
    detect_sql_string_construction,
    detect_unsafe_html_render,
    detect_eval,
    detect_exec,
    detect_subprocess_shell,
    detect_os_system,
    detect_weak_crypto,
    detect_long_function,
    detect_bare_except,
)


def analyze_content(relative_path: str, content: str) -> list[Finding]:
    """Run all detectors over one Python file's content."""
    try:
        tree = ast.parse(content, filename=relative_path)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []
    lines = content.splitlines()
    findings: list[Finding] = []
    for detector in DETECTORS:
        try:
            findings.extend(detector(tree, lines, relative_path))
        except Exception as exc:  # noqa: BLE001 - one bad detector must not kill analysis
            logger.warning("Detector %s failed on %s: %s", detector.__name__, relative_path, exc)
    # Deterministic ordering for stable output.
    findings.sort(key=lambda f: (f.file, f.line, f.detector))
    return findings
