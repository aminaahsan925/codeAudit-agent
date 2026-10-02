"""JavaScript/TypeScript analyzer: tree-sitter parsing + deterministic detectors.

One analyzer class, instantiated per language ("javascript" for .js/.jsx,
"typescript" for .ts/.tsx); the tree-sitter grammar is selected by language.
Every detector walks the tree-sitter AST — there is no regex scanning.
When in doubt a detector stays silent: false positives are worse than
misses, the same bar as the Python analyzer.

tree-sitter is imported lazily so a Python-only install (without the
tree-sitter packages) can still import this module. If the grammar cannot
be loaded, parsing degrades to a structured parse error and analysis yields
no findings — the run is never aborted.
"""

from __future__ import annotations

import logging
import re

from models.schemas import Category, CodeSymbol, Confidence, Finding, FindingSource, Severity
from services.languages.base import LanguageAnalyzer, ParsedSource
from utils.constants import SECRET_NAME_HINTS, SECRET_PLACEHOLDER_HINTS

logger = logging.getLogger(__name__)

# Grammar packages are imported lazily (see _get_grammar).
_GRAMMAR_CACHE: dict[str, object] = {}

_SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)

# Methods that execute a shell command when called on a child_process handle
# (or as a bare identifier after destructuring require("child_process")).
_COMMAND_METHODS = frozenset({"exec", "execSync", "spawn"})

# Object names that plausibly refer to the child_process module.
_CHILD_PROCESS_NAMES = frozenset({"child_process", "cp", "childprocess"})


def _get_grammar(language: str):
    """Load (and cache) the tree-sitter grammar for a language. Lazy so the
    module imports fine without tree-sitter installed."""
    if language not in _GRAMMAR_CACHE:
        from tree_sitter import Language

        if language == "typescript":
            import tree_sitter_typescript

            _GRAMMAR_CACHE[language] = Language(tree_sitter_typescript.language_tsx())
        else:
            import tree_sitter_javascript

            _GRAMMAR_CACHE[language] = Language(tree_sitter_javascript.language())
    return _GRAMMAR_CACHE[language]


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _line(lines: list[str], node) -> str:
    row = node.start_point[0]
    if 0 <= row < len(lines):
        return lines[row].rstrip("\n")
    return ""


def _walk(node):
    """Iterative pre-order walk over every node (avoids recursion limits)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _looks_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SECRET_NAME_HINTS)


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return (
        len(value.strip()) < 4
        or any(hint in lowered for hint in SECRET_PLACEHOLDER_HINTS)
        or lowered.startswith(("process.env",))
    )


def _is_plain_string(node) -> bool:
    """A string literal, or a template literal with no substitutions — both
    are statically known and cannot carry injected data."""
    if node.type == "string":
        return True
    if node.type == "template_string":
        return not any(child.type == "template_substitution" for child in node.children)
    return False


def _callee_name(func_node, src: bytes) -> str:
    """Dotted name of a call callee: 'eval', 'child_process.exec', ..."""
    if func_node.type == "identifier":
        return _text(func_node, src)
    if func_node.type == "member_expression":
        obj = func_node.child_by_field_name("object")
        prop = func_node.child_by_field_name("property")
        if obj is None or prop is None:
            return ""
        prop_text = _text(prop, src)
        if obj.type == "member_expression":
            obj_text = _callee_name(obj, src)
        else:
            obj_text = _text(obj, src)
        return f"{obj_text}.{prop_text}" if obj_text else prop_text
    return ""


def _method_name(dotted: str) -> str:
    return dotted.split(".")[-1] if dotted else ""


def _object_text(func_node, src: bytes) -> str:
    """Text of the object a member call is made on; '' for bare calls."""
    if func_node.type == "member_expression":
        obj = func_node.child_by_field_name("object")
        return _text(obj, src) if obj is not None else ""
    return ""


def _looks_like_child_process(obj_text: str) -> bool:
    lowered = obj_text.lower()
    return "child_process" in lowered or lowered in _CHILD_PROCESS_NAMES


def _arguments_of(call_node):
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return None, []
    return args_node, args_node.named_children


def _has_shell_true(args_node, src: bytes) -> bool:
    """An options object literal containing shell: true."""
    for node in _walk(args_node):
        if node.type != "pair":
            continue
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        if key is None or value is None:
            continue
        if _text(key, src).strip("\"'") == "shell" and value.type == "true":
            return True
    return False


def _strip_quotes(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"', "`"):
        return raw[1:-1]
    return raw


def _is_dynamic_sql_arg(node, src: bytes) -> bool:
    """True if a SQL argument node can carry runtime-built content."""
    if _is_plain_string(node):
        return False
    if node.type == "template_string":
        return True  # has substitutions (static ones are plain strings)
    if node.type == "parenthesized_expression":
        inner = node.named_children
        return bool(inner) and _is_dynamic_sql_arg(inner[0], src)
    if node.type == "binary_expression":
        return any(
            _is_dynamic_sql_arg(child, src)
            if child.type == "binary_expression"
            else not _is_plain_string(child)
            for child in node.named_children
        )
    return True  # identifier, call, member access, ... -> dynamic


class JavaScriptAnalyzer(LanguageAnalyzer):
    """Deep analysis for JavaScript (.js/.jsx) and TypeScript (.ts/.tsx)."""

    def __init__(self, language: str = "javascript") -> None:
        if language not in ("javascript", "typescript"):
            raise ValueError(f"JavaScriptAnalyzer cannot handle {language!r}")
        self.language = language

    # -- LanguageAnalyzer interface ------------------------------------

    def parse_source(self, content: str, relative_path: str) -> ParsedSource:
        try:
            grammar = _get_grammar(self.language)
        except ImportError as exc:
            return ParsedSource(
                relative_path=relative_path,
                language=self.language,
                parse_error=f"javascript parser unavailable: {exc}",
            )
        try:
            from tree_sitter import Parser

            src = content.encode("utf-8")
            tree = Parser(grammar).parse(src)
        except Exception as exc:  # noqa: BLE001 - total failure is structural
            logger.debug("Parse failed for %s: %s", relative_path, exc)
            return ParsedSource(
                relative_path=relative_path,
                language=self.language,
                parse_error=f"{type(exc).__name__}: {exc}",
            )
        # tree-sitter is error-tolerant: files with syntax errors still yield
        # a partial tree, which the detectors walk conservatively.
        return ParsedSource(
            relative_path=relative_path,
            language=self.language,
            symbols=_extract_symbols(tree.root_node, src),
        )

    def analyze_file(self, relative_path: str, content: str) -> list[Finding]:
        try:
            grammar = _get_grammar(self.language)
            from tree_sitter import Parser

            src = content.encode("utf-8")
            tree = Parser(grammar).parse(src)
        except ImportError:
            return []  # degraded: parse_source reports the cause structurally
        except Exception as exc:  # noqa: BLE001 - one bad file must not kill analysis
            logger.debug("Analysis parse failed for %s: %s", relative_path, exc)
            return []
        root = tree.root_node
        lines = content.splitlines()
        findings: list[Finding] = []
        for detector in self._detectors():
            try:
                findings.extend(detector(root, lines, src, relative_path))
            except Exception as exc:  # noqa: BLE001 - one bad detector must not kill analysis
                logger.warning(
                    "Detector %s failed on %s: %s", detector.__name__, relative_path, exc
                )
        # Deterministic ordering for stable output.
        findings.sort(key=lambda f: (f.file, f.line, f.detector))
        return findings

    # -- Finding construction -------------------------------------------

    def _make_finding(
        self,
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
        suggested_fix: str,
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
            evidence=evidence,
            suggested_fix=suggested_fix,
            confidence=confidence,
            source=FindingSource.DETERMINISTIC,
            detector=detector,
            language=self.language,
        )

    def _detectors(self):
        return (
            self._detect_dangerous_eval,
            self._detect_function_constructor,
            self._detect_command_injection,
            self._detect_xss_dom_sink,
            self._detect_react_dangerous_html,
            self._detect_hardcoded_secret,
            self._detect_sql_string_construction,
            self._detect_weak_crypto,
            self._detect_implied_eval,
        )

    # -- Detectors --------------------------------------------------------

    def _detect_dangerous_eval(self, root, lines, src, path) -> list[Finding]:
        """Bare eval(...) calls execute an arbitrary string as code."""
        findings = []
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if (
                func is not None
                and func.type == "identifier"
                and _text(func, src) == "eval"
            ):
                findings.append(
                    self._make_finding(
                        detector="js_dangerous_eval",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="Dangerous eval() call",
                        description=(
                            "eval() executes its string argument as JavaScript. "
                            "If any part of the string is attacker-controlled, "
                            "this is arbitrary code execution."
                        ),
                        relative_path=path,
                        line=node.start_point[0] + 1,
                        evidence=_line(lines, node),
                        confidence=Confidence.HIGH,
                        suggested_fix=(
                            "Avoid eval(); parse data with JSON.parse or use a "
                            "safe expression evaluator instead."
                        ),
                    )
                )
        return findings

    def _detect_function_constructor(self, root, lines, src, path) -> list[Finding]:
        """new Function(...) compiles a string into a function — eval by another name."""
        findings = []
        for node in _walk(root):
            if node.type != "new_expression":
                continue
            ctor = node.child_by_field_name("constructor")
            if (
                ctor is not None
                and ctor.type == "identifier"
                and _text(ctor, src) == "Function"
            ):
                findings.append(
                    self._make_finding(
                        detector="js_function_constructor",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="Function constructor with string body",
                        description=(
                            "new Function(...) compiles its string arguments into "
                            "a function at runtime, equivalent to eval(). "
                            "Attacker-controlled input here means code execution."
                        ),
                        relative_path=path,
                        line=node.start_point[0] + 1,
                        evidence=_line(lines, node),
                        confidence=Confidence.HIGH,
                        suggested_fix=(
                            "Define the function statically instead of building "
                            "it from strings."
                        ),
                    )
                )
        return findings

    def _detect_command_injection(self, root, lines, src, path) -> list[Finding]:
        """child_process.exec/execSync/spawn with shell:true or a non-literal
        command. exec/execSync always run through a shell; spawn does when
        shell:true is passed."""
        findings = []
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            dotted = _callee_name(func, src)
            if _method_name(dotted) not in _COMMAND_METHODS:
                continue
            obj_text = _object_text(func, src)
            # Bare exec(...)/spawn(...) (destructured import) is accepted;
            # member calls must plausibly target child_process so that e.g.
            # db.exec(...) stays silent.
            if obj_text and not _looks_like_child_process(obj_text):
                continue
            args_node, args = _arguments_of(node)
            if args_node is None or not args:
                continue
            if _has_shell_true(args_node, src) or not _is_plain_string(args[0]):
                findings.append(
                    self._make_finding(
                        detector="js_command_injection",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="Potential command injection",
                        description=(
                            f"child_process.{_method_name(dotted)}() is called with "
                            "a non-literal command or shell:true, so the command "
                            "runs through a shell. If any part is "
                            "attacker-controlled, this is command injection."
                        ),
                        relative_path=path,
                        line=node.start_point[0] + 1,
                        evidence=_line(lines, node),
                        confidence=Confidence.HIGH,
                        suggested_fix=(
                            "Avoid shell:true; pass arguments as an array to "
                            "execFile/spawn, and never interpolate untrusted "
                            "input into a shell command."
                        ),
                    )
                )
        return findings

    def _detect_xss_dom_sink(self, root, lines, src, path) -> list[Finding]:
        """innerHTML/outerHTML assignment of non-literal content, and
        document.write/writeln — classic DOM XSS sinks."""
        findings = []
        for node in _walk(root):
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if (
                    left is not None
                    and left.type == "member_expression"
                    and right is not None
                ):
                    prop = left.child_by_field_name("property")
                    if (
                        prop is not None
                        and _text(prop, src) in ("innerHTML", "outerHTML")
                        and not _is_plain_string(right)
                    ):
                        findings.append(
                            self._make_finding(
                                detector="js_xss_dom_sink",
                                category=Category.SECURITY,
                                severity=Severity.HIGH,
                                title="DOM XSS sink: HTML assignment",
                                description=(
                                    f"Assigning non-literal content to "
                                    f"{_text(prop, src)} parses it as HTML. If the "
                                    "value is attacker-controlled, this is "
                                    "cross-site scripting."
                                ),
                                relative_path=path,
                                line=node.start_point[0] + 1,
                                evidence=_line(lines, node),
                                confidence=Confidence.HIGH,
                                suggested_fix=(
                                    "Use textContent or a sanitizer/DOMPurify "
                                    "instead of assigning raw HTML."
                                ),
                            )
                        )
            elif node.type == "call_expression":
                func = node.child_by_field_name("function")
                if func is None:
                    continue
                if _callee_name(func, src) in ("document.write", "document.writeln"):
                    findings.append(
                        self._make_finding(
                            detector="js_xss_dom_sink",
                            category=Category.SECURITY,
                            severity=Severity.HIGH,
                            title="DOM XSS sink: document.write",
                            description=(
                                "document.write/writeln parses its argument as "
                                "HTML in the page context. Attacker-controlled "
                                "input here is cross-site scripting."
                            ),
                            relative_path=path,
                            line=node.start_point[0] + 1,
                            evidence=_line(lines, node),
                            confidence=Confidence.HIGH,
                            suggested_fix=(
                                "Build DOM with createElement/textContent or "
                                "sanitize the content first."
                            ),
                        )
                    )
        return findings

    def _detect_react_dangerous_html(self, root, lines, src, path) -> list[Finding]:
        """dangerouslySetInnerHTML in JSX attributes or createElement props."""
        findings = []
        for node in _walk(root):
            hit = False
            if node.type == "jsx_attribute":
                for child in node.named_children:
                    if (
                        child.type == "property_identifier"
                        and _text(child, src) == "dangerouslySetInnerHTML"
                    ):
                        hit = True
                        break
            elif node.type == "pair":
                key = node.child_by_field_name("key")
                if (
                    key is not None
                    and _text(key, src).strip("\"'") == "dangerouslySetInnerHTML"
                ):
                    hit = True
            if hit:
                findings.append(
                    self._make_finding(
                        detector="js_react_dangerous_html",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title="React dangerouslySetInnerHTML",
                        description=(
                            "dangerouslySetInnerHTML bypasses React's escaping "
                            "and injects raw HTML. If the __html value is "
                            "attacker-controlled, this is cross-site scripting."
                        ),
                        relative_path=path,
                        line=node.start_point[0] + 1,
                        evidence=_line(lines, node),
                        confidence=Confidence.HIGH,
                        suggested_fix=(
                            "Render the value as normal children/text, or "
                            "sanitize it with DOMPurify before injecting."
                        ),
                    )
                )
        return findings

    def _detect_hardcoded_secret(self, root, lines, src, path) -> list[Finding]:
        """const/let/var with a secret-like name assigned a string literal."""
        findings = []
        for node in _walk(root):
            if node.type != "variable_declarator":
                continue
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if (
                name_node is None
                or value_node is None
                or name_node.type != "identifier"
                or value_node.type != "string"
            ):
                continue
            name = _text(name_node, src)
            if not _looks_secret_name(name):
                continue
            value = _strip_quotes(_text(value_node, src)).strip()
            if not value or _is_placeholder(value):
                continue
            findings.append(
                self._make_finding(
                    detector="js_hardcoded_secret",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    title="Hardcoded secret",
                    description=(
                        f"Variable '{name}' looks like a credential but is "
                        "assigned a literal string. Secrets committed to a "
                        "repository can be extracted by anyone with read access."
                    ),
                    relative_path=path,
                    line=node.start_point[0] + 1,
                    evidence=_line(lines, node),
                    confidence=Confidence.HIGH,
                    suggested_fix=(
                        "Load the secret from an environment variable or a "
                        "secrets manager, and rotate the exposed value."
                    ),
                )
            )
        return findings

    def _detect_sql_string_construction(self, root, lines, src, path) -> list[Finding]:
        """Dynamic SQL (template literal with substitutions or string
        concatenation) passed to a query()/execute() call."""
        findings = []
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            if _method_name(_callee_name(func, src)) not in ("query", "execute"):
                continue
            _, args = _arguments_of(node)
            if not args:
                continue
            arg = args[0]
            if arg.type not in ("template_string", "binary_expression"):
                continue
            if not _is_dynamic_sql_arg(arg, src):
                continue
            if not _SQL_KEYWORDS.search(_text(arg, src)):
                continue
            findings.append(
                self._make_finding(
                    detector="js_sql_string_construction",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    title="Potential SQL injection",
                    description=(
                        "A SQL string is built dynamically (template literal or "
                        "concatenation) and passed to a database query call. If "
                        "any part is user-controlled, this is SQL injection."
                    ),
                    relative_path=path,
                    line=node.start_point[0] + 1,
                    evidence=_line(lines, node),
                    confidence=Confidence.MEDIUM,
                    suggested_fix=(
                        "Use parameterized queries / prepared statements "
                        "instead of building SQL with string operations."
                    ),
                )
            )
        return findings

    def _detect_weak_crypto(self, root, lines, src, path) -> list[Finding]:
        """crypto.createHash('md5'|'sha1') — broken hashes, unsuitable for
        security purposes."""
        findings = []
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            if _callee_name(func, src) != "crypto.createHash":
                continue
            _, args = _arguments_of(node)
            if not args or args[0].type != "string":
                continue
            algo = _strip_quotes(_text(args[0], src)).lower()
            if algo not in ("md5", "sha1"):
                continue
            findings.append(
                self._make_finding(
                    detector="js_weak_crypto",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Weak hash algorithm: {algo}",
                    description=(
                        f"crypto.createHash('{algo}') uses a broken hash "
                        "function. MD5 and SHA-1 are collision-broken and "
                        "unsuitable for integrity or password hashing."
                    ),
                    relative_path=path,
                    line=node.start_point[0] + 1,
                    evidence=_line(lines, node),
                    confidence=Confidence.HIGH,
                    suggested_fix=(
                        "Use SHA-256 or stronger (crypto.createHash('sha256')); "
                        "for passwords use bcrypt/scrypt/argon2."
                    ),
                )
            )
        return findings

    def _detect_implied_eval(self, root, lines, src, path) -> list[Finding]:
        """setTimeout/setInterval with a string first argument — implied eval."""
        findings = []
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            if _method_name(_callee_name(func, src)) not in ("setTimeout", "setInterval"):
                continue
            _, args = _arguments_of(node)
            if not args or args[0].type != "string":
                continue
            findings.append(
                self._make_finding(
                    detector="js_implied_eval",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    title="String argument to setTimeout/setInterval",
                    description=(
                        "Passing a string to setTimeout/setInterval evaluates "
                        "it as code (implied eval). Attacker-controlled input "
                        "here means code execution."
                    ),
                    relative_path=path,
                    line=node.start_point[0] + 1,
                    evidence=_line(lines, node),
                    confidence=Confidence.HIGH,
                    suggested_fix=(
                        "Pass a function or arrow function instead of a string."
                    ),
                )
            )
        return findings


def _extract_symbols(root, src: bytes) -> list[CodeSymbol]:
    """Best-effort symbol extraction for AI context: functions, classes, imports."""
    symbols: list[CodeSymbol] = []
    for node in _walk(root):
        if node.type == "function_declaration":
            name = node.child_by_field_name("name")
            symbols.append(
                CodeSymbol(
                    kind="function",
                    name=_text(name, src) if name is not None else "<anonymous>",
                    line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                )
            )
        elif node.type == "class_declaration":
            name = node.child_by_field_name("name")
            symbols.append(
                CodeSymbol(
                    kind="class",
                    name=_text(name, src) if name is not None else "<anonymous>",
                    line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                )
            )
        elif node.type == "import_statement":
            symbols.append(
                CodeSymbol(
                    kind="import",
                    name=_text(node, src).strip(),
                    line=node.start_point[0] + 1,
                )
            )
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in (
                "arrow_function",
                "function_expression",
            ):
                name = node.child_by_field_name("name")
                symbols.append(
                    CodeSymbol(
                        kind="function",
                        name=_text(name, src)
                        if name is not None
                        else "<anonymous>",
                        line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                    )
                )
    return symbols
