"""Lightweight intra-file source-to-sink tracing (Phase 3, §7.3).

Conservative and explicit about uncertainty. This is NOT full data-flow
analysis: it answers one narrow question per sink argument — can we name a
concrete untrusted origin for this value within the same file?

Recognized untrusted origins (documented, deliberately narrow):
  * Python: function parameters, and attribute/subscript chains rooted at
    ``request`` (Flask/Django request data: ``request.args``, ``request.form`` …).
  * JavaScript/TypeScript: function parameters, member chains rooted at
    ``req`` (Express-style ``req.query``/``req.body``/``req.params``), and
    ``process.argv``.

Semantics of the result:
  * TAINTED — a concrete origin was identified. The finding gets a
    ``taint_trace`` note naming the origin, and its confidence is raised to
    HIGH (a concrete untrusted flow is the strongest signal a local
    detector can produce).
  * UNKNOWN — the argument has no literal value and no recognized origin
    (e.g. a module-level variable, a helper call result). The finding gets
    a ``taint_trace`` note stating the uncertainty explicitly; confidence
    is unchanged.
  * CLEAN — the argument is a literal constant. No note is attached; the
    detector's own confidence stands.

Only the sink detectors named in the registry's taint pairs call into
this module, and only for findings they already produced: taint analysis
never creates a finding, never suppresses one, and never changes severity.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from enum import Enum

from models.schemas import Confidence, Finding

logger = logging.getLogger(__name__)


class TaintStatus(str, Enum):
    TAINTED = "tainted"  # concrete untrusted origin identified
    UNKNOWN = "unknown"  # origin could not be determined
    CLEAN = "clean"  # literal constant value


@dataclass(frozen=True)
class TaintResult:
    status: TaintStatus
    note: str | None  # human-readable trace; None when CLEAN


# Attribute/subscript chains rooted at these names count as untrusted input.
PYTHON_SOURCE_ROOTS = frozenset({"request"})
JS_SOURCE_ROOTS = frozenset({"req"})


def apply_taint(finding: Finding, result: TaintResult) -> Finding:
    """Attach a taint trace to a finding; raise confidence only on TAINTED.

    Returns the finding unchanged when the result is CLEAN (no note).
    Severity, id, evidence and all other fields are never touched here.
    """
    if result.status is TaintStatus.CLEAN or not result.note:
        return finding
    updates: dict = {"taint_trace": result.note}
    if result.status is TaintStatus.TAINTED and finding.confidence is not Confidence.HIGH:
        updates["confidence"] = Confidence.HIGH
    return finding.model_copy(update=updates)


# ---------------------------------------------------------------------------
# Python (ast)
# ---------------------------------------------------------------------------

def _enclosing_python_function(tree: ast.AST, node: ast.AST) -> ast.AST | None:
    """Innermost FunctionDef/AsyncFunctionDef containing ``node`` by source span."""
    n_start = (node.lineno, node.col_offset)
    n_end = (node.end_lineno or node.lineno, node.end_col_offset or 0)
    best: ast.AST | None = None
    best_span: tuple[int, int] | None = None
    for cand in ast.walk(tree):
        if not isinstance(cand, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        c_start = (cand.lineno, cand.col_offset)
        c_end = (cand.end_lineno or cand.lineno, cand.end_col_offset or 0)
        if c_start <= n_start and n_end <= c_end:
            span = (c_end[0] - c_start[0], c_end[1] - c_start[1])
            if best_span is None or span < best_span:
                best, best_span = cand, span
    return best


def _python_param_names(func: ast.AST | None) -> set[str]:
    if func is None:
        return set()
    args = func.args  # type: ignore[attr-defined]
    names = {a.arg for a in (*args.args, *args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _python_root_name(node: ast.AST) -> str | None:
    """Root identifier of an attribute/subscript/call chain.

    ``request.args.get('q')`` -> ``'request'``. Returns None when the chain
    does not bottom out at a plain name.
    """
    seen = 0
    while seen < 50:  # bound against pathological nesting
        seen += 1
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            return None
    return None


def _python_value_leaves(node: ast.AST):
    """Yield the non-constant leaves of a string-building expression.

    Descends through ``+``/``%`` concatenation, f-strings, ``"{}".format()``
    calls, and list/tuple literals. Anything else (a bare name, a call
    result, an attribute) is itself a leaf.
    """
    if isinstance(node, ast.Constant):
        return
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        yield from _python_value_leaves(node.left)
        yield from _python_value_leaves(node.right)
        return
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                yield from _python_value_leaves(v.value)
        return
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        for a in node.args:
            yield from _python_value_leaves(a)
        for kw in node.keywords:
            yield from _python_value_leaves(kw.value)
        return
    if isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            yield from _python_value_leaves(elt)
        return
    yield node


def _python_classify_leaf(leaf: ast.AST, params: set[str], func_name: str | None) -> TaintResult:
    if isinstance(leaf, ast.Name):
        if leaf.id in params:
            return TaintResult(
                TaintStatus.TAINTED,
                f"taint: '{leaf.id}' is a parameter of function "
                f"'{func_name}' — untrusted input may reach this sink",
            )
        return TaintResult(
            TaintStatus.UNKNOWN,
            f"taint: uncertain — '{leaf.id}' has no literal value or recognized "
            "source in this scope; attacker control could not be ruled out",
        )
    root = _python_root_name(leaf)
    if root in PYTHON_SOURCE_ROOTS:
        return TaintResult(
            TaintStatus.TAINTED,
            "taint: value derives from 'request.… ' (web request data) — "
            "untrusted input may reach this sink",
        )
    if root is not None and root in params:
        return TaintResult(
            TaintStatus.TAINTED,
            f"taint: value derives from parameter '{root}' of function "
            f"'{func_name}' — untrusted input may reach this sink",
        )
    return TaintResult(
        TaintStatus.UNKNOWN,
        "taint: uncertain — the value has no literal form or recognized "
        "source in this scope; attacker control could not be ruled out",
    )


def trace_python_sink(tree: ast.AST, sink_node: ast.AST, arg: ast.AST) -> TaintResult:
    """Classify the taint of a Python sink call's argument.

    Runs only for findings a detector already produced; never creates or
    suppresses findings on its own. Fail-safe: any internal error yields
    UNKNOWN with no note, so the finding survives with its original
    confidence rather than being lost to a tracing bug.
    """
    try:
        return _trace_python_sink(tree, sink_node, arg)
    except Exception as exc:  # noqa: BLE001 - taint must never kill a finding
        logger.warning("Python taint trace failed: %s", exc)
        return TaintResult(TaintStatus.UNKNOWN, None)


def _trace_python_sink(tree: ast.AST, sink_node: ast.AST, arg: ast.AST) -> TaintResult:
    if isinstance(arg, ast.Constant):
        return TaintResult(TaintStatus.CLEAN, None)
    func = _enclosing_python_function(tree, sink_node)
    params = _python_param_names(func)
    func_name = func.name if func is not None else None  # type: ignore[attr-defined]
    leaves = list(_python_value_leaves(arg))
    if not leaves:
        return TaintResult(TaintStatus.CLEAN, None)
    results = [_python_classify_leaf(leaf, params, func_name) for leaf in leaves]
    for r in results:
        if r.status is TaintStatus.TAINTED:
            return r
    return results[0]


# ---------------------------------------------------------------------------
# JavaScript/TypeScript (tree-sitter)
# ---------------------------------------------------------------------------

_JS_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    }
)


def _js_enclosing_function(root, node):
    """Innermost function node containing ``node``, by byte offsets."""
    n_start, n_end = node.start_byte, node.end_byte
    best = None
    best_span = None

    def visit(n):
        nonlocal best, best_span
        if n.type in _JS_FUNCTION_TYPES and n.start_byte <= n_start and n_end <= n.end_byte:
            # Exclude the sink node itself being the function (cannot happen:
            # sink nodes are call/assignment expressions, not functions).
            span = n.end_byte - n.start_byte
            if best_span is None or span < best_span:
                best, best_span = n, span
        for child in n.children:
            visit(child)

    visit(root)
    return best


def _js_text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _js_param_names(func_node, src: bytes) -> set[str]:
    names: set[str] = set()
    params = func_node.child_by_field_name("parameters")
    if params is None:
        return names

    def collect(n):
        if n.type == "identifier":
            names.add(_js_text(n, src))
        elif n.type == "assignment_pattern":
            # default parameter: function f(a = 1)
            left = n.child_by_field_name("left")
            if left is not None:
                collect(left)
        elif n.type == "rest_pattern":
            for child in n.named_children:
                collect(child)
        else:
            for child in n.named_children:
                collect(child)

    collect(params)
    return names


def _js_chain_root(node, src: bytes) -> str | None:
    """Root identifier of a member/subscript chain: req.query.q -> 'req'."""
    seen = 0
    while seen < 50:
        seen += 1
        if node.type == "identifier":
            return _js_text(node, src)
        if node.type in ("member_expression", "subscript_expression"):
            obj = node.child_by_field_name("object")
            if obj is None:
                return None
            node = obj
        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func is None:
                return None
            node = func
        else:
            return None
    return None


def _js_chain_text(node, src: bytes) -> str:
    """Dotted text of a member chain, e.g. 'process.argv'. Best effort."""
    parts: list[str] = []
    seen = 0
    while seen < 50:
        seen += 1
        if node.type == "identifier":
            parts.append(_js_text(node, src))
            break
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None:
                parts.append(_js_text(prop, src))
            obj = node.child_by_field_name("object")
            if obj is None:
                break
            node = obj
        elif node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            if obj is None:
                break
            node = obj
        else:
            break
    parts.reverse()
    return ".".join(parts)


def _js_value_leaves(node, src: bytes):
    """Yield non-literal leaves of a JS string-building expression."""
    t = node.type
    if t == "string":
        return
    if t == "template_string":
        for child in node.children:
            if child.type in ("substitution", "template_substitution"):
                for expr in child.named_children:
                    yield from _js_value_leaves(expr, src)
        return
    if t == "binary_expression":
        for child in node.named_children:
            yield from _js_value_leaves(child, src)
        return
    if t == "call_expression":
        # "...".concat(x) — treat like format(): descend into arguments.
        func = node.child_by_field_name("function")
        if func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            if prop is not None and _js_text(prop, src) == "concat":
                args = node.child_by_field_name("arguments")
                if args is not None:
                    for child in args.named_children:
                        yield from _js_value_leaves(child, src)
                    return
        yield node
        return
    yield node


def _js_classify_leaf(leaf, params: set[str], func_name: str | None, src: bytes) -> TaintResult:
    if leaf.type == "identifier":
        name = _js_text(leaf, src)
        if name in params:
            return TaintResult(
                TaintStatus.TAINTED,
                f"taint: '{name}' is a parameter of function "
                f"'{func_name}' — untrusted input may reach this sink",
            )
        return TaintResult(
            TaintStatus.UNKNOWN,
            f"taint: uncertain — '{name}' has no literal value or recognized "
            "source in this scope; attacker control could not be ruled out",
        )
    root = _js_chain_root(leaf, src)
    if root in JS_SOURCE_ROOTS:
        return TaintResult(
            TaintStatus.TAINTED,
            "taint: value derives from 'req.… ' (HTTP request data: "
            "req.query/req.body/req.params) — untrusted input may reach this sink",
        )
    if root == "process" and "argv" in _js_chain_text(leaf, src).split("."):
        return TaintResult(
            TaintStatus.TAINTED,
            "taint: value derives from 'process.argv' (command-line input) — "
            "untrusted input may reach this sink",
        )
    if root is not None and root in params:
        return TaintResult(
            TaintStatus.TAINTED,
            f"taint: value derives from parameter '{root}' of function "
            f"'{func_name}' — untrusted input may reach this sink",
        )
    return TaintResult(
        TaintStatus.UNKNOWN,
        "taint: uncertain — the value has no literal form or recognized "
        "source in this scope; attacker control could not be ruled out",
    )


def _js_function_name(func_node, src: bytes) -> str | None:
    name = func_node.child_by_field_name("name")
    return _js_text(name, src) if name is not None else None


def trace_js_sink(root, sink_node, arg_node, src: bytes) -> TaintResult:
    """Classify the taint of a JS/TS sink call's argument.

    Runs only for findings a detector already produced; never creates or
    suppresses findings on its own. Fail-safe: any internal error yields
    UNKNOWN with no note, so the finding survives with its original
    confidence rather than being lost to a tracing bug.
    """
    try:
        return _trace_js_sink(root, sink_node, arg_node, src)
    except Exception as exc:  # noqa: BLE001 - taint must never kill a finding
        logger.warning("JS taint trace failed: %s", exc)
        return TaintResult(TaintStatus.UNKNOWN, None)


def _trace_js_sink(root, sink_node, arg_node, src: bytes) -> TaintResult:
    if arg_node.type == "string":
        return TaintResult(TaintStatus.CLEAN, None)
    func = _js_enclosing_function(root, sink_node)
    params = _js_param_names(func, src) if func is not None else set()
    func_name = _js_function_name(func, src) if func is not None else None
    leaves = list(_js_value_leaves(arg_node, src))
    if not leaves:
        return TaintResult(TaintStatus.CLEAN, None)
    results = [_js_classify_leaf(leaf, params, func_name, src) for leaf in leaves]
    for r in results:
        if r.status is TaintStatus.TAINTED:
            return r
    return results[0]


__all__ = [
    "TaintStatus",
    "TaintResult",
    "PYTHON_SOURCE_ROOTS",
    "JS_SOURCE_ROOTS",
    "apply_taint",
    "trace_python_sink",
    "trace_js_sink",
]
