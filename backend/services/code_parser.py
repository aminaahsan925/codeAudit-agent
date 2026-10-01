"""Code parser: structural extraction from supported languages.

Phase 1 performs deep (AST) parsing for Python only. A single file with
invalid syntax never aborts the whole analysis: the failure is captured as
a structured parse error and parsing continues with the next file.
"""

from __future__ import annotations

import ast
import logging

from models.schemas import CodeSymbol, ParsedFile

logger = logging.getLogger(__name__)


def _symbols_from_tree(tree: ast.AST) -> list[CodeSymbol]:
    symbols: list[CodeSymbol] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            symbols.append(
                CodeSymbol(
                    kind="function",
                    name=node.name,
                    line=node.lineno,
                    end_line=node.end_lineno,
                )
            )
        elif isinstance(node, ast.ClassDef):
            symbols.append(
                CodeSymbol(
                    kind="class",
                    name=node.name,
                    line=node.lineno,
                    end_line=node.end_lineno,
                )
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                symbols.append(
                    CodeSymbol(kind="import", name=alias.name, line=node.lineno)
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                symbols.append(
                    CodeSymbol(
                        kind="import", name=f"{module}.{alias.name}".lstrip("."), line=node.lineno
                    )
                )
    return symbols


def parse_python(relative_path: str, content: str) -> ParsedFile:
    """Parse one Python file. Syntax errors become structured parse errors."""
    try:
        tree = ast.parse(content, filename=relative_path)
    except SyntaxError as exc:
        logger.debug("Parse failed for %s: %s", relative_path, exc)
        return ParsedFile(
            relative_path=relative_path,
            language="python",
            parse_error=f"SyntaxError at line {exc.lineno}: {exc.msg}",
        )
    except (ValueError, MemoryError, RecursionError) as exc:
        logger.debug("Parse failed for %s: %s", relative_path, exc)
        return ParsedFile(
            relative_path=relative_path,
            language="python",
            parse_error=f"{type(exc).__name__}: {exc}",
        )
    return ParsedFile(
        relative_path=relative_path,
        language="python",
        symbols=_symbols_from_tree(tree),
    )


def parse_file(relative_path: str, language: str | None, content: str) -> ParsedFile | None:
    """Dispatch to the right parser. Returns None for unsupported languages."""
    if language == "python":
        return parse_python(relative_path, content)
    return None
