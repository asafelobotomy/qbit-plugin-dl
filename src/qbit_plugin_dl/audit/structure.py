"""Checks on the shape of a nova3 engine file and line-level heuristics."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from qbit_plugin_dl.audit.policy import (
    _DANGEROUS_BUILTINS,
    _EXTREME_LINE_LEN,
    _MULTIPROCESSING_PROCESS_ATTRS,
    _OS_DANGEROUS_ATTRS,
    _OS_MODULES,
    SEVERITY_FAIL,
    SEVERITY_WARN,
)
from qbit_plugin_dl.audit.report import AuditFinding, _attr_chain, _finding

if TYPE_CHECKING:
    pass

def _sink_for_chain(chain: list[str]) -> tuple[str, str] | None:
    """(finding code, label) when a resolved dotted name is a dangerous callable."""
    dotted = ".".join(chain)
    root = chain[0]
    if (
        root in {"builtins", "__builtins__"}
        and len(chain) >= 2
        and chain[1] in _DANGEROUS_BUILTINS
    ):
        return "DYN_EXEC", dotted
    if root in _OS_MODULES and len(chain) >= 2 and chain[1] in _OS_DANGEROUS_ATTRS:
        return "OS_EXEC", dotted
    if chain[-1] == "ProcessPoolExecutor":
        return "PROCESS_EXEC", dotted
    if (
        root == "multiprocessing"
        and len(chain) >= 2
        and chain[1] in _MULTIPROCESSING_PROCESS_ATTRS
    ):
        return "PROCESS_EXEC", dotted
    if root == "subprocess" and len(chain) >= 2:
        return "SUBPROCESS", dotted
    if root == "ctypes" and len(chain) >= 2:
        return "CTYPES", dotted
    if root in {"marshal", "pickle", "_pickle"} and chain[-1] in {"loads", "load"}:
        return "PICKLE_MARSHAL", dotted
    return None


def _try_handles_import_error(node: ast.Try) -> bool:
    for handler in node.handlers:
        if handler.type is None:
            continue
        names = _exception_type_names(handler.type)
        if names & {"ImportError", "ModuleNotFoundError"}:
            return True
        # Some older engines use bare ``except Exception`` around Py2 imports.
        if names == {"Exception"}:
            return True
    return False


def _exception_type_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Tuple):
        names: set[str] = set()
        for elt in node.elts:
            names |= _exception_type_names(elt)
        return names
    return set()


def _check_line_heuristics(text: str) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > _EXTREME_LINE_LEN:
            findings.append(
                _finding(
                    "LONG_LINE",
                    SEVERITY_WARN,
                    f"Extreme line length ({len(line)}) at line {lineno}",
                )
            )
        if any(ord(ch) < 32 and ch not in "\t\r" for ch in line):
            findings.append(
                _finding(
                    "CONTROL_CHARS",
                    SEVERITY_WARN,
                    f"Control characters at line {lineno}",
                )
            )
            break
    return findings


def _check_nova3_structure(tree: ast.AST, stem: str) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    classes: list[ast.ClassDef] = [
        node for node in tree.body if isinstance(node, ast.ClassDef)
    ]
    if not classes:
        findings.append(
            _finding(
                "NOVA3_STRUCTURE",
                SEVERITY_FAIL,
                "No class definition found (nova3 engines need a search class)",
            )
        )
        return findings

    matching = [cls for cls in classes if cls.name == stem]
    candidates = matching or classes

    search_class: ast.ClassDef | None = None
    for cls in candidates:
        for item in cls.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "search":
                search_class = cls
                break
        if search_class is not None:
            break

    if search_class is None:
        # Any class with search?
        for cls in classes:
            for item in cls.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == "search"
                ):
                    search_class = cls
                    break
            if search_class is not None:
                break

    if search_class is None:
        findings.append(
            _finding(
                "NOVA3_STRUCTURE",
                SEVERITY_FAIL,
                "No class with a search() method found",
            )
        )
        return findings

    if matching and search_class.name != stem:
        findings.append(
            _finding(
                "NOVA3_CLASS_NAME",
                SEVERITY_WARN,
                f"Search class {search_class.name!r} does not match filename stem {stem!r}",
            )
        )
    elif not matching:
        findings.append(
            _finding(
                "NOVA3_CLASS_NAME",
                SEVERITY_WARN,
                f"No class named {stem!r}; using {search_class.name!r}",
            )
        )

    search_fn: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for item in search_class.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "search":
            search_fn = item
            break

    assert search_fn is not None
    args = search_fn.args
    positional = [a.arg for a in args.args]
    if not positional or positional[0] != "self":
        findings.append(
            _finding(
                "NOVA3_STRUCTURE",
                SEVERITY_FAIL,
                "search() must be an instance method with self",
            )
        )
    elif "what" not in positional and not any(
        a.arg == "what" for a in args.kwonlyargs
    ):
        findings.append(
            _finding(
                "NOVA3_STRUCTURE",
                SEVERITY_WARN,
                "search() missing expected 'what' parameter",
            )
        )

    attr_names = _class_assigned_names(search_class)
    for required in ("url", "name", "supported_categories"):
        if required not in attr_names:
            findings.append(
                _finding(
                    "NOVA3_ATTR",
                    SEVERITY_WARN,
                    f"Missing typical attribute {required!r} on {search_class.name}",
                )
            )

    # Results are usually printed from a parser class or helper, not search()
    # itself, so only note engines that never call prettyPrinter anywhere.
    if search_fn is not None and not _calls_pretty_printer(tree):
        findings.append(
            _finding(
                "NOVA3_PRETTYPRINTER",
                SEVERITY_WARN,
                "prettyPrinter is never called (may still be valid)",
            )
        )

    return findings


def _class_assigned_names(cls: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for item in cls.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
                elif isinstance(target, ast.Attribute) and isinstance(
                    target.value, ast.Name
                ) and target.value.id == "self":
                    names.add(target.attr)
        elif isinstance(item, ast.AnnAssign):
            target = item.target
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute) and isinstance(
                target.value, ast.Name
            ) and target.value.id == "self":
                names.add(target.attr)
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__init__":
            for sub in ast.walk(item):
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"
                        ):
                            names.add(target.attr)
    return names


def _calls_pretty_printer(tree: ast.AST) -> bool:
    # ``from novaprinter import prettyPrinter as pp`` → also accept ``pp(...)``.
    names = {"prettyPrinter"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(
                alias.asname
                for alias in node.names
                if alias.name == "prettyPrinter" and alias.asname
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in names:
            return True
        chain = _attr_chain(node.func)
        if chain and chain[-1] == "prettyPrinter":
            return True
    return False
