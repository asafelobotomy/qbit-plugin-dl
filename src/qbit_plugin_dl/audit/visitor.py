"""The AST visitor that applies the import, assignment and name policy to a plugin."""

from __future__ import annotations

import ast
import unicodedata
from typing import TYPE_CHECKING

from qbit_plugin_dl.audit.policy import (
    _BLOB_RUN,
    _DECODE_FUNCS,
    _DENIED_CONCURRENT_SUBMODULES,
    _DENIED_HTTP_SUBMODULES,
    _DENIED_ROOT_MODULES,
    _HIGH_ENTROPY_MIN_LEN,
    _HIGH_ENTROPY_THRESHOLD,
    _MULTIPROCESSING_PROCESS_ATTRS,
    _PROCESS_SPAWN_IMPORT_NAMES,
    _PY2_COMPAT_MODULES,
    SEVERITY_FAIL,
    SEVERITY_WARN,
)
from qbit_plugin_dl.audit.report import (
    AuditFinding,
    _attr_chain,
    _finding,
    _import_allowed,
    _is_multiprocessing_dummy,
    _root_module,
    _shannon_entropy,
)
from qbit_plugin_dl.audit.structure import _try_handles_import_error
from qbit_plugin_dl.audit.visitor_calls import CallChecksMixin
from qbit_plugin_dl.audit.visitor_refs import RefChecksMixin

if TYPE_CHECKING:
    pass

class _PolicyVisitor(RefChecksMixin, CallChecksMixin, ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[AuditFinding] = []
        # Local name -> dotted origin from ``import x as y`` / ``from x import y``,
        # so aliases (``import os as o``, ``from os import system``) resolve.
        self._aliases: dict[str, str] = {}
        # ids of nodes already judged in context (call targets, attribute bases,
        # vetted getattr receivers, membership tests) — not plain value refs.
        self._judged: set[int] = set()
        self.decode_names: set[str] = set()
        self.saw_decode_call = False
        self.saw_dyn_exec = False
        self._in_function = 0
        self._class_stack: list[str] = []
        self._py2_compat_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._in_function += 1
        self.generic_visit(node)
        self._in_function -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._in_function += 1
        self.generic_visit(node)
        self._in_function -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_Try(self, node: ast.Try) -> None:
        """Downgrade known Py2 imports inside ImportError compatibility shims.

        Engines use both orientations:

        - ``try: HTMLParser`` / ``except: html.parser``
        - ``try: html.parser`` / ``except: HTMLParser``

        so body *and* handlers must share the shim window.
        """
        if _try_handles_import_error(node):
            self._py2_compat_depth += 1
            for child in node.body:
                self.visit(child)
            for handler in node.handlers:
                self.visit(handler)
            self._py2_compat_depth -= 1
            for child in node.orelse:
                self.visit(child)
            for child in node.finalbody:
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_import(alias.name, node.lineno)
            if alias.asname:
                self._aliases[alias.asname] = alias.name
            else:
                root = _root_module(alias.name)
                self._aliases[root] = root

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level and not node.module:
            self.findings.append(
                _finding(
                    "IMPORT_RELATIVE",
                    SEVERITY_WARN,
                    f"Relative import at line {node.lineno}",
                )
            )
            return
        module = node.module or ""
        if node.level:
            # Relative import of helpers/novaprinter is unusual; warn.
            self.findings.append(
                _finding(
                    "IMPORT_RELATIVE",
                    SEVERITY_WARN,
                    f"Relative import of {module!r} at line {node.lineno}",
                )
            )
        if module:
            self._check_import(module, node.lineno)
            self._check_import_from_names(module, node.names, node.lineno)
            if not node.level:
                for alias in node.names:
                    if alias.name != "*":
                        self._aliases[alias.asname or alias.name] = (
                            f"{module}.{alias.name}"
                        )
        elif node.level == 0:
            self.findings.append(
                _finding(
                    "IMPORT_DENY",
                    SEVERITY_FAIL,
                    f"Empty import module at line {node.lineno}",
                )
            )

    def _check_import_from_names(
        self,
        module: str,
        names: list[ast.alias],
        lineno: int,
    ) -> None:
        """Catch process-spawn symbols even when the parent package is allowed."""
        if _is_multiprocessing_dummy(module):
            return
        for alias in names:
            if alias.name == "*":
                continue
            if alias.name in _PROCESS_SPAWN_IMPORT_NAMES:
                self.findings.append(
                    _finding(
                        "PROCESS_EXEC",
                        SEVERITY_FAIL,
                        f"Process-spawning import {alias.name!r} from "
                        f"{module!r} at line {lineno}",
                    )
                )
            elif (
                module.startswith("multiprocessing")
                and alias.name in _MULTIPROCESSING_PROCESS_ATTRS
            ):
                self.findings.append(
                    _finding(
                        "PROCESS_EXEC",
                        SEVERITY_FAIL,
                        f"Process-spawning import {alias.name!r} from "
                        f"{module!r} at line {lineno}",
                    )
                )

    def _check_import(self, name: str, lineno: int) -> None:
        root = _root_module(name)
        if (
            self._py2_compat_depth > 0
            and root in _PY2_COMPAT_MODULES
        ):
            self.findings.append(
                _finding(
                    "IMPORT_PY2_SHIM",
                    SEVERITY_WARN,
                    f"Python 2 compatibility import {name!r} at line {lineno}",
                )
            )
            return
        if _is_multiprocessing_dummy(name):
            return
        if (
            name in _DENIED_HTTP_SUBMODULES
            or name in _DENIED_CONCURRENT_SUBMODULES
            or name.startswith("concurrent.futures.process.")
        ):
            self.findings.append(
                _finding(
                    "IMPORT_DENY",
                    SEVERITY_FAIL,
                    f"Denied import {name!r} at line {lineno}",
                )
            )
            return
        if root in _DENIED_ROOT_MODULES:
            self.findings.append(
                _finding(
                    "IMPORT_DENY",
                    SEVERITY_FAIL,
                    f"Denied import {name!r} at line {lineno}",
                )
            )
            return
        if not _import_allowed(name):
            self.findings.append(
                _finding(
                    "IMPORT_DENY",
                    SEVERITY_FAIL,
                    f"Non-allowlisted import {name!r} at line {lineno}",
                )
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            chain = _attr_chain(node.value.func)
            if chain and (
                (chain[0] in {"base64", "binascii", "codecs"} and chain[-1] in _DECODE_FUNCS)
                or (
                    isinstance(node.value.func, ast.Name)
                    and node.value.func.id in _DECODE_FUNCS
                )
            ):
                self.saw_decode_call = True
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.decode_names.add(target.id)
        self._check_sys_mutation(node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_sys_mutation_target(node.target, node.lineno)
        self.generic_visit(node)

    def _check_sys_mutation(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_sys_mutation_target(target, node.lineno)

    def _check_sys_mutation_target(self, target: ast.AST, lineno: int) -> None:
        chain = _attr_chain(target)
        if chain and chain[0] == "sys" and len(chain) >= 2 and chain[1] in {
            "path",
            "modules",
        }:
            self.findings.append(
                _finding(
                    "SYS_MUTATION",
                    SEVERITY_WARN,
                    f"sys.{chain[1]} mutation at line {lineno}",
                )
            )
        if isinstance(target, ast.Subscript):
            chain = _attr_chain(target.value)
            if chain and chain[0] == "sys" and len(chain) >= 2 and chain[1] in {
                "path",
                "modules",
            }:
                self.findings.append(
                    _finding(
                        "SYS_MUTATION",
                        SEVERITY_WARN,
                        f"sys.{chain[1]} mutation at line {lineno}",
                    )
                )

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, str) and len(value) >= _HIGH_ENTROPY_MIN_LEN:
            if (
                _shannon_entropy(value) >= _HIGH_ENTROPY_THRESHOLD
                and _BLOB_RUN.search(value) is not None
            ):
                self.findings.append(
                    _finding(
                        "HIGH_ENTROPY",
                        SEVERITY_WARN,
                        f"High-entropy string literal at line {node.lineno}",
                    )
                )
        elif isinstance(value, (bytes, bytearray)) and len(value) >= _HIGH_ENTROPY_MIN_LEN:
            if _shannon_entropy(bytes(value)) >= _HIGH_ENTROPY_THRESHOLD:
                self.findings.append(
                    _finding(
                        "HIGH_ENTROPY",
                        SEVERITY_WARN,
                        f"High-entropy bytes literal at line {node.lineno}",
                    )
                )

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self._check_name_load(node)
        if isinstance(node.ctx, ast.Store):
            normalized = unicodedata.normalize("NFKC", node.id)
            if normalized != node.id or any(ord(ch) > 127 for ch in node.id):
                self.findings.append(
                    _finding(
                        "NON_ASCII_IDENT",
                        SEVERITY_WARN,
                        f"Non-ASCII or confusable identifier {node.id!r} "
                        f"at line {getattr(node, 'lineno', 0)}",
                    )
                )
        self.generic_visit(node)
