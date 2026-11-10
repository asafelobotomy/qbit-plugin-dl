"""Policy visitor checks for calls, bare names and decode-then-exec patterns."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from qbit_plugin_dl.audit.policy import (
    _DANGEROUS_BUILTINS,
    _DECODE_FUNCS,
    _MULTIPROCESSING_PROCESS_ATTRS,
    _OS_DANGEROUS_ATTRS,
    _OS_MODULES,
    _SENSITIVE_MODULES,
    SEVERITY_FAIL,
    SEVERITY_WARN,
)
from qbit_plugin_dl.audit.report import _attr_chain, _finding
from qbit_plugin_dl.audit.structure import _sink_for_chain

if TYPE_CHECKING:
    pass

class CallChecksMixin:
    """Checks on calls and the names they reach."""

    def _check_call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
            self.saw_dyn_exec = True
            self.findings.append(
                _finding(
                    "DYN_EXEC",
                    SEVERITY_FAIL,
                    f"Dangerous call {func.id}() at line {node.lineno}",
                )
            )
            self._check_decode_exec_args(node)
            return

        if self._check_dyn_attr_call(node):
            return

        if isinstance(func, ast.Name) and func.id == "ProcessPoolExecutor":
            self.findings.append(
                _finding(
                    "PROCESS_EXEC",
                    SEVERITY_FAIL,
                    f"ProcessPoolExecutor() at line {node.lineno}",
                )
            )
            return

        chain = self._resolved_chain(func)
        if not chain:
            return

        if chain[0] in {"builtins", "__builtins__"} and len(chain) >= 2 and (
            chain[1] in _DANGEROUS_BUILTINS
        ):
            self.saw_dyn_exec = True
            self.findings.append(
                _finding(
                    "DYN_EXEC",
                    SEVERITY_FAIL,
                    f"Dangerous call {'.'.join(chain)}() at line {node.lineno}",
                )
            )
            self._check_decode_exec_args(node)
            return

        if chain[:2] == ["sys", "modules"] and len(chain) >= 3:
            self._fail_sys_modules(node.lineno)
            return

        if chain[-1] == "ProcessPoolExecutor":
            self.findings.append(
                _finding(
                    "PROCESS_EXEC",
                    SEVERITY_FAIL,
                    f"{'.'.join(chain)}() at line {node.lineno}",
                )
            )
            return

        if chain[0] == "multiprocessing":
            if len(chain) >= 2 and chain[1] == "dummy":
                pass  # thread API — allowed
            elif len(chain) >= 2 and chain[1] in _MULTIPROCESSING_PROCESS_ATTRS:
                self.findings.append(
                    _finding(
                        "PROCESS_EXEC",
                        SEVERITY_FAIL,
                        f"Process-spawning call {'.'.join(chain)}() "
                        f"at line {node.lineno}",
                    )
                )
                return

        if chain[0] in _OS_MODULES and len(chain) >= 2 and chain[1] in _OS_DANGEROUS_ATTRS:
            self.findings.append(
                _finding(
                    "OS_EXEC",
                    SEVERITY_FAIL,
                    f"Dangerous call {'.'.join(chain)}() at line {node.lineno}",
                )
            )
            if self._in_function == 0:
                self.findings.append(
                    _finding(
                        "IMPORT_TIME_OS",
                        SEVERITY_FAIL,
                        f"Module-level OS call {'.'.join(chain)}() at line {node.lineno}",
                    )
                )
            return

        if chain[0] == "subprocess":
            self.findings.append(
                _finding(
                    "SUBPROCESS",
                    SEVERITY_FAIL,
                    f"subprocess call at line {node.lineno}",
                )
            )
            return

        if chain[0] in {"marshal", "pickle", "_pickle"} and chain[-1] in {
            "loads",
            "load",
        }:
            self.findings.append(
                _finding(
                    "PICKLE_MARSHAL",
                    SEVERITY_FAIL,
                    f"{'.'.join(chain)}() at line {node.lineno}",
                )
            )
            return

        if chain[0] == "ctypes":
            self.findings.append(
                _finding(
                    "CTYPES",
                    SEVERITY_FAIL,
                    f"ctypes call at line {node.lineno}",
                )
            )
            return

        if chain[0] in {"base64", "binascii", "codecs"} and chain[-1] in _DECODE_FUNCS:
            self.saw_decode_call = True
            self.findings.append(
                _finding(
                    "DECODE_CALL",
                    SEVERITY_WARN,
                    f"Decode call {'.'.join(chain)}() at line {node.lineno}",
                )
            )
            return

        if chain[0] == "socket":
            self.findings.append(
                _finding(
                    "RAW_SOCKET",
                    SEVERITY_WARN,
                    f"Raw socket use at line {node.lineno}",
                )
            )
            return

        # open(..., "w" / "wb" / "a" ...)
        if isinstance(func, ast.Name) and func.id == "open" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                if any(flag in mode.value for flag in ("w", "a", "x", "+")):
                    self.findings.append(
                        _finding(
                            "FILE_WRITE",
                            SEVERITY_WARN,
                            f"Write-mode open() at line {node.lineno}",
                        )
                    )

        # urllib / http at module level
        if (
            self._in_function == 0
            and not self._class_stack
            and chain[0] in {"urllib", "http"}
        ):
            self.findings.append(
                _finding(
                    "IMPORT_TIME_NET",
                    SEVERITY_WARN,
                    f"Import-time network call {'.'.join(chain)} at line {node.lineno}",
                )
            )

    def _check_name_load(self, node: ast.Name) -> None:
        judged = id(node) in self._judged
        if node.id in _DANGEROUS_BUILTINS:
            if not judged:
                # ``run = eval`` hides the later call from the DYN_EXEC check.
                self.saw_dyn_exec = True
                self.findings.append(
                    _finding(
                        "BUILTIN_REF",
                        SEVERITY_FAIL,
                        f"Dangerous builtin {node.id!r} referenced at line "
                        f"{node.lineno} (not called directly)",
                    )
                )
            return
        if node.id == "__builtins__":
            self.findings.append(
                _finding(
                    "BUILTINS_REF",
                    SEVERITY_FAIL,
                    f"Access to __builtins__ at line {node.lineno}",
                )
            )
            return
        origin = self._aliases.get(node.id)
        if origin is None or judged:
            return
        chain = origin.split(".")
        sink = _sink_for_chain(chain)
        if sink is not None:
            code, label = sink
            self._fail_reference(code, label, node.lineno)
        elif len(chain) == 1 and chain[0] in _SENSITIVE_MODULES:
            self.findings.append(
                _finding(
                    "MODULE_REF",
                    SEVERITY_FAIL,
                    f"Module {origin!r} used as a value at line {node.lineno} "
                    "(hides which attribute is accessed)",
                )
            )

    def _check_decode_exec_args(self, node: ast.Call) -> None:
        for arg in node.args:
            if isinstance(arg, ast.Call):
                chain = _attr_chain(arg.func)
                if chain and chain[-1] in _DECODE_FUNCS:
                    self.findings.append(
                        _finding(
                            "DECODE_EXEC",
                            SEVERITY_FAIL,
                            f"Decode-then-exec chain at line {node.lineno}",
                        )
                    )
            elif isinstance(arg, ast.Name) and arg.id in self.decode_names:
                self.findings.append(
                    _finding(
                        "DECODE_EXEC",
                        SEVERITY_FAIL,
                        f"Decode-then-exec via name {arg.id!r} at line {node.lineno}",
                    )
                )
