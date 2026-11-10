"""Audit findings and reports, plus the small source-level helpers the checks share."""

from __future__ import annotations

import ast
import io
import math
import tokenize
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

from qbit_plugin_dl.audit.policy import (
    _ALLOWED_ROOT_MODULES,
    _DENIED_CONCURRENT_SUBMODULES,
    _DENIED_HTTP_SUBMODULES,
    _DENIED_ROOT_MODULES,
    _ELF_MAGIC,
    _NUL,
    _PE_MAGIC,
    SEVERITY_FAIL,
    SEVERITY_WARN,
)

if TYPE_CHECKING:
    pass

@dataclass(frozen=True, slots=True)
class AuditFinding:
    code: str
    severity: str
    message: str


@dataclass(frozen=True, slots=True)
class AuditReport:
    findings: tuple[AuditFinding, ...]
    clamav_status: str = "skipped"
    clamav_backend: str = "none"

    @property
    def blocked(self) -> bool:
        return any(f.severity == SEVERITY_FAIL for f in self.findings)

    @property
    def fail_findings(self) -> tuple[AuditFinding, ...]:
        return tuple(f for f in self.findings if f.severity == SEVERITY_FAIL)

    @property
    def warn_findings(self) -> tuple[AuditFinding, ...]:
        return tuple(f for f in self.findings if f.severity == SEVERITY_WARN)

    def summary_error(self) -> str:
        fails = self.fail_findings
        if not fails:
            return "Safety check failed"
        parts = [f"{f.code}: {f.message}" for f in fails[:5]]
        extra = len(fails) - len(parts)
        text = "; ".join(parts)
        if extra > 0:
            text = f"{text}; …(+{extra} more)"
        return f"Safety check blocked install — {text}"


def _finding(code: str, severity: str, message: str) -> AuditFinding:
    return AuditFinding(code=code, severity=severity, message=message)


def _shannon_entropy(data: str | bytes) -> float:
    if not data:
        return 0.0
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="replace")
    else:
        raw = data
    counts: dict[int, int] = {}
    for byte in raw:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(raw)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _root_module(name: str) -> str:
    return name.split(".", 1)[0]


def _is_multiprocessing_dummy(fullname: str) -> bool:
    """``multiprocessing.dummy`` is a thread pool API (used by official Jackett)."""
    return fullname == "multiprocessing.dummy" or fullname.startswith(
        "multiprocessing.dummy."
    )


def _import_allowed(fullname: str) -> bool:
    if fullname in _DENIED_HTTP_SUBMODULES:
        return False
    if fullname in _DENIED_CONCURRENT_SUBMODULES or fullname.startswith(
        "concurrent.futures.process."
    ):
        return False
    if _is_multiprocessing_dummy(fullname):
        return True
    root = _root_module(fullname)
    if root in _DENIED_ROOT_MODULES:
        return False
    if fullname.startswith("http.server"):
        return False
    return root in _ALLOWED_ROOT_MODULES


def _check_format(content: bytes) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    if _NUL in content:
        findings.append(
            _finding("FORMAT_NUL", SEVERITY_FAIL, "NUL bytes in plugin source")
        )
    if content.startswith(_ELF_MAGIC):
        findings.append(
            _finding("FORMAT_ELF", SEVERITY_FAIL, "ELF binary masquerading as .py")
        )
    if content.startswith(_PE_MAGIC):
        findings.append(
            _finding("FORMAT_PE", SEVERITY_FAIL, "PE binary masquerading as .py")
        )
    try:
        if zipfile.is_zipfile(io.BytesIO(content)):
            findings.append(
                _finding(
                    "FORMAT_ZIP",
                    SEVERITY_FAIL,
                    "ZIP archive masquerading as .py",
                )
            )
    except OSError:
        pass
    return findings


def _decode_source(content: bytes) -> tuple[str | None, list[AuditFinding]]:
    findings: list[AuditFinding] = []
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
    except SyntaxError as exc:
        return None, [
            _finding(
                "ENCODING",
                SEVERITY_FAIL,
                f"Cannot detect encoding: {exc}",
            )
        ]
    try:
        text = content.decode(encoding)
    except UnicodeDecodeError as exc:
        return None, [
            _finding("ENCODING", SEVERITY_FAIL, f"Cannot decode source: {exc}")
        ]
    if text.startswith("#!"):
        findings.append(
            _finding("SHEBANG", SEVERITY_WARN, "Unexpected shebang in plugin source")
        )
    return text, findings


def _attr_chain(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        parts.reverse()
        return parts
    return None


def _fold_str(node: ast.AST | None) -> str | None:
    """Statically evaluate simple constant string expressions (``'sy' + 'stem'``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold_str(node.left), _fold_str(node.right)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return None
                folded = _fold_str(value.value)
            else:
                folded = _fold_str(value)
            if folded is None:
                return None
            parts.append(folded)
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        sep = _fold_str(node.func.value)
        items = [_fold_str(elt) for elt in node.args[0].elts]
        if sep is not None and all(item is not None for item in items):
            return sep.join(items)  # type: ignore[arg-type]
    return None
