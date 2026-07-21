"""Static safety review of downloaded nova3 engine sources.

Never import or exec plugin bodies. ClamAV is optional via ``audit_clamav``.
"""

from __future__ import annotations

import ast
import io
import math
import tokenize
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qbit_plugin_dl.audit_clamav import ClamAvSession

SEVERITY_FAIL = "fail"
SEVERITY_WARN = "warn"
SEVERITY_INFO = "info"

# Magic signatures for non-Python payloads masquerading as .py
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_NUL = b"\x00"

_ALLOWED_ROOT_MODULES: frozenset[str] = frozenset(
    {
        # Nova3 helpers
        "helpers",
        "novaprinter",
        "socks",
        # Common stdlib used by official / community engines
        "json",
        "re",
        "html",
        "urllib",
        "http",
        "gzip",
        "io",
        "datetime",
        "time",
        "typing",
        "dataclasses",
        "collections",
        "itertools",
        "functools",
        "hashlib",
        "xml",
        "ssl",
        "tempfile",
        "os",
        "sys",
        "traceback",
        "logging",
        "math",
        "enum",
        "base64",
        "binascii",
        "codecs",
        "copy",
        "string",
        "struct",
        "textwrap",
        "unicodedata",
        "random",
        "calendar",
        "email",
        "cgi",
    }
)

# Root modules that are never allowed even if somehow listed elsewhere.
_DENIED_ROOT_MODULES: frozenset[str] = frozenset(
    {
        "subprocess",
        "multiprocessing",
        "ctypes",
        "marshal",
        "pickle",
        "_pickle",
        "shelve",
        "code",
        "codeop",
        "importlib",
        "zipimport",
        "runpy",
        "pty",
        "smtplib",
        "ftplib",
        "xmlrpc",
        "socket",
        "asyncio",
        "concurrent",
        "threading",
        "signal",
        "fcntl",
        "resource",
        "pwd",
        "grp",
        "spwd",
        "crypt",
        "cffi",
        "requests",
        "httpx",
        "aiohttp",
        "paramiko",
        "fabric",
        "invoke",
    }
)

_DENIED_HTTP_SUBMODULES: frozenset[str] = frozenset({"http.server"})

_DANGEROUS_BUILTINS: frozenset[str] = frozenset(
    {"exec", "eval", "compile", "__import__"}
)

_OS_DANGEROUS_ATTRS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "fork",
        "forkpty",
        "kill",
        "killpg",
    }
)

_DECODE_FUNCS: frozenset[str] = frozenset(
    {
        "b64decode",
        "b32decode",
        "b16decode",
        "b85decode",
        "a85decode",
        "unhexlify",
        "decode",
        "decodebytes",
    }
)

_HIGH_ENTROPY_MIN_LEN = 80
_HIGH_ENTROPY_THRESHOLD = 4.5
_EXTREME_LINE_LEN = 500


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


def _import_allowed(fullname: str) -> bool:
    if fullname in _DENIED_HTTP_SUBMODULES:
        return False
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


class _PolicyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[AuditFinding] = []
        self.decode_names: set[str] = set()
        self.saw_decode_call = False
        self.saw_dyn_exec = False
        self._in_function = 0
        self._class_stack: list[str] = []

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

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_import(alias.name, node.lineno)

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
        elif node.level == 0:
            self.findings.append(
                _finding(
                    "IMPORT_DENY",
                    SEVERITY_FAIL,
                    f"Empty import module at line {node.lineno}",
                )
            )

    def _check_import(self, name: str, lineno: int) -> None:
        root = _root_module(name)
        if root in _DENIED_ROOT_MODULES or name in _DENIED_HTTP_SUBMODULES:
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

    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        self.generic_visit(node)

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

        chain = _attr_chain(func)
        if not chain:
            return

        if chain[0] == "os" and len(chain) >= 2 and chain[1] in _OS_DANGEROUS_ATTRS:
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

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            chain = _attr_chain(node.value.func)
            if chain and (
                (chain[0] in {"base64", "binascii", "codecs"} and chain[-1] in _DECODE_FUNCS)
                or (isinstance(node.value.func, ast.Name) and node.value.func.id in _DECODE_FUNCS)
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
            if _shannon_entropy(value) >= _HIGH_ENTROPY_THRESHOLD:
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
        if isinstance(node.ctx, ast.Load) and node.id in _DANGEROUS_BUILTINS:
            # Reference without call still suspicious when assigned/passed
            pass
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

    if search_fn is not None and not _calls_pretty_printer(search_fn):
        findings.append(
            _finding(
                "NOVA3_PRETTYPRINTER",
                SEVERITY_WARN,
                "search() does not call prettyPrinter (may still be valid)",
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


def _calls_pretty_printer(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "prettyPrinter":
            return True
        chain = _attr_chain(node.func)
        if chain and chain[-1] == "prettyPrinter":
            return True
    return False


def audit_plugin_static(content: bytes, *, filename: str) -> AuditReport:
    """Run format/AST/import/structure/heuristic checks (no ClamAV)."""
    findings: list[AuditFinding] = []
    findings.extend(_check_format(content))
    if any(f.severity == SEVERITY_FAIL for f in findings):
        return AuditReport(findings=tuple(findings))

    text, enc_findings = _decode_source(content)
    findings.extend(enc_findings)
    if text is None:
        return AuditReport(findings=tuple(findings))

    findings.extend(_check_line_heuristics(text))

    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        findings.append(
            _finding(
                "SYNTAX",
                SEVERITY_FAIL,
                f"SyntaxError: {exc.msg} at line {exc.lineno}",
            )
        )
        return AuditReport(findings=tuple(findings))

    visitor = _PolicyVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)

    if visitor.saw_decode_call and visitor.saw_dyn_exec:
        if not any(f.code == "DECODE_EXEC" for f in findings):
            findings.append(
                _finding(
                    "DECODE_EXEC",
                    SEVERITY_FAIL,
                    "Module contains both decode and dynamic exec/eval",
                )
            )

    stem = Path(filename).stem
    findings.extend(_check_nova3_structure(tree, stem))

    return AuditReport(findings=tuple(findings))


def audit_plugin_bytes(
    content: bytes,
    *,
    filename: str,
    clamav_session: ClamAvSession | None = None,
) -> AuditReport:
    """Full safety check: static review, then optional ClamAV when session provided."""
    report = audit_plugin_static(content, filename=filename)
    if report.blocked:
        return report

    if clamav_session is None:
        return report

    clam_findings, status, backend = clamav_session.scan_bytes(
        content, filename=filename
    )
    return AuditReport(
        findings=tuple([*report.findings, *clam_findings]),
        clamav_status=status,
        clamav_backend=backend,
    )
