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
        "__future__",
        "pathlib",
        "zlib",
        "queue",
        "warnings",
        "contextlib",
        "operator",
        "abc",
        "types",
        "configparser",
        # In-process threads (Jackett + many community engines)
        "threading",
        "concurrent",
    }
)

# Root modules that are never allowed even if somehow listed elsewhere.
# ``multiprocessing`` is denied except ``multiprocessing.dummy*`` (thread API).
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

# OS process spawning via concurrent.futures (threads are allowlisted above).
_DENIED_CONCURRENT_SUBMODULES: frozenset[str] = frozenset(
    {"concurrent.futures.process"}
)

_PROCESS_SPAWN_IMPORT_NAMES: frozenset[str] = frozenset(
    {"ProcessPoolExecutor", "Process"}
)

_MULTIPROCESSING_PROCESS_ATTRS: frozenset[str] = frozenset(
    {"Process", "Pool", "get_context", "Manager", "managers"}
)

# Imports that appear in try/except ImportError shims for Python 2/3 engines.
# Seeing them in AST alone is not malware — qBittorrent runs Python 3.
_PY2_COMPAT_MODULES: frozenset[str] = frozenset(
    {
        "HTMLParser",
        "urllib2",
        "urlparse",
        "cookielib",
        "Cookie",
        "Queue",
        "ConfigParser",
        "cStringIO",
        "StringIO",
        "httplib",
        "htmlentitydefs",
        "commands",
        "UserDict",
        "UserList",
        "UserString",
    }
)

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

_OS_MODULES: frozenset[str] = frozenset({"os", "posix", "nt"})

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

# Attr names that must not be resolved dynamically (getattr / __dict__ / …).
_DANGEROUS_ATTR_NAMES: frozenset[str] = frozenset(
    {
        *_OS_DANGEROUS_ATTRS,
        *_DANGEROUS_BUILTINS,
        "Process",
        "Pool",
        "ProcessPoolExecutor",
        "system",
        "popen",
        "Popen",
        "call",
        "run",
        "check_output",
        "check_call",
        "getoutput",
        "getstatusoutput",
        "loads",
        "load",
        "dumps",
        "dump",
    }
)

# Modules whose objects must not be passed around as plain values (``m = os``,
# ``getattr(os, name)``): doing so hides which attribute is used later.
_SENSITIVE_MODULES: frozenset[str] = frozenset(
    {"os", "posix", "nt", "builtins", "subprocess", "ctypes", "importlib"}
)

_DYN_ATTR_FUNCS: frozenset[str] = frozenset(
    {"getattr", "setattr", "delattr", "vars", "getattr_static"}
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


class _PolicyVisitor(ast.NodeVisitor):
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

    def visit_Call(self, node: ast.Call) -> None:
        # The call target is judged by _check_call; don't re-flag it as a
        # bare reference when generic_visit walks into it.
        current: ast.AST = node.func
        while True:
            self._judged.add(id(current))
            if not isinstance(current, ast.Attribute):
                break
            current = current.value
        self._check_call(node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self._check_dangerous_subscript(node)
        if isinstance(node.ctx, ast.Load) and self._resolved_chain(node.value) == [
            "sys",
            "modules",
        ]:
            self._fail_sys_modules(node.lineno)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # ``"x" in sys.modules`` is a harmless membership test.
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.In, ast.NotIn)):
                self._judged.add(id(comparator))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._judged.add(id(node.value))
        if isinstance(node.ctx, ast.Load) and id(node) not in self._judged:
            chain = self._resolved_chain(node)
            sink = _sink_for_chain(chain) if chain else None
            if sink is not None:
                code, label = sink
                self._fail_reference(code, label, node.lineno)
                return
        self.generic_visit(node)

    def _resolved_chain(self, node: ast.AST) -> list[str] | None:
        """Attribute chain with the root import alias expanded (``o.system`` → os)."""
        chain = _attr_chain(node)
        if not chain:
            return None
        origin = self._aliases.get(chain[0])
        if origin is None:
            return chain
        return origin.split(".") + chain[1:]

    def _fail_reference(self, code: str, label: str, lineno: int) -> None:
        if code == "DYN_EXEC":
            self.saw_dyn_exec = True
        self.findings.append(
            _finding(
                code,
                SEVERITY_FAIL,
                f"Reference to {label} at line {lineno} "
                "(aliasing a dangerous callable)",
            )
        )

    def _fail_sys_modules(self, lineno: int) -> None:
        self.findings.append(
            _finding(
                "SYS_MODULES",
                SEVERITY_FAIL,
                f"Module lookup via sys.modules at line {lineno}",
            )
        )

    def _constant_str(self, node: ast.AST | None) -> str | None:
        return _fold_str(node)

    def _check_dangerous_attr_name(self, name: str, lineno: int, *, via: str) -> None:
        if name not in _DANGEROUS_ATTR_NAMES:
            return
        self.findings.append(
            _finding(
                "DYN_ATTR",
                SEVERITY_FAIL,
                f"Dynamic access to dangerous attribute {name!r} via {via} "
                f"at line {lineno}",
            )
        )

    def _check_dangerous_subscript(self, node: ast.Subscript) -> None:
        chain = _attr_chain(node.value)
        if not chain:
            return
        if chain[-1] not in {"__dict__", "__builtins__", "__globals__", "__class__"}:
            return
        slice_node = node.slice
        name = self._constant_str(slice_node)
        if name is None:
            return
        self._check_dangerous_attr_name(
            name,
            node.lineno,
            via=".".join(chain),
        )

    def _check_dyn_attr_call(self, node: ast.Call) -> bool:
        """Block getattr/setattr/… and operator.attrgetter of dangerous names."""
        func = node.func
        lineno = node.lineno

        if isinstance(func, ast.Name) and func.id in _DYN_ATTR_FUNCS:
            # getattr(obj, "system") — name is 2nd arg; vars(obj) alone is warn-free.
            if func.id in {"getattr", "setattr", "delattr"} and len(node.args) >= 2:
                self._check_dyn_attr_name_arg(
                    node.args[1], lineno, via=func.id, receiver=node.args[0]
                )
                return True
            return False

        chain = self._resolved_chain(func)
        if not chain:
            return False
        if chain[0] == "operator" and chain[-1] in {"attrgetter", "methodcaller"}:
            if node.args:
                self._check_dyn_attr_name_arg(
                    node.args[0], lineno, via=".".join(chain), receiver=None
                )
                return True
        if chain[-1] in _DYN_ATTR_FUNCS and len(node.args) >= 2:
            self._check_dyn_attr_name_arg(
                node.args[1], lineno, via=".".join(chain), receiver=node.args[0]
            )
            return True
        return False

    def _check_dyn_attr_name_arg(
        self,
        name_node: ast.AST,
        lineno: int,
        *,
        via: str,
        receiver: ast.AST | None,
    ) -> None:
        name = self._constant_str(name_node)
        if name is not None:
            self._check_dangerous_attr_name(name, lineno, via=via)
            if name not in _DANGEROUS_ATTR_NAMES and receiver is not None:
                # Fully known attribute: the receiver isn't an opaque module ref.
                self._judged.add(id(receiver))
            return
        # Name not statically known. Receivers that are sensitive modules are
        # still caught as MODULE_REF when visited; elsewhere this is unusual.
        self.findings.append(
            _finding(
                "DYN_ATTR_DYNAMIC",
                SEVERITY_WARN,
                f"Attribute name computed at runtime via {via} at line {lineno}",
            )
        )

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
