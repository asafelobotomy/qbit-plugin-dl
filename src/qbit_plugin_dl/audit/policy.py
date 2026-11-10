"""What the static audit allows and denies: modules, builtins, attributes and thresholds."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

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
# Encoded payloads (base64 / hex / urlsafe base64) are long unbroken runs of
# this alphabet. Scraping regexes and magnet/tracker URLs are just as
# "random" by entropy but punctuation keeps their runs short.
_BLOB_RUN = re.compile(r"[A-Za-z0-9+/=_-]{64,}")
_EXTREME_LINE_LEN = 500
