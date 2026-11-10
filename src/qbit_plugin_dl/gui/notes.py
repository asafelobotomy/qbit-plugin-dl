"""Helpers that turn install results into short, readable notes."""

from __future__ import annotations

import re

from qbit_plugin_dl.audit import AuditFinding
from qbit_plugin_dl.catalog import (
    Plugin,
)
from qbit_plugin_dl.install import (
    InstallResult,
)

_IMPORT_NAME_RE = re.compile(r"import '([^']+)'")

_IMPORT_REASON_LABELS: dict[str, str] = {
    "multiprocessing": "Spawns OS processes (multiprocessing)",
    "socket": "Uses raw sockets",
    "HTMLParser": "Uses Python 2 HTMLParser (update to html.parser)",
    "urllib2": "Uses Python 2 urllib2 (update to urllib.request)",
    "Queue": "Uses Python 2 Queue module",
    "ctypes": "Uses ctypes",
    "subprocess": "Uses subprocess",
    "pickle": "Uses pickle",
    "marshal": "Uses marshal",
    "requests": (
        "Uses requests (not shipped by qBittorrent — needs urllib / helpers)"
    ),
    "httpx": (
        "Uses httpx (not shipped by qBittorrent — needs urllib / helpers)"
    ),
    "aiohttp": (
        "Uses aiohttp (not shipped by qBittorrent — needs urllib / helpers)"
    ),
}


def _import_roots_from_findings(findings: tuple[AuditFinding, ...]) -> list[str]:
    roots: list[str] = []
    for finding in findings:
        if finding.code != "IMPORT_DENY":
            continue
        match = _IMPORT_NAME_RE.search(finding.message)
        if not match:
            continue
        root = match.group(1).split(".", 1)[0]
        if root not in roots:
            roots.append(root)
    return roots


def _safety_group_key(result: InstallResult) -> tuple[str, str]:
    """Return (sort_key, human label) for grouping a safety-blocked install."""
    report = result.audit
    if report is None:
        return ("zz_other", "Other safety issues")
    fails = report.fail_findings
    if not fails:
        return ("zz_other", "Other safety issues")

    import_roots = _import_roots_from_findings(fails)
    if import_roots:
        primary = import_roots[0]
        label = _IMPORT_REASON_LABELS.get(
            primary,
            f"Disallowed import: {', '.join(import_roots[:3])}",
        )
        return (f"import:{primary}", label)

    code = fails[0].code
    labels = {
        "DYN_EXEC": "Dynamic code execution (exec/eval/…)",
        "OS_EXEC": "Dangerous OS process calls",
        "PROCESS_EXEC": "Spawns OS processes",
        "SUBPROCESS": "Subprocess usage",
        "PICKLE_MARSHAL": "Pickle/marshal loading",
        "CTYPES": "ctypes / native code",
        "FORMAT_ZIP": "Non-Python payload (ZIP)",
        "FORMAT_ELF": "Non-Python payload (ELF)",
        "FORMAT_PE": "Non-Python payload (PE)",
        "NOVA3_STRUCTURE": "Missing nova3 search() structure",
        "CLAM_HIT": "ClamAV infection signature",
        "SYNTAX": "Python syntax error",
    }
    return (f"code:{code}", labels.get(code, f"Safety rule: {code}"))


def _short_network_error(error: str) -> str:
    text = error.strip()
    lower = text.lower()
    if "404" in text:
        return "Download URL not found (HTTP 404)"
    if "untrusted download host" in lower:
        return text if len(text) <= 120 else text[:117] + "…"
    if "no address associated with hostname" in lower or "name or service not known" in lower:
        return "DNS lookup failed (host not found)"
    if "timed out" in lower or "timeout" in lower:
        return "Network timeout"
    if "too large" in lower:
        match = re.search(
            r"\((\d+)\s*bytes\s*>\s*(\d+)\s*bytes",
            text,
            flags=re.IGNORECASE,
        )
        if match:
            actual = _format_byte_size(int(match.group(1)))
            limit = _format_byte_size(int(match.group(2)))
            return f"File too large ({actual} > {limit} limit)"
        return "File too large"
    if "https required" in lower:
        return "Non-HTTPS download URL rejected"
    if len(text) > 100:
        return text[:97] + "…"
    return text


def _format_byte_size(n: int) -> str:
    """Human-readable byte size for summary lines."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


# Benign, high-volume warn codes → rolled up by count instead of per-plugin lines.
_COLLAPSED_WARN_LABELS: dict[str, str] = {
    "IMPORT_PY2_SHIM": "Python 2 compatibility shims",
    "NOVA3_PRETTYPRINTER": "prettyPrinter heuristic notes",
    "NOVA3_CLASS_NAME": "class name vs filename notes",
    "NOVA3_ATTR": "nova3 attribute notes",
}


def _still_blocked_reason(result: InstallResult) -> str:
    """Short reason a fix attempt still failed to install."""
    report = result.audit
    if report is not None:
        fails = report.fail_findings
        roots = _import_roots_from_findings(fails)
        if roots:
            labels = [
                _IMPORT_REASON_LABELS.get(root, root) for root in roots[:2]
            ]
            return f"still blocked: {'; '.join(labels)}"
        if fails:
            return f"still blocked: {fails[0].code}"
    if result.error:
        short = _short_network_error(result.error)
        if short != result.error.strip() or len(short) <= 80:
            return short
        return result.error.strip()[:77] + "…"
    return "still blocked"


def _format_name_list(names: list[str], *, limit: int = 8) -> str:
    if len(names) <= limit:
        return ", ".join(names)
    shown = ", ".join(names[:limit])
    return f"{shown}, … (+{len(names) - limit} more)"


def _alternate_hint(
    plugin: Plugin,
    alternates_by_filename: dict[str, tuple],
) -> str:
    """Human hint when another catalog URL shares this install filename."""
    members = alternates_by_filename.get(plugin.filename, ())
    for candidate in members:
        if candidate.download_url != plugin.download_url:
            author = candidate.author or "unknown author"
            return f"{candidate.name} ({author})"
    return ""
