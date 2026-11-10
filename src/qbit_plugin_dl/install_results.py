"""Install results and the fix reports attached to them."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from qbit_plugin_dl.audit import AuditReport
from qbit_plugin_dl.catalog import Plugin
from qbit_plugin_dl.fetch import (
    FetchError,
)
from qbit_plugin_dl.fix import (
    FixKind,
    FixReport,
)


@dataclass(frozen=True, slots=True)
class InstallResult:
    plugin: Plugin
    ok: bool
    path: Path | None
    error: str | None = None
    audit: AuditReport | None = None
    fix: FixReport | None = None
    provenance_error: str | None = None
    # Set when the download redirected to a source the user has not approved.
    # Callers may ask for consent and re-run the install.
    untrusted_redirect: FetchError | None = None


_AST_FIX_KINDS = frozenset(
    {
        FixKind.PY2_IMPORTS,
        FixKind.PROCESS_POOL,
        FixKind.MP_DUMMY,
    }
)


def _fix_report_for_write(
    *,
    alternate_used: bool,
    ast_kinds: Sequence[FixKind],
    tried_urls: Sequence[str],
    final_url: str,
) -> FixReport | None:
    kinds: list[FixKind] = []
    if alternate_used:
        kinds.append(FixKind.ALTERNATE)
    kinds.extend(ast_kinds)
    # Preserve order, drop duplicates.
    kinds = list(dict.fromkeys(kinds))
    if not kinds:
        return None
    return FixReport(
        kinds=tuple(kinds),
        rewritten=any(k in _AST_FIX_KINDS for k in ast_kinds),
        alternate_used=alternate_used,
        tried_urls=tuple(tried_urls),
        final_url=final_url,
    )


def _fix_report_for_failure(
    *,
    alternate_used: bool,
    ast_kinds: Sequence[FixKind],
    tried_urls: Sequence[str],
    final_url: str,
) -> FixReport | None:
    """Report attempted kinds for a failed install (includes this-round AST)."""
    return _fix_report_for_write(
        alternate_used=alternate_used,
        ast_kinds=ast_kinds,
        tried_urls=tried_urls,
        final_url=final_url,
    )


ProgressCallback = Callable[[int, int, Plugin, InstallResult | None], None]
