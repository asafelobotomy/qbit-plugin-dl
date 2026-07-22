"""Optional safe install-time fixes (AST transforms + alternate forks).

Never exec/import plugin bodies. ClamAV must run on bytes before any rewrite.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from qbit_plugin_dl.audit import AuditFinding, AuditReport, audit_plugin_static
from qbit_plugin_dl.audit_clamav import ClamAvSession
from qbit_plugin_dl.catalog import Plugin, group_plugins_for_display, plugin_preference_score

FIX_INDICATOR = "🔧 "

# Py2 module root → Python 3 module path
_PY2_MODULE_MAP: dict[str, str] = {
    "HTMLParser": "html.parser",
    "urllib2": "urllib.request",
    "urlparse": "urllib.parse",
    "cookielib": "http.cookiejar",
    "Cookie": "http.cookies",
    "Queue": "queue",
    "ConfigParser": "configparser",
    "cStringIO": "io",
    "StringIO": "io",
    "httplib": "http.client",
    "htmlentitydefs": "html.entities",
    "UserDict": "collections",
    "UserList": "collections",
    "UserString": "collections",
}


class FixKind(StrEnum):
    PY2_IMPORTS = "py2_imports"
    PROCESS_POOL = "process_pool_to_thread"
    MP_DUMMY = "multiprocessing_to_dummy"
    ALTERNATE = "alternate_fork"


@dataclass(frozen=True, slots=True)
class FixReport:
    """What safe fixes were applied for a successful or attempted install."""

    kinds: tuple[FixKind, ...] = ()
    rewritten: bool = False
    alternate_used: bool = False
    tried_urls: tuple[str, ...] = ()
    final_url: str = ""

    @property
    def applied(self) -> bool:
        return bool(self.kinds)


@dataclass
class _TransformState:
    kinds: set[FixKind] = field(default_factory=set)
    rename_names: dict[str, str] = field(default_factory=dict)


class _SafeFixTransformer(ast.NodeTransformer):
    def __init__(self, *, rewrite_mp_import: bool = False) -> None:
        self.state = _TransformState()
        self.rewrite_mp_import = rewrite_mp_import

    def visit_Import(self, node: ast.Import) -> ast.AST:
        new_names: list[ast.alias] = []
        changed = False
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root in _PY2_MODULE_MAP:
                new_mod = _PY2_MODULE_MAP[root]
                asname = alias.asname or alias.name
                new_names.append(ast.alias(name=new_mod, asname=asname))
                self.state.kinds.add(FixKind.PY2_IMPORTS)
                changed = True
            elif self.rewrite_mp_import and alias.name == "multiprocessing":
                # Bare import + ``.Pool``/``.Process`` attrs → dummy module.
                new_names.append(
                    ast.alias(name="multiprocessing.dummy", asname=alias.asname)
                )
                self.state.kinds.add(FixKind.MP_DUMMY)
                changed = True
            else:
                new_names.append(alias)
        if changed:
            return ast.copy_location(ast.Import(names=new_names), node)
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST:
        module = node.module or ""
        names = list(node.names)

        if module in _PY2_MODULE_MAP:
            node = ast.copy_location(
                ast.ImportFrom(
                    module=_PY2_MODULE_MAP[module],
                    names=names,
                    level=node.level,
                ),
                node,
            )
            self.state.kinds.add(FixKind.PY2_IMPORTS)
            return self.generic_visit(node)

        if module == "multiprocessing" or module.startswith("multiprocessing."):
            if not module.startswith("multiprocessing.dummy"):
                spawn_names = {"Pool", "Process"}
                if any(a.name in spawn_names for a in names):
                    node = ast.copy_location(
                        ast.ImportFrom(
                            module="multiprocessing.dummy",
                            names=names,
                            level=node.level,
                        ),
                        node,
                    )
                    self.state.kinds.add(FixKind.MP_DUMMY)
                    return self.generic_visit(node)

        if module.startswith("concurrent.futures"):
            new_aliases: list[ast.alias] = []
            changed = False
            for alias in names:
                if alias.name == "ProcessPoolExecutor":
                    new_aliases.append(
                        ast.alias(
                            name="ThreadPoolExecutor",
                            asname=alias.asname,
                        )
                    )
                    if alias.asname is None:
                        self.state.rename_names["ProcessPoolExecutor"] = (
                            "ThreadPoolExecutor"
                        )
                    self.state.kinds.add(FixKind.PROCESS_POOL)
                    changed = True
                else:
                    new_aliases.append(alias)
            if changed:
                node = ast.copy_location(
                    ast.ImportFrom(
                        module=module,
                        names=new_aliases,
                        level=node.level,
                    ),
                    node,
                )
                return self.generic_visit(node)

        return self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        node = self.generic_visit(node)
        assert isinstance(node, ast.Attribute)
        # concurrent.futures.ProcessPoolExecutor
        if node.attr == "ProcessPoolExecutor":
            self.state.kinds.add(FixKind.PROCESS_POOL)
            return ast.copy_location(
                ast.Attribute(value=node.value, attr="ThreadPoolExecutor", ctx=node.ctx),
                node,
            )
        # multiprocessing.Pool / Process (not .dummy.*)
        if node.attr in {"Pool", "Process"} and _is_multiprocessing_root(node.value):
            self.state.kinds.add(FixKind.MP_DUMMY)
            dummy = ast.Attribute(
                value=ast.Name(id="multiprocessing", ctx=ast.Load()),
                attr="dummy",
                ctx=ast.Load(),
            )
            return ast.copy_location(
                ast.Attribute(value=dummy, attr=node.attr, ctx=node.ctx),
                node,
            )
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if isinstance(node.ctx, ast.Load) and node.id in self.state.rename_names:
            return ast.copy_location(
                ast.Name(id=self.state.rename_names[node.id], ctx=node.ctx),
                node,
            )
        return node


def _is_multiprocessing_root(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id == "multiprocessing":
        return True
    if isinstance(node, ast.Attribute):
        # multiprocessing.something but not multiprocessing.dummy
        parts: list[str] = []
        cur: ast.AST | None = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name) and cur.id == "multiprocessing":
            parts.append(cur.id)
            parts.reverse()
            return len(parts) == 1 or (len(parts) >= 2 and parts[1] != "dummy")
    return False


def _uses_multiprocessing_process_attrs(tree: ast.AST) -> bool:
    """True when AST uses ``multiprocessing.Pool`` / ``Process`` (non-dummy)."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in {"Pool", "Process"}
            and _is_multiprocessing_root(node.value)
        ):
            return True
    return False


def clamav_allows_ast(
    status: str,
    *,
    allow_without_clamav: bool = False,
) -> bool:
    """
    Whether AST rewrites may run given a ClamAV status string.

    Infected → never. Clean → yes. Skipped / unavailable / error → only when
    ``allow_without_clamav`` is True. Any other status → no.
    """
    if status == "infected":
        return False
    if status == "clean":
        return True
    if status in {"skipped", "unavailable", "error"}:
        return allow_without_clamav
    return False


def apply_safe_ast_fixes(
    content: bytes,
    *,
    filename: str = "plugin.py",
) -> tuple[bytes, list[FixKind]]:
    """
    Apply allowlisted AST rewrites. Returns (new_bytes, kinds).

    On parse failure, returns the original bytes and no kinds.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = content.decode("latin-1")
        except UnicodeDecodeError:
            return content, []

    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError:
        return content, []

    transformer = _SafeFixTransformer(
        rewrite_mp_import=_uses_multiprocessing_process_attrs(tree)
    )
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)
    kinds = sorted(transformer.state.kinds, key=lambda k: k.value)
    if not kinds:
        return content, []

    try:
        rewritten = ast.unparse(new_tree)
    except Exception:  # noqa: BLE001 — keep original on unparse failure
        return content, []

    # Preserve a trailing newline like typical source files.
    if not rewritten.endswith("\n"):
        rewritten += "\n"
    return rewritten.encode("utf-8"), list(kinds)


def filename_alternates_map(
    catalog: Sequence[Plugin],
) -> dict[str, tuple[Plugin, ...]]:
    """Map install basename → preference-ranked plugins sharing that file."""
    buckets: dict[str, list[Plugin]] = {}
    for plugin in catalog:
        buckets.setdefault(plugin.filename, []).append(plugin)
    result: dict[str, tuple[Plugin, ...]] = {}
    for filename, members in buckets.items():
        ranked = sorted(members, key=plugin_preference_score, reverse=True)
        # Stable unique by download_url
        seen: set[str] = set()
        unique: list[Plugin] = []
        for plugin in ranked:
            if plugin.download_url in seen:
                continue
            seen.add(plugin.download_url)
            unique.append(plugin)
        result[filename] = tuple(unique)
    return result


def ranked_alternates(
    plugin: Plugin,
    alternates_by_filename: Mapping[str, Sequence[Plugin]],
    *,
    tried_urls: set[str] | None = None,
) -> list[Plugin]:
    """Return other catalog plugins for the same filename, preference order."""
    tried = tried_urls or set()
    members = alternates_by_filename.get(plugin.filename, ())
    return [
        candidate
        for candidate in members
        if candidate.download_url != plugin.download_url
        and candidate.download_url not in tried
    ]


def alternates_from_catalog(catalog: Sequence[Plugin]) -> dict[str, tuple[Plugin, ...]]:
    """Build filename→plugins map; also merge display-group siblings by filename."""
    base = filename_alternates_map(catalog)
    # Ensure with-categories / fork grouping did not hide same-filename peers.
    for group in group_plugins_for_display(catalog):
        members = (group.primary, *group.alternates)
        by_fn: dict[str, list[Plugin]] = {}
        for plugin in members:
            by_fn.setdefault(plugin.filename, []).append(plugin)
        for filename, group_members in by_fn.items():
            existing = list(base.get(filename, ()))
            urls = {p.download_url for p in existing}
            for plugin in group_members:
                if plugin.download_url not in urls:
                    existing.append(plugin)
                    urls.add(plugin.download_url)
            existing.sort(key=plugin_preference_score, reverse=True)
            base[filename] = tuple(existing)
    return base


def audit_clamav_then_static(
    content: bytes,
    *,
    filename: str,
    clamav_session: ClamAvSession | None,
) -> AuditReport:
    """
    ClamAV first (when session provided), then static AST.

    Infected → blocked without static. Unavailable/skipped/error ClamAV does not
    block; static still runs.
    """
    clam_findings: list[AuditFinding] = []
    status = "skipped"
    backend = "none"
    if clamav_session is not None:
        clam_findings, status, backend = clamav_session.scan_bytes(
            content, filename=filename
        )
        if status == "infected":
            return AuditReport(
                findings=tuple(clam_findings),
                clamav_status=status,
                clamav_backend=backend,
            )

    static = audit_plugin_static(content, filename=filename)
    return AuditReport(
        findings=tuple([*static.findings, *clam_findings]),
        clamav_status=status,
        clamav_backend=backend,
    )


def try_ast_fix_after_clamav(
    content: bytes,
    *,
    filename: str,
    clamav_session: ClamAvSession | None,
    prior_report: AuditReport,
    allow_ast_without_clamav: bool = False,
) -> tuple[bytes, AuditReport, list[FixKind]]:
    """
    If static failed and ClamAV allows AST, apply rewrites and re-scan.

    Returns (content, report, kinds). Kinds empty when no rewrite applied.
    """
    if not clamav_allows_ast(
        prior_report.clamav_status,
        allow_without_clamav=allow_ast_without_clamav,
    ):
        return content, prior_report, []
    if not prior_report.blocked:
        return content, prior_report, []
    # Only attempt AST when failures look rewriteable (import/process), not format.
    fail_codes = {f.code for f in prior_report.fail_findings}
    if fail_codes & {"FORMAT_NUL", "FORMAT_ZIP", "FORMAT_ELF", "FORMAT_PE", "SYNTAX"}:
        return content, prior_report, []

    fixed_bytes, kinds = apply_safe_ast_fixes(content, filename=filename)
    if not kinds:
        return content, prior_report, []

    report = audit_clamav_then_static(
        fixed_bytes, filename=filename, clamav_session=clamav_session
    )
    return fixed_bytes, report, kinds
