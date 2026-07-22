"""PySide6 UI for selecting and installing unofficial search plugins."""

from __future__ import annotations

import re
from collections import defaultdict
from importlib.resources import as_file, files
from pathlib import Path

from PySide6.QtCore import Qt, QSettings, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStyle,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from qbit_plugin_dl import __version__
from qbit_plugin_dl.audit import SEVERITY_WARN, AuditFinding
from qbit_plugin_dl.audit_clamav import (
    ClamAvSession,
    format_clamav_backend_label,
)
from qbit_plugin_dl.catalog import (
    Plugin,
    Visibility,
    fetch_catalog,
    filter_plugins,
    group_plugins_for_display,
    parse_wiki_date,
    parse_wiki_version,
)
from qbit_plugin_dl.categories import (
    ADULT_CATEGORY,
    FILTER_CATEGORIES,
    UNCATEGORIZED,
    apply_cached_categories,
    enrich_plugins,
    format_categories,
)
from qbit_plugin_dl.fetch import (
    hostname_from_url,
    untrusted_hosts_in_urls,
)
from qbit_plugin_dl.fix import FIX_INDICATOR, alternates_from_catalog
from qbit_plugin_dl.install import (
    InstallResult,
    UninstallResult,
    candidate_engine_dirs,
    detect_engine_dirs,
    format_engine_dir_label,
    install_plugins,
    list_installed_filenames,
    resolve_install_dir,
    uninstall_plugins,
)
from qbit_plugin_dl.provenance import fix_kinds_for_filename, list_fixed_filenames
from qbit_plugin_dl.updates import (
    UPDATE_INDICATOR,
    find_outdated_filenames,
    plugins_for_updates,
)

DISCLAIMER = (
    "Unofficial qBittorrent search plugins are community-provided Python scripts "
    "and are not inherently safe. Use them at your own risk. Prefer auditing a "
    "plugin before installing it.\n\n"
    "This app runs a static safety check before writing engines, and may use "
    "ClamAV when available. That reduces risk but is not a guarantee of safety.\n\n"
    "Plugins marked with warning symbols (✖ / ❗ / ❌) are strongly discouraged "
    "by the upstream wiki because they can slow down or break other plugins."
)

COLS = (
    "",
    "Name",
    "Version",
    "Visibility",
    "Categories",
    "Updated",
    "Author",
    "Source",
    "Comments",
    "Installed",
)

# Column indices for sort-key helpers / tests.
COL_CHECK = 0
COL_NAME = 1
COL_VERSION = 2
COL_VISIBILITY = 3
COL_CATEGORIES = 4
COL_UPDATED = 5
COL_AUTHOR = 6
COL_SOURCE = 7
COL_COMMENTS = 8
COL_INSTALLED = 9

SOURCE_LABELS = {
    "wiki": "Wiki",
    "official": "Official",
    "lightdestory": "LightDestory",
}


def plugin_column_sort_key(
    plugin: Plugin,
    column: int,
    *,
    checked: bool = False,
    installed: bool = False,
) -> tuple:
    """Return a comparable sort key for a plugin column."""
    if column == COL_CHECK:
        return (0 if checked else 1,)
    if column == COL_NAME:
        return (plugin.name.casefold(),)
    if column == COL_VISIBILITY:
        return (plugin.visibility.value,)
    if column == COL_CATEGORIES:
        return (format_categories(plugin.categories).casefold(),)
    if column == COL_VERSION:
        return (parse_wiki_version(plugin.version), plugin.version.casefold())
    if column == COL_UPDATED:
        return (parse_wiki_date(plugin.last_update), plugin.last_update.casefold())
    if column == COL_AUTHOR:
        return (plugin.author.casefold(),)
    if column == COL_SOURCE:
        return (SOURCE_LABELS.get(plugin.source_id, plugin.source_id).casefold(),)
    if column == COL_COMMENTS:
        return (plugin.comments.casefold(),)
    if column == COL_INSTALLED:
        return (0 if installed else 1,)
    return (plugin.name.casefold(),)


class PluginTreeItem(QTreeWidgetItem):
    """Tree row with type-aware column sorting (version/date/check/installed)."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:
        tree = self.treeWidget()
        column = tree.sortColumn() if tree is not None else 0
        left = self._sort_key(column)
        if isinstance(other, PluginTreeItem):
            right = other._sort_key(column)
        else:
            right = (other.text(column).casefold(),)
        return left < right

    def _sort_key(self, column: int) -> tuple:
        plugin = self.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(plugin, Plugin):
            return (self.text(column).casefold(),)
        return plugin_column_sort_key(
            plugin,
            column,
            checked=self.checkState(0) == Qt.CheckState.Checked,
            installed=self.text(COL_INSTALLED) == "Yes",
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
            return f"still blocked: {', '.join(roots[:3])}"
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


def format_install_summary(
    results: list[InstallResult],
    engines_dir: Path,
    *,
    alternates_by_filename: dict[str, tuple] | None = None,
) -> tuple[str, str, str]:
    """
    Build install-complete dialog title, body, and icon kind.

    Icon kind is one of: ``information``, ``warning``, ``critical``.
    """
    total = len(results)
    installed = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    alt_map = alternates_by_filename or {}

    infections: list[InstallResult] = []
    safety_blocked: list[InstallResult] = []
    other_failed: list[InstallResult] = []
    for result in failed:
        report = result.audit
        if report is not None and report.clamav_status == "infected":
            infections.append(result)
        elif report is not None and report.blocked:
            safety_blocked.append(result)
        else:
            other_failed.append(result)

    # Warnings only for plugins that were actually installed.
    # Prefer ClamAV status from a result that actually ran a scan.
    collapsed_warn_plugins: dict[str, set[str]] = defaultdict(set)
    notable_warning_lines: list[str] = []
    total_warn_findings = 0
    clam_backend = "none"
    clam_status = "skipped"
    for result in results:
        report = result.audit
        if report is None:
            continue
        if report.clamav_backend != "none" or report.clamav_status not in {
            "skipped",
            "unavailable",
        }:
            clam_backend = report.clamav_backend
            clam_status = report.clamav_status
        if not result.ok:
            continue
        for finding in report.findings:
            if finding.severity != SEVERITY_WARN:
                continue
            total_warn_findings += 1
            if finding.code in _COLLAPSED_WARN_LABELS:
                collapsed_warn_plugins[finding.code].add(result.plugin.name)
            else:
                notable_warning_lines.append(
                    f"{result.plugin.name} — {finding.code}: {finding.message}"
                )

    lines: list[str] = [
        "Summary",
        f"  Installed: {len(installed)} of {total}",
        f"  Failed: {len(failed)}",
    ]
    if infections:
        lines.append(f"  Infections blocked: {len(infections)}")
    if safety_blocked:
        lines.append(f"  Blocked by safety check: {len(safety_blocked)}")
    if other_failed:
        lines.append(f"  Download / network errors: {len(other_failed)}")

    fixed_ok = [r for r in installed if r.fix is not None and r.fix.applied]
    if fixed_ok:
        lines.append(f"  Fixed during install: {len(fixed_ok)}")

    lines.extend(
        [
            "",
            f"Install folder:\n  {engines_dir}",
            f"ClamAV: {format_clamav_backend_label(clam_backend, clam_status).removeprefix('ClamAV: ').strip()}",
            "",
            "Restart qBittorrent (or refresh Search plugins) to load new engines.",
        ]
    )

    if fixed_ok:
        lines.append("")
        lines.append(
            f"Safe fixes applied ({len(fixed_ok)}) — marked "
            f"{FIX_INDICATOR.strip()} in the list"
        )
        for result in fixed_ok:
            kinds = (
                ", ".join(k.value for k in result.fix.kinds) if result.fix else ""
            )
            lines.append(f"  • {result.plugin.name} — {kinds}")

    failed_fix_attempts = [
        r
        for r in failed
        if r.fix is not None and r.fix.applied
    ]
    if failed_fix_attempts:
        lines.append("")
        lines.append(
            f"Fix attempts that did not install ({len(failed_fix_attempts)})"
        )
        for result in failed_fix_attempts:
            kinds = (
                ", ".join(k.value for k in result.fix.kinds) if result.fix else ""
            )
            reason = _still_blocked_reason(result)
            lines.append(f"  • {result.plugin.name} — {kinds}; {reason}")

    provenance_warnings = [r for r in installed if r.provenance_error]
    if provenance_warnings:
        lines.append("")
        lines.append(
            f"Provenance save failed ({len(provenance_warnings)}) — "
            "engine written; fix marker may be missing"
        )
        for result in provenance_warnings:
            lines.append(
                f"  • {result.plugin.name} — {result.provenance_error}"
            )

    if infections:
        lines.append("")
        lines.append(f"Infections blocked ({len(infections)}) — not installed")
        for result in infections:
            lines.append(f"  • {result.plugin.name}")

    if safety_blocked:
        lines.append("")
        lines.append(
            f"Blocked by safety check ({len(safety_blocked)}) — not installed"
        )
        lines.append(
            "These engines use APIs that qBittorrent search plugins should not need."
        )
        grouped: dict[str, list[str]] = defaultdict(list)
        labels: dict[str, str] = {}
        for result in safety_blocked:
            key, label = _safety_group_key(result)
            labels[key] = label
            grouped[key].append(result.plugin.name)
        for key in sorted(grouped.keys()):
            names = grouped[key]
            lines.append("")
            lines.append(f"  {labels[key]} ({len(names)})")
            lines.append(f"    {_format_name_list(names)}")
            hinted: set[str] = set()
            for result in safety_blocked:
                if _safety_group_key(result)[0] != key:
                    continue
                if result.plugin.name in hinted:
                    continue
                hint = _alternate_hint(result.plugin, alt_map)
                if hint:
                    lines.append(f"    Alternate available: {hint}")
                    hinted.add(result.plugin.name)

    if other_failed:
        lines.append("")
        lines.append(f"Download / network errors ({len(other_failed)})")
        for result in other_failed:
            reason = _short_network_error(result.error or "unknown error")
            lines.append(f"  • {result.plugin.name} — {reason}")
            hint = _alternate_hint(result.plugin, alt_map)
            if hint:
                lines.append(f"    Alternate available: {hint}")

    if total_warn_findings:
        lines.append("")
        lines.append(
            f"Notes on installed plugins ({total_warn_findings}) — installed anyway"
        )
        if collapsed_warn_plugins:
            lines.append("  Common (informational):")
            for code in sorted(
                collapsed_warn_plugins.keys(),
                key=lambda c: (-len(collapsed_warn_plugins[c]), c),
            ):
                label = _COLLAPSED_WARN_LABELS[code]
                count = len(collapsed_warn_plugins[code])
                noun = "plugin" if count == 1 else "plugins"
                lines.append(f"    • {label}: {count} {noun}")
        if notable_warning_lines:
            shown = notable_warning_lines[:8]
            extra = len(notable_warning_lines) - len(shown)
            lines.append(f"  Other notes ({len(notable_warning_lines)}):")
            lines.extend(f"    • {line}" for line in shown)
            if extra > 0:
                lines.append(f"    • …(+{extra} more)")

    if infections:
        title = "Install complete — infections blocked"
        icon = "critical"
    elif failed and not installed:
        title = "Install failed"
        icon = "critical"
    elif failed:
        title = "Install complete — with failures"
        icon = "warning"
    else:
        title = "Install complete"
        icon = "information"

    return title, "\n".join(lines), icon


def format_uninstall_summary(
    results: list[UninstallResult],
    engines_dir: Path,
) -> tuple[str, str, str]:
    """Build uninstall-complete dialog title, body, and icon kind."""
    total = len(results)
    removed_ok = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    file_count = sum(len(r.removed) for r in removed_ok)

    lines = [
        f"Engines directory:\n  {engines_dir}",
        "",
        "Summary",
        f"  Cleaned: {len(removed_ok)} of {total} engine(s)",
        f"  Files removed: {file_count}",
    ]
    if failed:
        lines.append(f"  Failed: {len(failed)}")

    if removed_ok:
        lines.append("")
        lines.append(f"Removed ({len(removed_ok)})")
        for result in removed_ok:
            label = (
                result.plugin.name
                if result.plugin is not None
                else result.filename
            )
            extras = len(result.removed) - 1 if result.removed else 0
            if extras > 0:
                lines.append(
                    f"  • {label} ({result.filename} + {extras} companion(s))"
                )
            else:
                lines.append(f"  • {label} ({result.filename})")

    if failed:
        lines.append("")
        lines.append(f"Failed ({len(failed)})")
        for result in failed:
            label = (
                result.plugin.name
                if result.plugin is not None
                else result.filename
            )
            err = result.error or "unknown error"
            lines.append(f"  • {label}: {err}")

    lines.extend(
        [
            "",
            "Engine scripts, stem-named config (e.g. jackett.json), leftover "
            ".tmp files, matching bytecode, and install provenance were "
            "cleared for each successful removal.",
        ]
    )

    if failed and not removed_ok:
        title = "Uninstall failed"
        icon = "critical"
    elif failed:
        title = "Uninstall complete — with failures"
        icon = "warning"
    else:
        title = "Uninstall complete"
        icon = "information"

    return title, "\n".join(lines), icon


def plugin_included_in_select_all(plugin: Plugin) -> bool:
    """Whether Select all should check this plugin (skips discouraged)."""
    return not plugin.warning


def load_app_icon() -> QIcon:
    """Load the bundled application icon from package resources."""
    resource = files("qbit_plugin_dl.resources").joinpath("icon.png")
    with as_file(resource) as path:
        return QIcon(str(path))


def _settings() -> QSettings:
    return QSettings()


def safety_accepted() -> bool:
    return bool(_settings().value("safety/accepted", False, type=bool))


def set_safety_accepted(accepted: bool = True) -> None:
    settings = _settings()
    settings.setValue("safety/accepted", accepted)
    settings.sync()


def clamav_enabled() -> bool:
    return bool(_settings().value("safety/clamav_enabled", True, type=bool))


def auto_fix_enabled() -> bool:
    """Whether safe install-time fixes are enabled (default off)."""
    return bool(_settings().value("install/auto_fix", False, type=bool))


def set_auto_fix_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("install/auto_fix", enabled)
    settings.sync()


def allow_ast_without_clamav_enabled() -> bool:
    """AST rewrites when ClamAV did not return clean (default off)."""
    return bool(
        _settings().value("install/allow_ast_without_clamav", False, type=bool)
    )


def set_allow_ast_without_clamav_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("install/allow_ast_without_clamav", enabled)
    settings.sync()


def trusted_download_hosts() -> set[str]:
    """Persisted hosts the user chose to always trust for downloads."""
    raw = _settings().value("security/trusted_download_hosts", [], type=list)
    if not isinstance(raw, list):
        return set()
    return {str(h).lower() for h in raw if str(h).strip()}


def add_trusted_download_host(host: str) -> None:
    host = host.lower().strip()
    if not host:
        return
    hosts = trusted_download_hosts()
    hosts.add(host)
    settings = _settings()
    settings.setValue("security/trusted_download_hosts", sorted(hosts))
    settings.sync()


def clamav_allow_clamscan_fallback() -> bool | None:
    """Return remembered clamscan consent, or None if unset."""
    settings = _settings()
    if not settings.contains("safety/allow_clamscan_fallback"):
        return None
    return bool(settings.value("safety/allow_clamscan_fallback", False, type=bool))


def set_clamav_allow_clamscan_fallback(allowed: bool) -> None:
    settings = _settings()
    settings.setValue("safety/allow_clamscan_fallback", allowed)
    settings.sync()


def build_clamav_session() -> ClamAvSession:
    return ClamAvSession(
        enabled=clamav_enabled(),
        allow_clamscan_fallback=clamav_allow_clamscan_fallback(),
    )


class CatalogWorker(QThread):
    finished_ok = Signal(list, str)
    failed = Signal(str)

    def __init__(self, force_refresh: bool = False) -> None:
        super().__init__()
        self.force_refresh = force_refresh

    def run(self) -> None:
        try:
            plugins, summary = fetch_catalog(force_refresh=self.force_refresh)
            plugins = apply_cached_categories(plugins)
            self.finished_ok.emit(plugins, summary)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class CategoryWorker(QThread):
    progress = Signal(int, int)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(
        self,
        plugins: list[Plugin],
        force_refresh: bool = False,
        *,
        trusted_hosts: set[str] | None = None,
    ) -> None:
        super().__init__()
        self.plugins = plugins
        self.force_refresh = force_refresh
        self.trusted_hosts = trusted_hosts or set()

    def run(self) -> None:
        try:

            def on_progress(done: int, total: int, _plugin: Plugin) -> None:
                self.progress.emit(done, total)

            enriched = enrich_plugins(
                self.plugins,
                force_refresh=self.force_refresh,
                on_progress=on_progress,
                trusted_hosts=self.trusted_hosts,
            )
            self.finished_ok.emit(enriched)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class InstallWorker(QThread):
    progress = Signal(int, int, str)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(
        self,
        plugins: list[Plugin],
        engines_dir: Path,
        clamav_session: ClamAvSession | None = None,
        *,
        auto_fix: bool = False,
        catalog: list[Plugin] | None = None,
        trusted_hosts: set[str] | None = None,
        allow_ast_without_clamav: bool = False,
    ) -> None:
        super().__init__()
        self.plugins = plugins
        self.engines_dir = engines_dir
        self.clamav_session = clamav_session
        self.auto_fix = auto_fix
        self.catalog = catalog
        self.trusted_hosts = trusted_hosts or set()
        self.allow_ast_without_clamav = allow_ast_without_clamav

    def run(self) -> None:
        try:

            def on_progress(
                done: int,
                total: int,
                plugin: Plugin,
                result: InstallResult | None,
            ) -> None:
                status = "ok"
                if result is not None and not result.ok:
                    status = result.error or "error"
                elif result is not None and result.fix is not None and result.fix.applied:
                    status = f"ok (fixed: {', '.join(k.value for k in result.fix.kinds)})"
                self.progress.emit(done, total, f"{plugin.name}: {status}")

            results = install_plugins(
                self.plugins,
                self.engines_dir,
                on_progress=on_progress,
                clamav_session=self.clamav_session,
                auto_fix=self.auto_fix,
                catalog=self.catalog,
                trusted_hosts=self.trusted_hosts,
                allow_ast_without_clamav=self.allow_ast_without_clamav,
            )
            self.finished_ok.emit(results)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UninstallWorker(QThread):
    progress = Signal(int, int, str)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(self, plugins: list[Plugin], engines_dir: Path) -> None:
        super().__init__()
        self.plugins = plugins
        self.engines_dir = engines_dir

    def run(self) -> None:
        try:

            def on_progress(
                done: int,
                total: int,
                filename: str,
                result: UninstallResult | None,
            ) -> None:
                status = "ok"
                if result is not None and not result.ok:
                    status = result.error or "error"
                label = (
                    result.plugin.name
                    if result is not None and result.plugin is not None
                    else filename
                )
                self.progress.emit(done, total, f"{label}: {status}")

            results = uninstall_plugins(
                self.plugins,
                self.engines_dir,
                on_progress=on_progress,
            )
            self.finished_ok.emit(results)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UpdateCheckWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        engines_dir: Path,
        plugins: list[Plugin],
        *,
        trusted_hosts: set[str] | None = None,
    ) -> None:
        super().__init__()
        self.engines_dir = engines_dir
        self.plugins = plugins
        self.trusted_hosts = trusted_hosts or set()

    def run(self) -> None:
        try:
            outdated = find_outdated_filenames(
                self.engines_dir,
                self.plugins,
                trusted_hosts=self.trusted_hosts,
            )
            self.finished_ok.emit(outdated)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class DisclaimerDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Safety notice")
        self.setModal(True)
        self.resize(560, 360)
        self.setMinimumSize(480, 300)
        layout = QVBoxLayout(self)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(DISCLAIMER)
        text.setMinimumHeight(200)
        text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(text)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Yes | QDialogButtonBox.StandardButton.No
        )
        buttons.button(QDialogButtonBox.StandardButton.Yes).setText("Accept")
        buttons.button(QDialogButtonBox.StandardButton.No).setText("Decline")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class InstallSummaryDialog(QDialog):
    """Bounded, scrollable install result dialog (avoids huge QMessageBox width)."""

    def __init__(
        self,
        title: str,
        body: str,
        icon_kind: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(560, 420)
        self.setMinimumSize(420, 280)
        self.setMaximumWidth(640)

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(self._icon_for_kind(icon_kind).pixmap(32, 32))
        header.addWidget(icon_label)
        title_label = QLabel(title)
        title_label.setWordWrap(True)
        title_font = title_label.font()
        title_font.setBold(True)
        title_label.setFont(title_font)
        header.addWidget(title_label, stretch=1)
        layout.addLayout(header)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(body)
        text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        text.setMinimumHeight(220)
        layout.addWidget(text, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _icon_for_kind(self, icon_kind: str) -> QIcon:
        style = self.style()
        if icon_kind == "critical":
            sp = QStyle.StandardPixmap.SP_MessageBoxCritical
        elif icon_kind == "warning":
            sp = QStyle.StandardPixmap.SP_MessageBoxWarning
        else:
            sp = QStyle.StandardPixmap.SP_MessageBoxInformation
        return style.standardIcon(sp)


class MainWindow(QMainWindow):
    def __init__(self, icon: QIcon | None = None) -> None:
        super().__init__()
        self.setWindowTitle(f"qBittorrent Plugin Downloader {__version__}")
        self.resize(1100, 700)
        if icon is not None and not icon.isNull():
            self.setWindowIcon(icon)

        self._all_plugins: list[Plugin] = []
        self._visible_plugins: list[Plugin] = []
        self._checked: set[tuple[str, str]] = set()
        self._installed: set[str] = set()
        self._fixed: set[str] = set()
        self._updates: set[str] = set()
        self._session_trusted_hosts: set[str] = set()
        self._engines_dir = resolve_install_dir()
        self._catalog_worker: CatalogWorker | None = None
        self._category_worker: CategoryWorker | None = None
        self._install_worker: InstallWorker | None = None
        self._uninstall_worker: UninstallWorker | None = None
        self._update_worker: UpdateCheckWorker | None = None
        self._force_category_refresh = False
        self._status_base = "Loading catalog…"
        self._status_updates_suffix = ""

        self._build_menu()

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh catalog")
        self.refresh_btn.clicked.connect(self.refresh_catalog)
        toolbar.addWidget(self.refresh_btn)

        toolbar.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search name, author, comments…")
        self.filter_edit.textChanged.connect(self.apply_filters)
        toolbar.addWidget(self.filter_edit, stretch=1)

        toolbar.addWidget(QLabel("Show:"))
        self.visibility_combo = QComboBox()
        self.visibility_combo.addItem("All", None)
        self.visibility_combo.addItem("Public", Visibility.PUBLIC)
        self.visibility_combo.addItem("Private", Visibility.PRIVATE)
        self.visibility_combo.currentIndexChanged.connect(self.apply_filters)
        toolbar.addWidget(self.visibility_combo)

        toolbar.addWidget(QLabel("Category:"))
        self.category_combo = QComboBox()
        self.category_combo.addItem("All", None)
        for cat in FILTER_CATEGORIES:
            label = "Adult" if cat == ADULT_CATEGORY else cat.capitalize()
            self.category_combo.addItem(label, cat)
        self.category_combo.addItem("Uncategorized", UNCATEGORIZED)
        self.category_combo.currentIndexChanged.connect(self.apply_filters)
        toolbar.addWidget(self.category_combo)

        self.hide_discouraged = QCheckBox("Hide discouraged")
        self.hide_discouraged.setChecked(True)
        self.hide_discouraged.stateChanged.connect(self.apply_filters)
        toolbar.addWidget(self.hide_discouraged)

        self.auto_fix_cb = QCheckBox("Safe fixes during install")
        self.auto_fix_cb.setChecked(auto_fix_enabled())
        self.auto_fix_cb.setToolTip(
            "When enabled, install may try alternate catalog forks and "
            "allowlisted AST rewrites. AST requires a clean ClamAV scan "
            "unless “Allow AST without ClamAV” is also enabled. "
            "Off by default."
        )
        self.auto_fix_cb.stateChanged.connect(self._on_auto_fix_toggled)
        toolbar.addWidget(self.auto_fix_cb)

        self.ast_without_clam_cb = QCheckBox("Allow AST without ClamAV")
        self.ast_without_clam_cb.setChecked(allow_ast_without_clamav_enabled())
        self.ast_without_clam_cb.setToolTip(
            "Permit allowlisted AST rewrites when ClamAV is skipped, "
            "unavailable, or errors. Alternates still work without this. "
            "Off by default."
        )
        self.ast_without_clam_cb.stateChanged.connect(self._on_ast_without_clam_toggled)
        toolbar.addWidget(self.ast_without_clam_cb)
        layout.addLayout(toolbar)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Install to:"))
        self.path_combo = QComboBox()
        self.path_combo.setMinimumWidth(480)
        self._populate_path_combo()
        self.path_combo.currentIndexChanged.connect(self._on_path_changed)
        path_row.addWidget(self.path_combo, stretch=1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_path)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        self.private_note = QLabel(
            "Private plugins often need credentials edited into the script after install."
        )
        self.private_note.setWordWrap(True)
        layout.addWidget(self.private_note)

        self.catalog_note = QLabel(
            "Catalogs: Unofficial wiki · Official nova3 · LightDestory "
            "(duplicates merge by install filename)."
        )
        self.catalog_note.setWordWrap(True)
        layout.addWidget(self.catalog_note)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(COLS))
        self.tree.setHeaderLabels(COLS)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setColumnWidth(0, 44)
        self.tree.setColumnWidth(1, 200)
        self.tree.setColumnWidth(2, 70)
        self.tree.setColumnWidth(3, 80)
        self.tree.setColumnWidth(4, 140)
        self.tree.setColumnWidth(5, 110)
        self.tree.setColumnWidth(6, 120)
        self.tree.setColumnWidth(7, 90)
        self.tree.setColumnWidth(8, 220)
        header = self.tree.header()
        header.setStretchLastSection(True)
        header.setSortIndicatorShown(True)
        # Manual sort on click so catalog order is kept until the user sorts.
        # IMPORTANT: setSortingEnabled(False) forces sectionsClickable=False, so
        # re-enable clickable *after* that call or header clicks do nothing.
        self._sort_column: int | None = None
        self._sort_order = Qt.SortOrder.AscendingOrder
        self.tree.setSortingEnabled(False)
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._on_header_section_clicked)
        self.tree.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.tree, stretch=1)

        footer = QHBoxLayout()
        self.select_all_btn = QPushButton("Select all visible")
        self.select_all_btn.clicked.connect(self.select_all_visible)
        footer.addWidget(self.select_all_btn)

        self.clear_btn = QPushButton("Clear selection")
        self.clear_btn.clicked.connect(self.clear_selection)
        footer.addWidget(self.clear_btn)

        footer.addStretch(1)

        self.install_btn = QPushButton("Install selected")
        self.install_btn.clicked.connect(self.install_selected)
        footer.addWidget(self.install_btn)

        self.uninstall_btn = QPushButton("Uninstall selected")
        self.uninstall_btn.clicked.connect(self.uninstall_selected)
        footer.addWidget(self.uninstall_btn)

        self.update_all_btn = QPushButton("Update all")
        self.update_all_btn.setEnabled(False)
        self.update_all_btn.clicked.connect(self.update_all_outdated)
        footer.addWidget(self.update_all_btn)
        layout.addLayout(footer)

        # Own row so long install status text cannot widen the main window.
        self.status_label = QLabel("Loading catalog…")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        status_policy = QSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Minimum,
        )
        status_policy.setHorizontalStretch(1)
        self.status_label.setSizePolicy(status_policy)
        self.status_label.setMinimumWidth(0)
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(True)
        self.progress.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        layout.addWidget(self.progress)

        QTimer.singleShot(0, lambda: self.refresh_catalog(force_refresh=False))

    def _build_menu(self) -> None:
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)
        help_menu = menu_bar.addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About qBittorrent Plugin Downloader",
            (
                f"<b>qBittorrent Plugin Downloader</b> {__version__}<br><br>"
                "Selective installer for qBittorrent search plugins from multiple "
                "allowlisted catalogs (unofficial wiki, official nova3 engines, "
                "and LightDestory).<br><br>"
                "Before writing engines, the app runs a static safety check. "
                "When ClamAV is available it prefers a running <code>clamd</code> "
                "(via <code>clamdscan --fdpass</code>); one-shot "
                "<code>clamscan</code> needs your consent. Optional "
                "<b>Safe fixes during install</b> (off by default) may try "
                "alternate catalog forks and allowlisted AST rewrites. AST "
                "rewrites require a <b>clean</b> ClamAV result unless "
                "<b>Allow AST without ClamAV</b> is enabled. Infected content "
                "is never fixed; after any rewrite ClamAV runs again when "
                "available. Downloads stream with a size cap; "
                "<code>raw.githubusercontent.com</code> / gist hosts are "
                "auto-trusted, other HTTPS hosts need confirmation. Fixed "
                "engines show 🔧 in the list. "
                "This is a review aid, not a sandbox or guarantee of safety.<br><br>"
                "Plugins are community Python scripts — use them at your own risk."
            ),
        )

    def _populate_path_combo(self) -> None:
        self.path_combo.blockSignals(True)
        self.path_combo.clear()
        existing = detect_engine_dirs()
        existing_keys = {str(path) for path in existing}
        seen: set[str] = set()
        for path in existing:
            key = str(path)
            if key not in seen:
                self.path_combo.addItem(format_engine_dir_label(path), path)
                seen.add(key)
        for path in candidate_engine_dirs():
            key = str(path)
            if key not in seen:
                self.path_combo.addItem(
                    format_engine_dir_label(path, will_create=True),
                    path,
                )
                seen.add(key)
        # Select current engines dir
        for i in range(self.path_combo.count()):
            if self.path_combo.itemData(i) == self._engines_dir:
                self.path_combo.setCurrentIndex(i)
                break
        else:
            will_create = str(self._engines_dir) not in existing_keys
            self.path_combo.insertItem(
                0,
                format_engine_dir_label(self._engines_dir, will_create=will_create),
                self._engines_dir,
            )
            self.path_combo.setCurrentIndex(0)
        self.path_combo.blockSignals(False)
        self._refresh_installed()

    def _on_path_changed(self) -> None:
        path = self.path_combo.currentData()
        if isinstance(path, Path):
            self._engines_dir = path
            self._refresh_installed()
            self._rebuild_tree()
            self._start_update_check()

    def _browse_path(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self,
            "Select qBittorrent engines directory",
            str(self._engines_dir),
        )
        if chosen:
            self._engines_dir = Path(chosen)
            self._populate_path_combo()
            self._rebuild_tree()
            self._start_update_check()

    def _refresh_installed(self) -> None:
        self._installed = list_installed_filenames(self._engines_dir)
        self._fixed = list_fixed_filenames()

    def _on_auto_fix_toggled(self, _state: int = 0) -> None:
        set_auto_fix_enabled(self.auto_fix_cb.isChecked())

    def _on_ast_without_clam_toggled(self, _state: int = 0) -> None:
        set_allow_ast_without_clamav_enabled(self.ast_without_clam_cb.isChecked())

    def _effective_trusted_hosts(self) -> set[str]:
        return trusted_download_hosts() | self._session_trusted_hosts

    def _prompt_untrusted_hosts(self, plugins: list[Plugin]) -> bool:
        """
        Pre-prompt for non-allowlisted hosts on catalog URLs.

        Returns False if the user cancels.
        """
        unknown = untrusted_hosts_in_urls(
            (p.download_url for p in plugins),
            trusted_hosts=self._effective_trusted_hosts(),
        )
        if not unknown:
            return True

        examples: list[str] = []
        for host in unknown:
            for plugin in plugins:
                if hostname_from_url(plugin.download_url) == host:
                    examples.append(f"{host}\n  e.g. {plugin.download_url}")
                    break
            else:
                examples.append(host)

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Untrusted download hosts")
        box.setText(
            "Some selected plugins download from hosts that are not on the "
            "built-in allowlist (raw.githubusercontent.com / "
            "gist.githubusercontent.com)."
        )
        box.setInformativeText(
            "Approve to continue this install:\n\n" + "\n\n".join(examples)
        )
        once_btn = box.addButton("Trust once", QMessageBox.ButtonRole.AcceptRole)
        always_btn = box.addButton("Always trust", QMessageBox.ButtonRole.YesRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        clicked = box.clickedButton()
        if clicked is once_btn:
            self._session_trusted_hosts.update(unknown)
            return True
        if clicked is always_btn:
            for host in unknown:
                add_trusted_download_host(host)
            return True
        return False

    def _plugin_key(self, plugin: Plugin) -> tuple[str, str]:
        return (plugin.name, plugin.download_url)

    def _plugin_from_item(self, item: QTreeWidgetItem) -> Plugin | None:
        value = item.data(0, Qt.ItemDataRole.UserRole)
        return value if isinstance(value, Plugin) else None

    def _fill_plugin_item(self, item: QTreeWidgetItem, plugin: Plugin) -> None:
        item.setFlags(
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsUserCheckable
        )
        item.setData(0, Qt.ItemDataRole.UserRole, plugin)
        key = self._plugin_key(plugin)
        item.setCheckState(
            0,
            Qt.CheckState.Checked if key in self._checked else Qt.CheckState.Unchecked,
        )
        has_update = plugin.filename in self._updates
        is_fixed = plugin.filename in self._fixed
        if has_update:
            display_name = f"{UPDATE_INDICATOR}{plugin.name}"
        elif is_fixed:
            display_name = f"{FIX_INDICATOR}{plugin.name}"
        else:
            display_name = plugin.name
        source_label = SOURCE_LABELS.get(plugin.source_id, plugin.source_id)
        version_text = plugin.version.strip() if plugin.version.strip() else "—"
        values = (
            display_name,
            version_text,
            plugin.visibility.value,
            format_categories(plugin.categories),
            plugin.last_update,
            plugin.author,
            source_label,
            plugin.comments,
            "Yes" if plugin.filename in self._installed else "No",
        )
        for col, value in enumerate(values, start=1):
            item.setText(col, value)
        if has_update:
            tip = "Update available — catalog source differs from what was installed"
            if is_fixed:
                kinds = fix_kinds_for_filename(plugin.filename)
                kind_txt = ", ".join(kinds) if kinds else "safe install-time fix"
                tip = f"{tip}. Also fixed previously: {kind_txt}"
            item.setToolTip(COL_NAME, tip)
        elif is_fixed:
            kinds = fix_kinds_for_filename(plugin.filename)
            kind_txt = ", ".join(kinds) if kinds else "safe install-time fix"
            item.setToolTip(
                COL_NAME,
                f"Installed with safe fix ({kind_txt}). ClamAV ran before rewrite.",
            )
        elif plugin.warning:
            item.setToolTip(COL_NAME, "Discouraged by upstream wiki")
        elif item.parent() is not None:
            item.setToolTip(
                COL_NAME,
                f"Alternate fork by {plugin.author} (same install filename)",
            )

    def refresh_catalog(self, force_refresh: bool = True) -> None:
        if self._catalog_worker and self._catalog_worker.isRunning():
            return
        if self._category_worker and self._category_worker.isRunning():
            return
        self._force_category_refresh = force_refresh
        self.refresh_btn.setEnabled(False)
        self.status_label.setText("Fetching catalog…")
        worker = CatalogWorker(force_refresh=force_refresh)
        self._catalog_worker = worker
        worker.finished_ok.connect(self._on_catalog_loaded)
        worker.failed.connect(self._on_catalog_failed)
        worker.start()

    def _on_catalog_loaded(self, plugins: list, summary: str = "") -> None:
        self._all_plugins = plugins
        self.apply_filters()
        public = sum(1 for p in plugins if p.visibility == Visibility.PUBLIC)
        private = sum(1 for p in plugins if p.visibility == Visibility.PRIVATE)
        counts = f" — {summary}" if summary else ""
        self._status_base = (
            f"Loaded {len(plugins)} plugins "
            f"({public} public, {private} private){counts}"
        )
        self.status_label.setText(self._status_base)
        self._start_category_enrichment(force_refresh=self._force_category_refresh)

    def _start_category_enrichment(self, force_refresh: bool = False) -> None:
        if self._category_worker and self._category_worker.isRunning():
            return
        if not self._all_plugins:
            self.refresh_btn.setEnabled(True)
            self._start_update_check()
            return
        self.refresh_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(self._all_plugins))
        self.progress.setValue(0)
        self.status_label.setText(
            f"Resolving categories… 0/{len(self._all_plugins)}"
        )
        worker = CategoryWorker(
            self._all_plugins,
            force_refresh=force_refresh,
            trusted_hosts=self._effective_trusted_hosts(),
        )
        self._category_worker = worker
        worker.progress.connect(self._on_category_progress)
        worker.finished_ok.connect(self._on_categories_loaded)
        worker.failed.connect(self._on_categories_failed)
        worker.start()

    def _on_category_progress(self, done: int, total: int) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.status_label.setText(f"Resolving categories… {done}/{total}")

    def _on_categories_loaded(self, plugins: list) -> None:
        self._all_plugins = plugins
        self.refresh_btn.setEnabled(True)
        self.progress.setVisible(False)
        categorized = sum(1 for p in plugins if p.categories)
        self._status_base = f"{self._status_base} — {categorized} categorized"
        self.apply_filters()
        self._refresh_status_label()
        self._start_update_check()

    def _on_categories_failed(self, message: str) -> None:
        self.refresh_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.status_label.setText(f"{self._status_base} — category resolve failed")
        QMessageBox.warning(self, "Category resolve", message)
        self._start_update_check()

    def _on_catalog_failed(self, message: str) -> None:
        self.refresh_btn.setEnabled(True)
        self.status_label.setText("Catalog fetch failed")
        QMessageBox.critical(self, "Catalog error", message)

    def apply_filters(self) -> None:
        visibility = self.visibility_combo.currentData()
        category = self.category_combo.currentData()
        self._visible_plugins = filter_plugins(
            self._all_plugins,
            query=self.filter_edit.text(),
            visibility=visibility,
            hide_discouraged=self.hide_discouraged.isChecked(),
            category=category,
        )
        show_note = visibility in (None, Visibility.PRIVATE)
        self.private_note.setVisible(show_note)
        self._rebuild_tree()
        if self._all_plugins and not self._visible_plugins:
            self.status_label.setText("No plugins match the current filters.")
        elif self._all_plugins:
            self._refresh_status_label()

    def _refresh_status_label(self) -> None:
        if self._all_plugins and not self._visible_plugins:
            return
        text = self._status_base
        if self._status_updates_suffix:
            text = f"{text}{self._status_updates_suffix}"
        self.status_label.setText(text)

    def _set_busy_for_install(self, busy: bool) -> None:
        self.install_btn.setEnabled(not busy)
        self.uninstall_btn.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self._sync_update_all_button(busy=busy)

    def _sync_update_all_button(self, *, busy: bool | None = None) -> None:
        if busy is None:
            busy = bool(
                (self._install_worker and self._install_worker.isRunning())
                or (self._uninstall_worker and self._uninstall_worker.isRunning())
                or (self._catalog_worker and self._catalog_worker.isRunning())
                or (self._update_worker and self._update_worker.isRunning())
            )
        self.update_all_btn.setEnabled(bool(self._updates) and not busy)

    def _start_update_check(self) -> None:
        if self._update_worker and self._update_worker.isRunning():
            return
        if not self._all_plugins:
            self._updates = set()
            self._status_updates_suffix = ""
            self._sync_update_all_button()
            return
        worker = UpdateCheckWorker(
            self._engines_dir,
            list(self._all_plugins),
            trusted_hosts=self._effective_trusted_hosts(),
        )
        self._update_worker = worker
        self._sync_update_all_button(busy=True)
        worker.finished_ok.connect(self._on_updates_checked)
        worker.failed.connect(self._on_updates_failed)
        worker.start()

    def _on_updates_checked(self, outdated: object) -> None:
        self._updates = set(outdated) if isinstance(outdated, set) else set()
        count = len(self._updates)
        self._status_updates_suffix = (
            f" — {count} update{'s' if count != 1 else ''}" if count else ""
        )
        self._rebuild_tree()
        self._refresh_status_label()
        self._sync_update_all_button()

    def _on_updates_failed(self, message: str) -> None:
        self.status_label.setText(f"{self._status_base} — update check failed")
        self._sync_update_all_button()
        if message:
            QMessageBox.warning(self, "Update check", message)

    def _on_header_section_clicked(self, section: int) -> None:
        """Toggle ascending/descending sort for the clicked column."""
        if section < 0 or section >= len(COLS):
            return
        if self._sort_column == section:
            self._sort_order = (
                Qt.SortOrder.DescendingOrder
                if self._sort_order == Qt.SortOrder.AscendingOrder
                else Qt.SortOrder.AscendingOrder
            )
        else:
            self._sort_column = section
            self._sort_order = Qt.SortOrder.AscendingOrder
        self._apply_tree_sort()

    def _apply_tree_sort(self) -> None:
        if self._sort_column is None:
            return
        header = self.tree.header()
        header.setSortIndicator(self._sort_column, self._sort_order)
        self.tree.sortItems(self._sort_column, self._sort_order)

    def _rebuild_tree(self) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()
        for group in group_plugins_for_display(self._visible_plugins):
            parent = PluginTreeItem(self.tree)
            self._fill_plugin_item(parent, group.primary)
            for alternate in group.alternates:
                child = PluginTreeItem(parent)
                self._fill_plugin_item(child, alternate)
            parent.setExpanded(False)
        self.tree.blockSignals(False)
        self._apply_tree_sort()

    def _uncheck_filename_conflicts(
        self,
        item: QTreeWidgetItem,
        plugin: Plugin,
    ) -> None:
        """Uncheck other checked rows that would write the same .py basename."""
        target = plugin.filename
        root = self.tree.invisibleRootItem()
        stack = [root.child(i) for i in range(root.childCount())]
        while stack:
            current = stack.pop()
            for i in range(current.childCount()):
                stack.append(current.child(i))
            if current is item:
                continue
            other = self._plugin_from_item(current)
            if other is None or other.filename != target:
                continue
            if current.checkState(0) != Qt.CheckState.Checked:
                continue
            current.setCheckState(0, Qt.CheckState.Unchecked)
            self._checked.discard(self._plugin_key(other))

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if column != 0:
            return
        plugin = self._plugin_from_item(item)
        if plugin is None:
            return
        key = self._plugin_key(plugin)
        if item.checkState(0) == Qt.CheckState.Checked:
            self._checked.add(key)
            self.tree.blockSignals(True)
            self._uncheck_filename_conflicts(item, plugin)
            self.tree.blockSignals(False)
        else:
            self._checked.discard(key)

    def select_all_visible(self) -> None:
        """Check top-level (preferred) rows only — not collapsed alternates."""
        self.tree.blockSignals(True)
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            plugin = self._plugin_from_item(item)
            if plugin is None or not plugin_included_in_select_all(plugin):
                continue
            self._checked.add(self._plugin_key(plugin))
            item.setCheckState(0, Qt.CheckState.Checked)
            self._uncheck_filename_conflicts(item, plugin)
        self.tree.blockSignals(False)

    def clear_selection(self) -> None:
        self._checked.clear()
        self.tree.blockSignals(True)
        root = self.tree.invisibleRootItem()
        stack = [root.child(i) for i in range(root.childCount())]
        while stack:
            item = stack.pop()
            for i in range(item.childCount()):
                stack.append(item.child(i))
            item.setCheckState(0, Qt.CheckState.Unchecked)
        self.tree.blockSignals(False)

    def _selected_plugins(self) -> list[Plugin]:
        selected: list[Plugin] = []
        for plugin in self._all_plugins:
            if self._plugin_key(plugin) in self._checked:
                selected.append(plugin)
        return selected

    def install_selected(self) -> None:
        plugins = self._selected_plugins()
        if not plugins:
            QMessageBox.information(self, "Nothing selected", "Select at least one plugin.")
            return
        self._start_install(plugins)

    def uninstall_selected(self) -> None:
        plugins = self._selected_plugins()
        if not plugins:
            QMessageBox.information(self, "Nothing selected", "Select at least one plugin.")
            return

        # Dedupe by filename for the confirm message (same as uninstall API).
        by_filename: dict[str, Plugin] = {}
        for plugin in plugins:
            by_filename.setdefault(plugin.filename, plugin)
        installed = [
            p for p in by_filename.values() if p.filename in self._installed
        ]
        if not installed:
            QMessageBox.information(
                self,
                "Nothing installed",
                "None of the selected plugins are installed in the current "
                "engines directory.",
            )
            return

        names = _format_name_list([p.name for p in installed])
        answer = QMessageBox.question(
            self,
            "Uninstall selected",
            (
                f"Permanently remove {len(installed)} installed engine(s) "
                f"from:\n{self._engines_dir}\n\n"
                f"{names}\n\n"
                "This deletes the .py file, any stem-named config "
                "(e.g. jackett.json), leftover .tmp files, matching "
                "bytecode, and this app’s install provenance. "
                "This cannot be undone."
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_uninstall(installed)

    def update_all_outdated(self) -> None:
        if not self._updates:
            return
        plugins = plugins_for_updates(self._updates, self._all_plugins)
        if not plugins:
            QMessageBox.information(
                self,
                "Nothing to update",
                "No catalog matches were found for the outdated engines.",
            )
            return
        answer = QMessageBox.question(
            self,
            "Update all",
            f"Update {len(plugins)} plugin(s) from the catalog?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_install(plugins)

    def _prompt_clamscan_consent(self, session: ClamAvSession) -> bool:
        """
        Ask whether to use slow clamscan when clamd is unavailable.

        Returns False if the user cancels the whole install.
        """
        if not session.needs_clamscan_consent():
            return True

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("ClamAV virus scan")
        box.setText(
            "ClamAV daemon (clamd) is not running or not reachable.\n\n"
            "One-shot clamscan reloads the virus database into memory for every "
            "file and can use a large amount of RAM — avoid it for bulk installs. "
            "Prefer starting clamd, or skip the virus scan "
            "(static safety checks still run)."
        )
        use_btn = box.addButton(
            "Use clamscan",
            QMessageBox.ButtonRole.AcceptRole,
        )
        skip_btn = box.addButton(
            "Skip virus scan",
            QMessageBox.ButtonRole.DestructiveRole,
        )
        cancel_btn = box.addButton(QMessageBox.StandardButton.Cancel)
        remember = QCheckBox("Remember this choice")
        box.setCheckBox(remember)
        box.exec()

        clicked = box.clickedButton()
        if clicked is cancel_btn or clicked is None:
            return False
        if clicked is use_btn:
            session.grant_clamscan_fallback()
            if remember.isChecked():
                set_clamav_allow_clamscan_fallback(True)
            return True
        if clicked is skip_btn:
            session.deny_clamscan_fallback()
            if remember.isChecked():
                set_clamav_allow_clamscan_fallback(False)
            return True
        return False

    def _start_install(self, plugins: list[Plugin]) -> None:
        if self._install_worker and self._install_worker.isRunning():
            return
        if self._uninstall_worker and self._uninstall_worker.isRunning():
            return

        session = build_clamav_session()
        if not self._prompt_clamscan_consent(session):
            return
        if not self._prompt_untrusted_hosts(plugins):
            return

        self._engines_dir = resolve_install_dir(preferred=self._engines_dir)
        self._set_busy_for_install(True)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(plugins))
        self.progress.setValue(0)
        self.status_label.setText(f"Installing {len(plugins)} plugin(s)…")

        worker = InstallWorker(
            plugins,
            self._engines_dir,
            clamav_session=session,
            auto_fix=self.auto_fix_cb.isChecked(),
            catalog=list(self._all_plugins),
            trusted_hosts=self._effective_trusted_hosts(),
            allow_ast_without_clamav=self.ast_without_clam_cb.isChecked(),
        )
        self._install_worker = worker
        worker.progress.connect(self._on_install_progress)
        worker.finished_ok.connect(self._on_install_finished)
        worker.failed.connect(self._on_install_failed)
        worker.start()

    def _start_uninstall(self, plugins: list[Plugin]) -> None:
        if self._install_worker and self._install_worker.isRunning():
            return
        if self._uninstall_worker and self._uninstall_worker.isRunning():
            return

        self._set_busy_for_install(True)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(plugins))
        self.progress.setValue(0)
        self.status_label.setText(f"Uninstalling {len(plugins)} plugin(s)…")

        worker = UninstallWorker(plugins, self._engines_dir)
        self._uninstall_worker = worker
        worker.progress.connect(self._on_install_progress)
        worker.finished_ok.connect(self._on_uninstall_finished)
        worker.failed.connect(self._on_uninstall_failed)
        worker.start()

    def _set_status(self, text: str) -> None:
        """Update status without letting long lines grow the window width."""
        self.status_label.setToolTip(text)
        display = text if len(text) <= 96 else f"{text[:93]}…"
        self.status_label.setText(display)

    def _on_install_progress(self, done: int, total: int, message: str) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        # Prefer short progress text; full detail stays in the tooltip.
        short = message
        if ": " in message:
            name, _, rest = message.partition(": ")
            if rest.startswith("Safety check") or len(rest) > 40:
                short = f"{name}: blocked" if "blocked" in rest.lower() else f"{name}: {rest[:24]}…"
        self._set_status(f"[{done}/{total}] {short}")

    def _on_install_finished(self, results: list) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        ok = sum(1 for r in results if r.ok)
        fail = len(results) - ok
        self._refresh_installed()
        self._rebuild_tree()
        self._set_status(f"Installed {ok}, failed {fail}")

        title, msg, icon_kind = format_install_summary(
            results,
            self._engines_dir,
            alternates_by_filename=alternates_from_catalog(self._all_plugins),
        )
        dialog = InstallSummaryDialog(title, msg, icon_kind, parent=self)
        dialog.exec()
        self._start_update_check()

    def _on_install_failed(self, message: str) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        self._set_status("Install error")
        QMessageBox.critical(self, "Install error", message)

    def _on_uninstall_finished(self, results: list) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        ok = sum(1 for r in results if r.ok)
        fail = len(results) - ok
        self._refresh_installed()
        self._rebuild_tree()
        self._set_status(f"Uninstalled {ok}, failed {fail}")

        title, msg, icon_kind = format_uninstall_summary(results, self._engines_dir)
        dialog = InstallSummaryDialog(title, msg, icon_kind, parent=self)
        dialog.exec()
        self._start_update_check()

    def _on_uninstall_failed(self, message: str) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        self._set_status("Uninstall error")
        QMessageBox.critical(self, "Uninstall error", message)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        for worker in (
            self._catalog_worker,
            self._category_worker,
            self._install_worker,
            self._uninstall_worker,
            self._update_worker,
        ):
            if worker is not None and worker.isRunning():
                worker.wait(10000)
        super().closeEvent(event)


def run_app() -> int:
    import sys

    app = QApplication(sys.argv)
    app.setApplicationName("qbit-plugin-dl")
    app.setApplicationDisplayName("qBittorrent Plugin Downloader")
    app.setOrganizationName("qbit-plugin-dl")
    app.setOrganizationDomain("qbit-plugin-dl.local")
    app.setDesktopFileName("qbit-plugin-dl")
    app.setApplicationVersion(__version__)
    icon = load_app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)

    if QApplication.platformName() not in {"offscreen", "minimal"}:
        if not safety_accepted():
            dialog = DisclaimerDialog()
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return 1
            set_safety_accepted(True)

    window = MainWindow(icon=icon)
    window.show()
    return app.exec()
