"""Install and uninstall summaries, and which plugins a selection includes."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from qbit_plugin_dl.audit import SEVERITY_WARN
from qbit_plugin_dl.audit_clamav import (
    format_clamav_backend_label,
)
from qbit_plugin_dl.catalog import (
    Plugin,
)
from qbit_plugin_dl.fix import FIX_INDICATOR
from qbit_plugin_dl.gui.notes import (
    _COLLAPSED_WARN_LABELS,
    _alternate_hint,
    _format_name_list,
    _safety_group_key,
    _short_network_error,
    _still_blocked_reason,
)
from qbit_plugin_dl.install import (
    MAX_PLUGIN_BYTES,
    InstallResult,
    UninstallResult,
)


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
    warned_plugins: set[str] = set()
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
            warned_plugins.add(result.plugin.name)
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
        http_client_roots = {"requests", "httpx", "aiohttp"}
        grouped: dict[str, list[str]] = defaultdict(list)
        labels: dict[str, str] = {}
        for result in safety_blocked:
            key, label = _safety_group_key(result)
            labels[key] = label
            grouped[key].append(result.plugin.name)
        http_keys = {f"import:{root}" for root in http_client_roots}
        if not http_keys & grouped.keys():
            lines.append(
                "These engines use APIs that qBittorrent search plugins should not need."
            )
        http_note_shown = False
        for key in sorted(grouped.keys()):
            names = grouped[key]
            lines.append("")
            lines.append(f"  {labels[key]} ({len(names)})")
            lines.append(f"    {_format_name_list(names)}")
            # Explain under the group it applies to, not above every group.
            if key in http_keys and not http_note_shown:
                lines.append(
                    "    Third-party HTTP libraries (requests/httpx/aiohttp) are not "
                    "available inside qBittorrent — engines must use urllib / helpers."
                )
                http_note_shown = True
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

    if warned_plugins:
        count = len(warned_plugins)
        lines.append("")
        lines.append(
            f"Notes on {count} installed plugin{'s' if count != 1 else ''} "
            "— installed anyway"
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


def plugin_too_large(plugin: Plugin) -> bool:
    """True when the catalog lists a size the download limit would reject."""
    return plugin.size_bytes is not None and plugin.size_bytes > MAX_PLUGIN_BYTES


def plugin_included_in_select_all(plugin: Plugin) -> bool:
    """Whether Select all should check this plugin (skips discouraged / too large)."""
    return not plugin.warning and not plugin_too_large(plugin)
