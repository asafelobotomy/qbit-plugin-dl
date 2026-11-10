"""Download, audit, fix and write selected plugins into an engines directory.

Engine-directory helpers live in ``engine_dirs`` and removal in ``uninstall``; both are
re-exported here so existing imports keep working.
"""

from __future__ import annotations

import asyncio
from collections.abc import Collection, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import httpx

from qbit_plugin_dl.audit import audit_plugin_bytes
from qbit_plugin_dl.audit_clamav import ClamAvSession
from qbit_plugin_dl.catalog import Plugin
from qbit_plugin_dl.engine_dirs import (
    candidate_engine_dirs,
    detect_engine_dirs,
    engine_dir_kind,
    format_engine_dir_label,
    list_installed_filenames,
    resolve_install_dir,
    resolve_plugin_dest,
    validate_plugin_filename,
)
from qbit_plugin_dl.fetch import (
    MAX_PLUGIN_BYTES,
    MAX_REDIRECTS,
    FetchError,
    fetch_with_github_recovery_async,
    require_https_url,
    untrusted_redirect,
)
from qbit_plugin_dl.fix import (
    FixKind,
    FixReport,
    alternates_from_catalog,
    audit_clamav_then_static,
    ranked_alternates,
    try_ast_fix_after_clamav,
)
from qbit_plugin_dl.install_results import (
    InstallResult,
    ProgressCallback,
    _fix_report_for_failure,
    _fix_report_for_write,
)
from qbit_plugin_dl.paths import atomic_write_bytes
from qbit_plugin_dl.provenance import (
    content_sha,
    content_sha256,
    record_install_provenance,
)
from qbit_plugin_dl.uninstall import (
    UninstallResult,
    companion_paths_for_engine,
    uninstall_plugin,
    uninstall_plugins,
)


async def _download_one(
    client: httpx.AsyncClient,
    plugin: Plugin,
    engines_dir: Path,
    semaphore: asyncio.Semaphore,
    clamav_session: ClamAvSession | None,
    *,
    auto_fix: bool,
    alternates_by_filename: Mapping[str, Sequence[Plugin]],
    trusted_hosts: Collection[str] | None = None,
    allow_ast_without_clamav: bool = False,
) -> InstallResult:
    async with semaphore:
        return await _install_plugin_with_optional_fix(
            client,
            plugin,
            engines_dir,
            clamav_session,
            auto_fix=auto_fix,
            alternates_by_filename=alternates_by_filename,
            trusted_hosts=trusted_hosts,
            allow_ast_without_clamav=allow_ast_without_clamav,
        )


async def _fetch_plugin_bytes(
    client: httpx.AsyncClient,
    plugin: Plugin,
    *,
    trusted_hosts: Collection[str] | None = None,
) -> tuple[bytes | None, str | None, FetchError | None]:
    """Return (content, error_message, fetch_error)."""
    result = await fetch_with_github_recovery_async(
        client,
        plugin.download_url,
        basename=plugin.filename,
        max_bytes=MAX_PLUGIN_BYTES,
        trusted_hosts=trusted_hosts,
    )
    if isinstance(result, FetchError):
        return None, result.message, result
    return result.content, None, None


def _write_engine(
    dest: Path,
    content: bytes,
    plugin: Plugin,
    *,
    engines_dir: Path,
    fix: FixReport | None,
    source_bytes: bytes | None = None,
    install_filename: str | None = None,
) -> InstallResult:
    provenance_error: str | None = None
    provenance_name = install_filename or plugin.filename
    try:
        # Re-validate containment immediately before replace (symlink TOCTOU).
        dest = resolve_plugin_dest(engines_dir, provenance_name)
        atomic_write_bytes(dest, content)
    except (OSError, ValueError) as exc:
        # Disk full, read-only dir, name too long, containment change, …:
        # fail this plugin only, never the whole batch.
        return InstallResult(
            plugin=plugin,
            ok=False,
            path=None,
            error=f"Could not write {provenance_name}: {exc}",
            fix=fix,
        )

    written_sha = content_sha(content)
    written_sha256 = content_sha256(content)
    source_sha = None
    source_sha256 = None
    if fix and fix.rewritten and source_bytes is not None:
        source_sha = content_sha(source_bytes)
        source_sha256 = content_sha256(source_bytes)
    try:
        kinds = [k.value for k in (fix.kinds if fix else ())]
        record_install_provenance(
            provenance_name,
            download_url=plugin.download_url,
            sha=written_sha,
            sha256=written_sha256,
            fixed=bool(fix and fix.applied),
            rewritten=bool(fix and fix.rewritten),
            fix_kinds=kinds,
            source_sha=source_sha,
            source_sha256=source_sha256,
        )
    except OSError as exc:
        provenance_error = str(exc)
    return InstallResult(
        plugin=plugin,
        ok=True,
        path=dest,
        fix=fix,
        provenance_error=provenance_error,
    )


async def _install_plugin_with_optional_fix(
    client: httpx.AsyncClient,
    plugin: Plugin,
    engines_dir: Path,
    clamav_session: ClamAvSession | None,
    *,
    auto_fix: bool,
    alternates_by_filename: Mapping[str, Sequence[Plugin]],
    trusted_hosts: Collection[str] | None = None,
    allow_ast_without_clamav: bool = False,
) -> InstallResult:
    tried_urls: list[str] = []
    current = plugin
    alternate_used = False
    install_filename = plugin.filename

    while True:
        tried_urls.append(current.download_url)
        ast_kinds_this_round: list[FixKind] = []
        source_bytes_before_ast: bytes | None = None
        try:
            dest = resolve_plugin_dest(engines_dir, install_filename)
        except ValueError as exc:
            return InstallResult(
                plugin=plugin,
                ok=False,
                path=None,
                error=str(exc),
            )

        content, fetch_error, fetch_err = await _fetch_plugin_bytes(
            client, current, trusted_hosts=trusted_hosts
        )
        if content is None:
            # Network / size / host failure — try alternate if auto_fix.
            if auto_fix:
                nxt = ranked_alternates(
                    current,
                    alternates_by_filename,
                    tried_urls=set(tried_urls),
                )
                if nxt:
                    current = nxt[0]
                    alternate_used = True
                    continue
            return InstallResult(
                plugin=plugin,
                ok=False,
                path=None,
                error=fetch_error or "Download failed",
                fix=_fix_report_for_failure(
                    alternate_used=alternate_used,
                    ast_kinds=(),
                    tried_urls=tried_urls,
                    final_url=current.download_url,
                ),
                untrusted_redirect=untrusted_redirect(fetch_err, current.download_url),
            )

        if auto_fix:
            report = await asyncio.to_thread(
                audit_clamav_then_static,
                content,
                filename=install_filename,
                clamav_session=clamav_session,
            )
            if report.clamav_status == "infected":
                return InstallResult(
                    plugin=current,
                    ok=False,
                    path=None,
                    error=report.summary_error(),
                    audit=report,
                    fix=_fix_report_for_failure(
                        alternate_used=alternate_used,
                        ast_kinds=(),
                        tried_urls=tried_urls,
                        final_url=current.download_url,
                    ),
                )

            if report.blocked:
                source_bytes_before_ast = content
                content, report, ast_kinds_this_round = await asyncio.to_thread(
                    try_ast_fix_after_clamav,
                    content,
                    filename=install_filename,
                    clamav_session=clamav_session,
                    prior_report=report,
                    allow_ast_without_clamav=allow_ast_without_clamav,
                )

            # Post-rewrite infection: never alternate or write.
            if report.clamav_status == "infected":
                return InstallResult(
                    plugin=current,
                    ok=False,
                    path=None,
                    error=report.summary_error(),
                    audit=report,
                    fix=_fix_report_for_failure(
                        alternate_used=alternate_used,
                        ast_kinds=ast_kinds_this_round,
                        tried_urls=tried_urls,
                        final_url=current.download_url,
                    ),
                )

            if not report.blocked:
                fix_report = _fix_report_for_write(
                    alternate_used=alternate_used,
                    ast_kinds=ast_kinds_this_round,
                    tried_urls=tried_urls,
                    final_url=current.download_url,
                )
                result = _write_engine(
                    dest,
                    content,
                    current,
                    engines_dir=engines_dir,
                    fix=fix_report,
                    source_bytes=source_bytes_before_ast,
                    install_filename=install_filename,
                )
                if not result.ok:
                    return replace(result, audit=report)
                return InstallResult(
                    plugin=current,
                    ok=True,
                    path=result.path,
                    audit=report,
                    fix=fix_report,
                    provenance_error=result.provenance_error,
                )

            # Still blocked — try next alternate (discard this round's AST kinds).
            nxt = ranked_alternates(
                current,
                alternates_by_filename,
                tried_urls=set(tried_urls),
            )
            if nxt:
                current = nxt[0]
                alternate_used = True
                continue
            return InstallResult(
                plugin=plugin,
                ok=False,
                path=None,
                error=report.summary_error(),
                audit=report,
                fix=_fix_report_for_failure(
                    alternate_used=alternate_used,
                    ast_kinds=ast_kinds_this_round,
                    tried_urls=tried_urls,
                    final_url=current.download_url,
                ),
            )

        # auto_fix off — legacy static-then-ClamAV path.
        report = await asyncio.to_thread(
            audit_plugin_bytes,
            content,
            filename=install_filename,
            clamav_session=clamav_session,
        )
        if report.blocked:
            return InstallResult(
                plugin=current,
                ok=False,
                path=None,
                error=report.summary_error(),
                audit=report,
            )
        result = _write_engine(
            dest,
            content,
            current,
            engines_dir=engines_dir,
            fix=None,
            install_filename=install_filename,
        )
        if not result.ok:
            return replace(result, audit=report)
        return InstallResult(
            plugin=current,
            ok=True,
            path=result.path,
            audit=report,
            provenance_error=result.provenance_error,
        )


async def install_plugins_async(
    plugins: Sequence[Plugin],
    engines_dir: Path,
    *,
    concurrency: int = 6,
    on_progress: ProgressCallback | None = None,
    client: httpx.AsyncClient | None = None,
    clamav_session: ClamAvSession | None = None,
    auto_fix: bool = False,
    catalog: Sequence[Plugin] | None = None,
    filename_alternates: Mapping[str, Sequence[Plugin]] | None = None,
    trusted_hosts: Collection[str] | None = None,
    allow_ast_without_clamav: bool = False,
) -> list[InstallResult]:
    """Download selected plugins into engines_dir concurrently."""
    engines_dir.mkdir(parents=True, exist_ok=True)
    total = len(plugins)
    if total == 0:
        return []

    if filename_alternates is None:
        if catalog is not None:
            filename_alternates = alternates_from_catalog(catalog)
        else:
            filename_alternates = alternates_from_catalog(plugins)

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=45.0,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        )

    semaphore = asyncio.Semaphore(concurrency)
    results_by_index: dict[int, InstallResult] = {}
    completed = 0

    async def _run_one(index: int, plugin: Plugin) -> tuple[int, InstallResult]:
        try:
            result = await _download_one(
                client,
                plugin,
                engines_dir,
                semaphore,
                clamav_session,
                auto_fix=auto_fix,
                alternates_by_filename=filename_alternates,
                trusted_hosts=trusted_hosts,
                allow_ast_without_clamav=allow_ast_without_clamav,
            )
        except Exception as exc:  # noqa: BLE001 — isolate one plugin's failure
            result = InstallResult(
                plugin=plugin,
                ok=False,
                path=None,
                error=f"Unexpected error: {type(exc).__name__}: {exc}",
            )
        return index, result

    try:
        tasks = [
            asyncio.create_task(_run_one(index, plugin))
            for index, plugin in enumerate(plugins)
        ]
        for task in asyncio.as_completed(tasks):
            index, result = await task
            results_by_index[index] = result
            completed += 1
            if on_progress is not None:
                on_progress(completed, total, result.plugin, result)
    finally:
        if owns_client:
            await client.aclose()

    return [results_by_index[i] for i in range(total)]


def install_plugins(
    plugins: Sequence[Plugin],
    engines_dir: Path,
    *,
    concurrency: int = 6,
    on_progress: ProgressCallback | None = None,
    clamav_session: ClamAvSession | None = None,
    auto_fix: bool = False,
    catalog: Sequence[Plugin] | None = None,
    filename_alternates: Mapping[str, Sequence[Plugin]] | None = None,
    trusted_hosts: Collection[str] | None = None,
    allow_ast_without_clamav: bool = False,
) -> list[InstallResult]:
    """Synchronous wrapper around install_plugins_async."""
    return asyncio.run(
        install_plugins_async(
            plugins,
            engines_dir,
            concurrency=concurrency,
            on_progress=on_progress,
            clamav_session=clamav_session,
            auto_fix=auto_fix,
            catalog=catalog,
            filename_alternates=filename_alternates,
            trusted_hosts=trusted_hosts,
            allow_ast_without_clamav=allow_ast_without_clamav,
        )
    )


__all__ = [
    "MAX_PLUGIN_BYTES",
    "InstallResult",
    "UninstallResult",
    "candidate_engine_dirs",
    "companion_paths_for_engine",
    "detect_engine_dirs",
    "engine_dir_kind",
    "format_engine_dir_label",
    "install_plugins",
    "install_plugins_async",
    "list_installed_filenames",
    "require_https_url",
    "resolve_install_dir",
    "resolve_plugin_dest",
    "uninstall_plugin",
    "uninstall_plugins",
    "validate_plugin_filename",
]
