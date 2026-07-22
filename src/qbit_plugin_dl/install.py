"""Detect qBittorrent engines directories and download selected plugins."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx

from qbit_plugin_dl.audit import AuditReport, audit_plugin_bytes
from qbit_plugin_dl.audit_clamav import ClamAvSession
from qbit_plugin_dl.catalog import Plugin
from qbit_plugin_dl.fetch import (
    MAX_PLUGIN_BYTES,
    MAX_REDIRECTS,
    FetchError,
    fetch_plugin_bytes_async,
    require_https_url,
)
from qbit_plugin_dl.fix import (
    FixKind,
    FixReport,
    alternates_from_catalog,
    audit_clamav_then_static,
    ranked_alternates,
    try_ast_fix_after_clamav,
)
from qbit_plugin_dl.provenance import (
    content_sha,
    content_sha256,
    record_install_provenance,
    remove_install_provenance,
)


def candidate_engine_dirs(home: Path | None = None) -> list[Path]:
    """Return known Linux engines paths in preference order."""
    home = home or Path.home()
    xdg_data = Path(os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share")))
    return [
        home
        / ".var"
        / "app"
        / "org.qbittorrent.qBittorrent"
        / "data"
        / "qBittorrent"
        / "nova3"
        / "engines",
        xdg_data / "qBittorrent" / "nova3" / "engines",
        xdg_data / "data" / "qBittorrent" / "nova3" / "engines",
    ]


def detect_engine_dirs(home: Path | None = None) -> list[Path]:
    """Return existing engines directories (may be empty)."""
    return [path for path in candidate_engine_dirs(home) if path.is_dir()]


def resolve_install_dir(home: Path | None = None, preferred: Path | None = None) -> Path:
    """
    Choose an install directory.

    Prefer an explicit path, else the first existing candidate, else create the
    modern native path.
    """
    if preferred is not None:
        preferred.mkdir(parents=True, exist_ok=True)
        return preferred

    existing = detect_engine_dirs(home)
    if existing:
        return existing[0]

    target = candidate_engine_dirs(home)[1]
    target.mkdir(parents=True, exist_ok=True)
    return target


def engine_dir_kind(path: Path, home: Path | None = None) -> str:
    """Classify an engines path as Flatpak, Native, Legacy, or Custom."""
    candidates = candidate_engine_dirs(home)
    resolved = path.expanduser()
    try:
        resolved = resolved.resolve()
    except OSError:
        pass
    labels = ("Flatpak", "Native", "Legacy")
    for label, candidate in zip(labels, candidates, strict=True):
        try:
            if resolved == candidate.resolve():
                return label
        except OSError:
            if resolved == candidate:
                return label
    return "Custom"


def format_engine_dir_label(
    path: Path,
    *,
    will_create: bool = False,
    home: Path | None = None,
) -> str:
    """Human-readable combo label for an engines directory."""
    kind = engine_dir_kind(path, home=home)
    label = f"{kind} — {path}"
    if will_create:
        label = f"{label} (will create)"
    return label


def list_installed_filenames(engines_dir: Path) -> set[str]:
    if not engines_dir.is_dir():
        return set()
    return {path.name for path in engines_dir.glob("*.py")}


def validate_plugin_filename(name: str) -> str:
    """
    Require a safe .py basename with no path components.

    Raises ValueError when the name is empty, not a .py file, or contains
    separators / parent references.
    """
    if not name or name in {".", ".."}:
        raise ValueError("Invalid plugin filename")
    if "/" in name or "\\" in name or name != Path(name).name:
        raise ValueError(f"Plugin filename must be a basename: {name!r}")
    if ".." in Path(name).parts:
        raise ValueError(f"Plugin filename must not contain '..': {name!r}")
    if not name.endswith(".py"):
        raise ValueError(f"Plugin filename must end with .py: {name!r}")
    return name


def resolve_plugin_dest(engines_dir: Path, filename: str) -> Path:
    """Return dest path under engines_dir after validating containment."""
    safe_name = validate_plugin_filename(filename)
    engines_root = engines_dir.resolve()
    dest = (engines_dir / safe_name).resolve()
    try:
        dest.relative_to(engines_root)
    except ValueError as exc:
        raise ValueError(
            f"Refusing to write outside engines dir: {dest}"
        ) from exc
    return dest


@dataclass(frozen=True, slots=True)
class InstallResult:
    plugin: Plugin
    ok: bool
    path: Path | None
    error: str | None = None
    audit: AuditReport | None = None
    fix: FixReport | None = None
    provenance_error: str | None = None


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

@dataclass(frozen=True, slots=True)
class UninstallResult:
    """Outcome of removing one engine basename and its companions."""

    filename: str
    ok: bool
    removed: tuple[Path, ...] = ()
    error: str | None = None
    plugin: Plugin | None = None


ProgressCallback = Callable[[int, int, Plugin, InstallResult | None], None]
UninstallProgressCallback = Callable[[int, int, str, UninstallResult | None], None]


def companion_paths_for_engine(engines_dir: Path, filename: str) -> list[Path]:
    """
    Return paths that belong to an engine install and should be removed with it.

    Includes the ``.py``, leftover ``.tmp``, stem-named JSON config (e.g.
    ``jackett.json``), and matching ``__pycache__`` bytecode under engines and
    the parent ``nova3`` directory.
    """
    safe_name = validate_plugin_filename(filename)
    dest = resolve_plugin_dest(engines_dir, safe_name)
    stem = Path(safe_name).stem
    engines_root = engines_dir.resolve()
    nova3_root = engines_root.parent

    candidates: list[Path] = [
        dest,
        Path(str(dest) + ".tmp"),
        engines_dir / f"{stem}.json",
    ]

    for cache_dir in (engines_dir / "__pycache__", nova3_root / "__pycache__"):
        if not cache_dir.is_dir():
            continue
        try:
            cache_resolved = cache_dir.resolve()
        except OSError:
            continue
        # Keep deletions under engines or nova3 only.
        try:
            cache_resolved.relative_to(nova3_root)
        except ValueError:
            continue
        for path in cache_dir.glob(f"{stem}*.pyc"):
            candidates.append(path)

    # De-dupe while preserving order; only return existing files that stay
    # contained under nova3.
    seen: set[Path] = set()
    contained: list[Path] = []
    for path in candidates:
        try:
            resolved = path.resolve()
            resolved.relative_to(nova3_root)
        except (OSError, ValueError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.is_file():
            contained.append(path)
    return contained


def uninstall_plugin(
    filename: str,
    engines_dir: Path,
    *,
    plugin: Plugin | None = None,
) -> UninstallResult:
    """
    Fully remove one installed engine: script, companions, provenance.

    Idempotent: missing files are treated as success (already clean).
    """
    try:
        safe_name = validate_plugin_filename(filename)
        resolve_plugin_dest(engines_dir, safe_name)
    except ValueError as exc:
        return UninstallResult(
            filename=filename,
            ok=False,
            error=str(exc),
            plugin=plugin,
        )

    removed: list[Path] = []
    errors: list[str] = []
    for path in companion_paths_for_engine(engines_dir, safe_name):
        try:
            path.unlink()
            removed.append(path)
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")

    try:
        remove_install_provenance(safe_name)
    except OSError as exc:
        errors.append(f"provenance: {exc}")

    if errors:
        return UninstallResult(
            filename=safe_name,
            ok=False,
            removed=tuple(removed),
            error="; ".join(errors),
            plugin=plugin,
        )
    return UninstallResult(
        filename=safe_name,
        ok=True,
        removed=tuple(removed),
        plugin=plugin,
    )


def uninstall_plugins(
    plugins: Sequence[Plugin],
    engines_dir: Path,
    *,
    on_progress: UninstallProgressCallback | None = None,
) -> list[UninstallResult]:
    """
    Uninstall selected plugins by unique basename (full clean).

    Multiple catalog rows that share a filename are processed once.
    """
    # Preserve first-seen order while deduping by filename.
    by_filename: dict[str, Plugin] = {}
    for plugin in plugins:
        by_filename.setdefault(plugin.filename, plugin)

    total = len(by_filename)
    results: list[UninstallResult] = []
    for index, (filename, plugin) in enumerate(by_filename.items(), start=1):
        result = uninstall_plugin(filename, engines_dir, plugin=plugin)
        results.append(result)
        if on_progress is not None:
            on_progress(index, total, filename, result)
    return results


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
) -> tuple[bytes | None, str | None]:
    """Return (content, error). error set on failure."""
    result = await fetch_plugin_bytes_async(
        client,
        plugin.download_url,
        max_bytes=MAX_PLUGIN_BYTES,
        trusted_hosts=trusted_hosts,
    )
    if isinstance(result, FetchError):
        return None, result.message
    return result.content, None


def _write_engine(
    dest: Path,
    content: bytes,
    plugin: Plugin,
    *,
    engines_dir: Path,
    fix: FixReport | None,
    source_bytes: bytes | None = None,
) -> InstallResult:
    dest_tmp = Path(str(dest) + ".tmp")
    provenance_error: str | None = None
    try:
        # Re-validate containment immediately before replace (symlink TOCTOU).
        dest = resolve_plugin_dest(engines_dir, plugin.filename)
        dest_tmp = Path(str(dest) + ".tmp")
        fd = os.open(
            dest_tmp,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                dest_tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        os.replace(dest_tmp, dest)
    except Exception:
        try:
            dest_tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise

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
            plugin.filename,
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

    while True:
        tried_urls.append(current.download_url)
        ast_kinds_this_round: list[FixKind] = []
        source_bytes_before_ast: bytes | None = None
        try:
            dest = resolve_plugin_dest(engines_dir, current.filename)
        except ValueError as exc:
            return InstallResult(
                plugin=plugin,
                ok=False,
                path=None,
                error=str(exc),
            )

        content, fetch_error = await _fetch_plugin_bytes(
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
            )

        if auto_fix:
            report = await asyncio.to_thread(
                audit_clamav_then_static,
                content,
                filename=current.filename,
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
                    filename=current.filename,
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
                )
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
            filename=current.filename,
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
            dest, content, current, engines_dir=engines_dir, fix=None
        )
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
