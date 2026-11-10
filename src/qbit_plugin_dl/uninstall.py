"""Remove installed engines and their companion files."""

from __future__ import annotations

import glob
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from qbit_plugin_dl.catalog import Plugin
from qbit_plugin_dl.engine_dirs import resolve_plugin_dest, validate_plugin_filename
from qbit_plugin_dl.provenance import (
    remove_install_provenance,
)


@dataclass(frozen=True, slots=True)
class UninstallResult:
    """Outcome of removing one engine basename and its companions."""

    filename: str
    ok: bool
    removed: tuple[Path, ...] = ()
    error: str | None = None
    plugin: Plugin | None = None


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
        Path(str(dest) + ".tmp"),  # legacy fixed temp name
        engines_dir / f"{stem}.json",
    ]
    # Leftovers from atomic_write_bytes (".<name>.<random>.tmp").
    candidates.extend(engines_dir.glob(f".{glob.escape(safe_name)}.*.tmp"))

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
        # Exactly this module's bytecode ("<stem>.cpython-312.pyc" or
        # "<stem>.pyc"), never other modules sharing the prefix.
        escaped = glob.escape(stem)
        candidates.extend(cache_dir.glob(f"{escaped}.*.pyc"))
        candidates.append(cache_dir / f"{stem}.pyc")

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
