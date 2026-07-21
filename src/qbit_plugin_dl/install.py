"""Detect qBittorrent engines directories and download selected plugins."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

from qbit_plugin_dl.catalog import Plugin
from qbit_plugin_dl.provenance import content_sha, record_install_provenance

MAX_PLUGIN_BYTES = 2 * 1024 * 1024


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


def require_https_url(url: str) -> str:
    """Reject non-HTTPS download URLs."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"HTTPS required for plugin downloads: {url}")
    if not parsed.netloc:
        raise ValueError(f"Invalid download URL: {url}")
    return url


@dataclass(frozen=True, slots=True)
class InstallResult:
    plugin: Plugin
    ok: bool
    path: Path | None
    error: str | None = None


ProgressCallback = Callable[[int, int, Plugin, InstallResult | None], None]


async def _download_one(
    client: httpx.AsyncClient,
    plugin: Plugin,
    engines_dir: Path,
    semaphore: asyncio.Semaphore,
) -> InstallResult:
    async with semaphore:
        try:
            require_https_url(plugin.download_url)
            dest = resolve_plugin_dest(engines_dir, plugin.filename)
            response = await client.get(plugin.download_url)
            response.raise_for_status()
            # Refuse if the final URL after redirects left HTTPS.
            require_https_url(str(response.url))
            content = response.content
            if len(content) > MAX_PLUGIN_BYTES:
                return InstallResult(
                    plugin=plugin,
                    ok=False,
                    path=None,
                    error=f"Response too large (>{MAX_PLUGIN_BYTES} bytes)",
                )
            if not content.strip():
                return InstallResult(
                    plugin=plugin,
                    ok=False,
                    path=None,
                    error="Empty response",
                )
            dest_tmp = Path(str(dest) + ".tmp")
            dest_tmp.write_bytes(content)
            os.replace(dest_tmp, dest)
            try:
                record_install_provenance(
                    plugin.filename,
                    download_url=plugin.download_url,
                    sha=content_sha(content),
                )
            except OSError:
                pass
            return InstallResult(plugin=plugin, ok=True, path=dest)
        except Exception as exc:  # noqa: BLE001 - report any download failure
            return InstallResult(
                plugin=plugin,
                ok=False,
                path=None,
                error=str(exc),
            )


async def install_plugins_async(
    plugins: Sequence[Plugin],
    engines_dir: Path,
    *,
    concurrency: int = 6,
    on_progress: ProgressCallback | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[InstallResult]:
    """Download selected plugins into engines_dir concurrently."""
    engines_dir.mkdir(parents=True, exist_ok=True)
    total = len(plugins)
    if total == 0:
        return []

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=45.0, follow_redirects=True)

    semaphore = asyncio.Semaphore(concurrency)
    results: list[InstallResult] = []
    completed = 0

    try:
        tasks = [
            asyncio.create_task(_download_one(client, plugin, engines_dir, semaphore))
            for plugin in plugins
        ]
        for task in asyncio.as_completed(tasks):
            result = await task
            results.append(result)
            completed += 1
            if on_progress is not None:
                on_progress(completed, total, result.plugin, result)
    finally:
        if owns_client:
            await client.aclose()

    # Preserve input order for reporting.
    by_name = {(r.plugin.name, r.plugin.download_url): r for r in results}
    return [
        by_name[(plugin.name, plugin.download_url)]
        for plugin in plugins
        if (plugin.name, plugin.download_url) in by_name
    ]


def install_plugins(
    plugins: Sequence[Plugin],
    engines_dir: Path,
    *,
    concurrency: int = 6,
    on_progress: ProgressCallback | None = None,
) -> list[InstallResult]:
    """Synchronous wrapper around install_plugins_async."""
    return asyncio.run(
        install_plugins_async(
            plugins,
            engines_dir,
            concurrency=concurrency,
            on_progress=on_progress,
        )
    )
