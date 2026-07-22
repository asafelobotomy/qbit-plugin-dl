"""Detect outdated installed engines by comparing content hashes to catalog URLs."""

from __future__ import annotations

import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from pathlib import Path

import httpx

from qbit_plugin_dl.catalog import Plugin, group_plugins_for_display
from qbit_plugin_dl.categories import load_categories_cache, save_categories_cache
from qbit_plugin_dl.fetch import (
    MAX_PLUGIN_BYTES,
    MAX_REDIRECTS,
    FetchError,
    fetch_plugin_bytes,
)
from qbit_plugin_dl.install import list_installed_filenames
from qbit_plugin_dl.provenance import (
    content_sha,
    content_sha256,
    load_installed_provenance,
)

UPDATE_INDICATOR = "⬆ "


def preferred_plugins_by_filename(
    catalog: Sequence[Plugin],
) -> dict[str, Plugin]:
    """Map install basename → preferred (primary) catalog Plugin."""
    mapping: dict[str, Plugin] = {}
    for group in group_plugins_for_display(catalog):
        mapping.setdefault(group.primary.filename, group.primary)
    return mapping


def catalog_plugins_by_url(catalog: Sequence[Plugin]) -> dict[str, Plugin]:
    return {plugin.download_url: plugin for plugin in catalog}


def resolve_catalog_plugin(
    filename: str,
    *,
    catalog: Sequence[Plugin],
    provenance: Mapping[str, dict] | None = None,
    preferred: Mapping[str, Plugin] | None = None,
    by_url: Mapping[str, Plugin] | None = None,
) -> Plugin | None:
    """
    Choose the catalog Plugin that represents the current install target.

    Prefer provenance download_url when it still appears in the catalog;
    otherwise the preferred primary for that filename.
    """
    preferred = (
        preferred
        if preferred is not None
        else preferred_plugins_by_filename(catalog)
    )
    by_url = by_url if by_url is not None else catalog_plugins_by_url(catalog)
    provenance = provenance if provenance is not None else load_installed_provenance()

    entry = provenance.get(filename)
    if isinstance(entry, dict):
        url = entry.get("download_url")
        if isinstance(url, str) and url in by_url:
            return by_url[url]
    return preferred.get(filename)


def local_file_sha(path: Path) -> str | None:
    """Legacy truncated content hash of a local engine file."""
    try:
        return content_sha(path.read_bytes())
    except OSError:
        return None


def local_file_sha256(path: Path) -> str | None:
    try:
        return content_sha256(path.read_bytes())
    except OSError:
        return None


def remote_sha_from_cache(
    download_url: str,
    categories_cache: Mapping[str, dict] | None = None,
    *,
    prefer_full: bool = False,
) -> str | None:
    cache = (
        categories_cache
        if categories_cache is not None
        else load_categories_cache()
    )
    entry = cache.get(download_url)
    if not isinstance(entry, dict):
        return None
    if prefer_full:
        full = entry.get("sha256")
        # Never fall back to truncated sha when a full hash is required — mixing
        # lengths always looks like an update.
        if isinstance(full, str) and full:
            return full
        return None
    sha = entry.get("sha")
    return sha if isinstance(sha, str) and sha else None


def fetch_remote_sha(
    download_url: str,
    *,
    client: httpx.Client,
    categories_cache: dict[str, dict] | None = None,
    categories_cache_path: Path | None = None,
    trusted_hosts: Collection[str] | None = None,
    prefer_full: bool = False,
) -> str | None:
    """HTTPS GET plugin body, hash it, and optionally refresh categories cache sha."""
    result = fetch_plugin_bytes(
        client,
        download_url,
        max_bytes=MAX_PLUGIN_BYTES,
        trusted_hosts=trusted_hosts,
    )
    if isinstance(result, FetchError):
        return None
    content = result.content
    truncated = content_sha(content)
    full = content_sha256(content)

    if categories_cache is not None:
        entry = dict(categories_cache.get(download_url) or {})
        entry["sha"] = truncated
        entry["sha256"] = full
        entry.setdefault("fetched_at", time.time())
        categories_cache[download_url] = entry
        save_categories_cache(categories_cache, categories_cache_path)
    return full if prefer_full else truncated


def _install_baseline_hash(entry: Mapping[str, object] | None) -> tuple[str, bool] | None:
    """
    Return (hash, prefer_full) for the content we installed from the source URL.

    For AST-rewritten engines this is the pre-rewrite source hash. Otherwise the
    post-install content hash recorded at install time.
    """
    if not isinstance(entry, dict):
        return None
    if entry.get("rewritten"):
        full = entry.get("source_sha256")
        if isinstance(full, str) and full:
            return full, True
        trunc = entry.get("source_sha")
        if isinstance(trunc, str) and trunc:
            return trunc, False
        return None
    full = entry.get("sha256")
    if isinstance(full, str) and full:
        return full, True
    trunc = entry.get("sha")
    if isinstance(trunc, str) and trunc:
        return trunc, False
    return None


def find_outdated_filenames(
    engines_dir: Path,
    catalog: Sequence[Plugin],
    *,
    provenance: Mapping[str, dict] | None = None,
    categories_cache: Mapping[str, dict] | None = None,
    client: httpx.Client | None = None,
    remote_shas: Mapping[str, str] | None = None,
    trusted_hosts: Collection[str] | None = None,
) -> set[str]:
    """
    Return installed basenames whose **catalog source** content has changed.

    Compares the install-time baseline (provenance source/content hash) to the
    current remote body at the same hash width. Local edits alone do not count
    as updates. When provenance is missing, falls back to local file vs remote.
    """
    installed = list_installed_filenames(engines_dir)
    if not installed or not catalog:
        return set()

    provenance = provenance if provenance is not None else load_installed_provenance()
    preferred = preferred_plugins_by_filename(catalog)
    by_url = catalog_plugins_by_url(catalog)
    cat_cache: dict[str, dict] | None = (
        dict(categories_cache)
        if categories_cache is not None
        else load_categories_cache()
    )
    remote_map = dict(remote_shas) if remote_shas is not None else {}

    owns_client = client is None
    if client is None:
        client = httpx.Client(
            timeout=30.0,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        )

    outdated: set[str] = set()
    try:
        for filename in sorted(installed):
            plugin = resolve_catalog_plugin(
                filename,
                catalog=catalog,
                provenance=provenance,
                preferred=preferred,
                by_url=by_url,
            )
            if plugin is None:
                continue
            local_path = engines_dir / filename
            entry = provenance.get(filename)
            baseline = _install_baseline_hash(
                entry if isinstance(entry, dict) else None
            )
            if baseline is not None:
                local_or_base, prefer_full = baseline
            else:
                # No provenance: compare truncated local hash to remote (legacy path).
                trunc = local_file_sha(local_path)
                if trunc is None:
                    continue
                local_or_base, prefer_full = trunc, False

            url = plugin.download_url
            remote = remote_map.get(url)
            if remote is not None:
                # Ignore injected remotes of the wrong width.
                if prefer_full and len(remote) != 64:
                    remote = None
                elif not prefer_full and len(remote) == 64:
                    remote = remote[:16]
            if remote is None:
                remote = remote_sha_from_cache(
                    url, cat_cache, prefer_full=prefer_full
                )
            if (
                remote is None
                and prefer_full
                and len(local_or_base) == 64
            ):
                # Truncated cache entry that still matches the install baseline
                # prefix is enough to rule out an update without a live fetch.
                trunc = remote_sha_from_cache(
                    url, cat_cache, prefer_full=False
                )
                if (
                    isinstance(trunc, str)
                    and trunc
                    and local_or_base.startswith(trunc)
                ):
                    continue
            if remote is None and remote_shas is None:
                remote = fetch_remote_sha(
                    url,
                    client=client,
                    categories_cache=cat_cache,
                    trusted_hosts=trusted_hosts,
                    prefer_full=prefer_full,
                )
                if remote is not None:
                    remote_map[url] = remote
            if remote is None:
                continue

            if remote != local_or_base:
                outdated.add(filename)
    finally:
        if owns_client:
            client.close()

    return outdated


def plugins_for_updates(
    filenames: Iterable[str],
    catalog: Sequence[Plugin],
    *,
    provenance: Mapping[str, dict] | None = None,
) -> list[Plugin]:
    """Resolve outdated filenames to concrete catalog Plugins for install."""
    provenance = provenance if provenance is not None else load_installed_provenance()
    preferred = preferred_plugins_by_filename(catalog)
    by_url = catalog_plugins_by_url(catalog)
    plugins: list[Plugin] = []
    seen: set[str] = set()
    for filename in filenames:
        if filename in seen:
            continue
        plugin = resolve_catalog_plugin(
            filename,
            catalog=catalog,
            provenance=provenance,
            preferred=preferred,
            by_url=by_url,
        )
        if plugin is None:
            continue
        seen.add(filename)
        plugins.append(plugin)
    return plugins
