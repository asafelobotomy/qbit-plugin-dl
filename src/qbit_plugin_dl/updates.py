"""Detect outdated installed engines by comparing content hashes to catalog URLs."""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

import httpx

from qbit_plugin_dl.catalog import Plugin, group_plugins_for_display
from qbit_plugin_dl.categories import load_categories_cache, save_categories_cache
from qbit_plugin_dl.install import (
    MAX_PLUGIN_BYTES,
    list_installed_filenames,
    require_https_url,
)
from qbit_plugin_dl.provenance import (
    content_sha,
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
    try:
        return content_sha(path.read_bytes())
    except OSError:
        return None


def remote_sha_from_cache(
    download_url: str,
    categories_cache: Mapping[str, dict] | None = None,
) -> str | None:
    cache = (
        categories_cache
        if categories_cache is not None
        else load_categories_cache()
    )
    entry = cache.get(download_url)
    if not isinstance(entry, dict):
        return None
    sha = entry.get("sha")
    return sha if isinstance(sha, str) and sha else None


def fetch_remote_sha(
    download_url: str,
    *,
    client: httpx.Client,
    categories_cache: dict[str, dict] | None = None,
    categories_cache_path: Path | None = None,
) -> str | None:
    """HTTPS GET plugin body, hash it, and optionally refresh categories cache sha."""
    try:
        require_https_url(download_url)
        response = client.get(download_url)
        response.raise_for_status()
        require_https_url(str(response.url))
        content = response.content
        if len(content) > MAX_PLUGIN_BYTES or not content.strip():
            return None
        sha = content_sha(content)
    except Exception:  # noqa: BLE001 - best-effort
        return None

    if categories_cache is not None:
        entry = dict(categories_cache.get(download_url) or {})
        entry["sha"] = sha
        entry.setdefault("fetched_at", time.time())
        categories_cache[download_url] = entry
        save_categories_cache(categories_cache, categories_cache_path)
    return sha


def find_outdated_filenames(
    engines_dir: Path,
    catalog: Sequence[Plugin],
    *,
    provenance: Mapping[str, dict] | None = None,
    categories_cache: Mapping[str, dict] | None = None,
    client: httpx.Client | None = None,
    remote_shas: Mapping[str, str] | None = None,
) -> set[str]:
    """
    Return installed basenames whose local content differs from the catalog URL.

    ``remote_shas`` may supply precomputed URL→sha maps (tests). Otherwise the
    categories cache is used, with HTTPS fetch as a fallback.
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
        client = httpx.Client(timeout=30.0, follow_redirects=True)

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
            local = local_file_sha(local_path)
            if local is None:
                continue

            url = plugin.download_url
            remote = remote_map.get(url)
            if remote is None:
                remote = remote_sha_from_cache(url, cat_cache)
            if remote is None and remote_shas is None:
                # Only network-fetch when caller did not supply a closed sha map.
                remote = fetch_remote_sha(
                    url,
                    client=client,
                    categories_cache=cat_cache,
                )
                if remote is not None:
                    remote_map[url] = remote
            if remote is None:
                continue
            if local != remote:
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
