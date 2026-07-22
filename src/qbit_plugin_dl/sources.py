"""Allowlisted multi-source catalog providers for qbit-plugin-dl."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

import httpx

from qbit_plugin_dl.catalog import (
    CACHE_TTL_SECONDS,
    CATALOG_URL,
    Plugin,
    Visibility,
    _cache_is_fresh,
    catalog_cache_file,
    load_cached_catalog,
    parse_mediawiki,
    save_catalog_cache,
    sources_cache_dir,
)
from qbit_plugin_dl.paths import atomic_write_text

GITHUB_API_ACCEPT = "application/vnd.github+json"
GITHUB_API_VERSION = "2022-11-28"
SKIP_ENGINE_FILES = frozenset({"__init__.py", "template.py"})


class CatalogFetchError(RuntimeError):
    """Raised when every enabled catalog provider fails."""


@dataclass(frozen=True, slots=True)
class CatalogSource:
    id: str
    label: str
    enabled: bool = True


class CatalogProvider(Protocol):
    source: CatalogSource

    def fetch(
        self,
        client: httpx.Client,
        *,
        force_refresh: bool = False,
    ) -> list[Plugin]: ...


@dataclass(frozen=True, slots=True)
class WikiCatalogProvider:
    """Unofficial MediaWiki catalog from qbittorrent/search-plugins."""

    source: CatalogSource = CatalogSource(id="wiki", label="Unofficial wiki")

    def fetch(
        self,
        client: httpx.Client,
        *,
        force_refresh: bool = False,
        url: str = CATALOG_URL,
        cache_path: Path | None = None,
        ttl: int = CACHE_TTL_SECONDS,
    ) -> list[Plugin]:
        cache_path = cache_path or catalog_cache_file()
        if not force_refresh and _cache_is_fresh(cache_path, ttl):
            text = load_cached_catalog(cache_path)
            if text is not None:
                return parse_mediawiki(text)

        response = client.get(url)
        response.raise_for_status()
        text = response.text
        save_catalog_cache(text, cache_path)
        return parse_mediawiki(text)


def engine_display_name(filename: str) -> str:
    """Light title-case of an engine module stem for the Name column."""
    stem = Path(filename).stem
    parts = re.split(r"[_\-\s]+", stem)
    return " ".join(p[:1].upper() + p[1:] if p else "" for p in parts if p)


def parse_github_contents_listing(
    payload: list | dict,
    *,
    owner: str,
    repo: str,
    path: str,
    ref: str,
    source_id: str,
    source_label: str,
) -> list[Plugin]:
    """
    Convert a GitHub Contents API directory listing into Plugin records.

    Only ``.py`` engine files are kept; ``__init__.py`` / ``template.py`` skipped.
    """
    if isinstance(payload, dict):
        # Single-file response — not a directory listing.
        payload = [payload]

    plugins: list[Plugin] = []
    path = path.strip("/")
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "file":
            continue
        name = entry.get("name") or ""
        if not name.endswith(".py") or name in SKIP_ENGINE_FILES:
            continue
        # Reject path traversal in listed names.
        if "/" in name or "\\" in name or name in {".", ".."}:
            continue
        raw_path = "/".join(
            quote(part, safe="") for part in (*path.split("/"), name) if part
        )
        download_url = (
            f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{raw_path}"
        )
        comments = f"Source: {source_label}"
        if name.lower() == "jackett.py":
            comments += " — requires a local Jackett instance"
        plugins.append(
            Plugin(
                name=engine_display_name(name),
                site_url=f"https://github.com/{owner}/{repo}",
                author=owner,
                author_url=f"https://github.com/{owner}",
                version="",
                last_update="",
                download_url=download_url,
                comments=comments,
                visibility=Visibility.PUBLIC,
                warning=False,
                source_id=source_id,
            )
        )
    plugins.sort(key=lambda p: p.name.lower())
    return plugins


@dataclass(frozen=True, slots=True)
class GitHubEnginesProvider:
    """List ``.py`` engines from an allowlisted GitHub repository directory."""

    owner: str
    repo: str
    path: str
    ref: str
    source: CatalogSource

    def _cache_path(self) -> Path:
        return sources_cache_dir() / f"{self.source.id}.json"

    def _api_url(self) -> str:
        path = self.path.strip("/")
        return (
            f"https://api.github.com/repos/{self.owner}/{self.repo}/contents/"
            f"{path}?ref={quote(self.ref, safe='')}"
        )

    def fetch(
        self,
        client: httpx.Client,
        *,
        force_refresh: bool = False,
        ttl: int = CACHE_TTL_SECONDS,
    ) -> list[Plugin]:
        cache_path = self._cache_path()
        payload: list | dict | None = None
        if not force_refresh and _cache_is_fresh(cache_path, ttl):
            try:
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None

        if payload is None:
            response = client.get(
                self._api_url(),
                headers={
                    "Accept": GITHUB_API_ACCEPT,
                    "X-GitHub-Api-Version": GITHUB_API_VERSION,
                },
            )
            response.raise_for_status()
            payload = response.json()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(
                cache_path,
                json.dumps(payload, indent=2, sort_keys=True),
            )
            # Touch mtime explicitly for freshness.
            cache_path.touch()

        return parse_github_contents_listing(
            payload,
            owner=self.owner,
            repo=self.repo,
            path=self.path,
            ref=self.ref,
            source_id=self.source.id,
            source_label=self.source.label,
        )


def default_providers() -> list[CatalogProvider]:
    """Hard-coded v1 allowlist of enabled catalog providers."""
    return [
        WikiCatalogProvider(),
        GitHubEnginesProvider(
            owner="qbittorrent",
            repo="search-plugins",
            path="nova3/engines",
            ref="master",
            source=CatalogSource(id="official", label="Official nova3"),
        ),
        GitHubEnginesProvider(
            owner="LightDestory",
            repo="qBittorrent-Search-Plugins",
            path="src/engines",
            ref="master",
            source=CatalogSource(id="lightdestory", label="LightDestory"),
        ),
    ]


def fetch_all_catalogs(
    *,
    force_refresh: bool = False,
    client: httpx.Client | None = None,
    providers: list[CatalogProvider] | None = None,
) -> tuple[list[Plugin], str]:
    """
    Fetch enabled providers (best-effort) and merge plugin lists.

    Returns ``(plugins, status_summary)`` where summary looks like
    ``wiki=92 official=8 lightdestory=26`` (failed sources noted as ``id=err``).
    """
    providers = providers if providers is not None else default_providers()
    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=30.0, follow_redirects=True)

    all_plugins: list[Plugin] = []
    parts: list[str] = []
    attempted = 0
    failures = 0
    try:
        for provider in providers:
            if not provider.source.enabled:
                continue
            attempted += 1
            try:
                plugins = provider.fetch(client, force_refresh=force_refresh)
                all_plugins.extend(plugins)
                parts.append(f"{provider.source.id}={len(plugins)}")
            except Exception:  # noqa: BLE001 - keep other sources
                failures += 1
                parts.append(f"{provider.source.id}=err")
    finally:
        if owns_client:
            client.close()

    summary = " ".join(parts)
    if attempted > 0 and failures == attempted:
        raise CatalogFetchError(
            f"All catalog sources failed ({summary or 'no providers'})"
        )
    return all_plugins, summary
