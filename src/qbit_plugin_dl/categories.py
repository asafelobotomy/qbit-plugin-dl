"""Resolve qBittorrent search-plugin categories from .py sources and heuristics."""

from __future__ import annotations

import ast
import asyncio
import json
import re
import time
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import replace
from pathlib import Path

import httpx

from qbit_plugin_dl.catalog import Plugin
from qbit_plugin_dl.fetch import (
    MAX_PLUGIN_BYTES,
    MAX_REDIRECTS,
    FetchError,
    fetch_plugin_bytes_async,
)
from qbit_plugin_dl.paths import atomic_write_text, cache_dir
from qbit_plugin_dl.provenance import content_sha, content_sha256

QBIT_CATEGORIES = (
    "anime",
    "books",
    "games",
    "movies",
    "music",
    "pictures",
    "software",
    "tv",
)
QBIT_CATEGORY_SET = frozenset(QBIT_CATEGORIES)
ADULT_CATEGORY = "adult"
UNCATEGORIZED = "uncategorized"

FILTER_CATEGORIES = (*QBIT_CATEGORIES, ADULT_CATEGORY)


def categories_cache_file() -> Path:
    """Path to the categories JSON cache (XDG-aware)."""
    return cache_dir() / "categories.json"

# Match supported_categories = { ... } including nested braces unlikely; use balanced scan.
_SUPPORTED_CATS_ASSIGN = re.compile(
    r"supported_categories\s*=\s*",
    re.IGNORECASE,
)

# Heuristic signals: (category, substrings matched against name + site_url)
_HEURISTIC_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "anime",
        (
            "nyaa",
            "anime",
            "mikan",
            "animetosho",
            "anidex",
            "dmhy",
            "acgrip",
            "subsplease",
            "bakabt",
            "tokyo toshokan",
            "tokyotosho",
            "neko",
            "dark-libria",
            "darklibria",
        ),
    ),
    (
        "movies",
        (
            "yts",
            "1337",
            "piratebay",
            "thepiratebay",
            "rarbg",
            "torrenflix",
        ),
    ),
    (
        "tv",
        (
            "eztv",
            "lostfilm",
        ),
    ),
    (
        "games",
        (
            "fitgirl",
            "dodi",
            "gog-games",
            "goggames",
            "small-games",
            "smallgames",
            "gazellegames",
            "online-fix",
            "onlinefix",
            "rockbox",
        ),
    ),
    (
        "books",
        (
            "audiobook",
            "academic torrents",
            "pediatorrent",
        ),
    ),
    (
        ADULT_CATEGORY,
        (
            "sukebei",
            "porn",
            "xxx",
            "pornolab",
            "myporn",
        ),
    ),
)


ProgressCallback = Callable[[int, int, Plugin], None]


def parse_supported_categories(source: str) -> frozenset[str]:
    """Extract qBittorrent category keys from a plugin .py source string."""
    match = _SUPPORTED_CATS_ASSIGN.search(source)
    if not match:
        return frozenset()

    start = match.end()
    while start < len(source) and source[start].isspace():
        start += 1
    if start >= len(source) or source[start] != "{":
        return frozenset()

    depth = 0
    end = start
    for i in range(start, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    else:
        return frozenset()

    literal = source[start:end]
    try:
        value = ast.literal_eval(literal)
    except (SyntaxError, ValueError):
        return frozenset()

    if not isinstance(value, dict):
        return frozenset()

    cats: set[str] = set()
    for key in value:
        key_s = str(key).strip().lower()
        if key_s in QBIT_CATEGORY_SET:
            cats.add(key_s)
    return frozenset(cats)


def heuristic_categories(name: str, site_url: str = "") -> frozenset[str]:
    """Infer categories from plugin name/URL when the .py only declares `all`."""
    haystack = f"{name} {site_url}".lower()
    found: set[str] = set()
    for category, signals in _HEURISTIC_RULES:
        if any(signal in haystack for signal in signals):
            found.add(category)
    return frozenset(found)


def resolve_categories(
    *,
    name: str,
    site_url: str,
    source: str | None,
) -> frozenset[str]:
    """
    Prefer categories declared in the plugin source; if none, use heuristics.

    Heuristics never remove declared categories.
    """
    declared = parse_supported_categories(source) if source else frozenset()
    if declared:
        return declared
    return heuristic_categories(name, site_url)


def load_categories_cache(path: Path | None = None) -> dict[str, dict]:
    path = path or categories_cache_file()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_categories_cache(
    cache: dict[str, dict],
    path: Path | None = None,
) -> None:
    path = path or categories_cache_file()
    atomic_write_text(
        path,
        json.dumps(cache, indent=2, sort_keys=True),
    )


def categories_from_cache_entry(entry: dict | None) -> frozenset[str] | None:
    if not entry or "categories" not in entry:
        return None
    raw = entry["categories"]
    if not isinstance(raw, list):
        return None
    return frozenset(str(c) for c in raw)


def apply_cached_categories(
    plugins: Sequence[Plugin],
    cache: dict[str, dict] | None = None,
) -> list[Plugin]:
    """Return plugins with categories filled from cache when available."""
    cache = cache if cache is not None else load_categories_cache()
    result: list[Plugin] = []
    for plugin in plugins:
        entry = cache.get(plugin.download_url)
        cats = categories_from_cache_entry(entry)
        if cats is not None:
            result.append(replace(plugin, categories=cats))
        else:
            result.append(plugin)
    return result


async def _enrich_one(
    client: httpx.AsyncClient,
    plugin: Plugin,
    cache: dict[str, dict],
    cache_lock: asyncio.Lock,
    semaphore: asyncio.Semaphore,
    *,
    force_refresh: bool,
    trusted_hosts: Collection[str] | None = None,
) -> Plugin:
    if not force_refresh:
        async with cache_lock:
            cached = categories_from_cache_entry(cache.get(plugin.download_url))
        if cached is not None:
            return replace(plugin, categories=cached)

    async with semaphore:
        source: str | None = None
        content_bytes: bytes | None = None
        result = await fetch_plugin_bytes_async(
            client,
            plugin.download_url,
            max_bytes=MAX_PLUGIN_BYTES,
            trusted_hosts=trusted_hosts,
        )
        if isinstance(result, FetchError):
            source = None
            content_bytes = None
        else:
            content_bytes = result.content
            source = content_bytes.decode("utf-8", errors="replace")

    cats = resolve_categories(
        name=plugin.name,
        site_url=plugin.site_url,
        source=source,
    )
    entry = {
        "categories": sorted(cats),
        "sha": content_sha(content_bytes) if content_bytes is not None else None,
        "sha256": content_sha256(content_bytes) if content_bytes is not None else None,
        "fetched_at": time.time(),
    }
    async with cache_lock:
        cache[plugin.download_url] = entry
    return replace(plugin, categories=cats)


async def enrich_plugins_async(
    plugins: Sequence[Plugin],
    *,
    force_refresh: bool = False,
    concurrency: int = 6,
    cache_path: Path | None = None,
    on_progress: ProgressCallback | None = None,
    client: httpx.AsyncClient | None = None,
    trusted_hosts: Collection[str] | None = None,
) -> list[Plugin]:
    """Fetch plugin sources and attach categories; update disk cache."""
    if not plugins:
        return []

    cache_path = cache_path or categories_cache_file()
    cache = {} if force_refresh else load_categories_cache(cache_path)
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        )

    semaphore = asyncio.Semaphore(concurrency)
    cache_lock = asyncio.Lock()
    total = len(plugins)
    completed = 0
    results: list[Plugin] = []

    try:
        tasks = [
            asyncio.create_task(
                _enrich_one(
                    client,
                    plugin,
                    cache,
                    cache_lock,
                    semaphore,
                    force_refresh=force_refresh,
                    trusted_hosts=trusted_hosts,
                )
            )
            for plugin in plugins
        ]
        for plugin, task in zip(plugins, tasks, strict=True):
            enriched = await task
            results.append(enriched)
            completed += 1
            if on_progress is not None:
                on_progress(completed, total, enriched)
    finally:
        if owns_client:
            await client.aclose()

    save_categories_cache(cache, cache_path)
    return results


def enrich_plugins(
    plugins: Sequence[Plugin],
    *,
    force_refresh: bool = False,
    concurrency: int = 6,
    cache_path: Path | None = None,
    on_progress: ProgressCallback | None = None,
    trusted_hosts: Collection[str] | None = None,
) -> list[Plugin]:
    """Synchronous wrapper around enrich_plugins_async."""
    return asyncio.run(
        enrich_plugins_async(
            plugins,
            force_refresh=force_refresh,
            concurrency=concurrency,
            cache_path=cache_path,
            on_progress=on_progress,
            trusted_hosts=trusted_hosts,
        )
    )


def format_categories(categories: Iterable[str]) -> str:
    cats = sorted(categories)
    return ", ".join(cats) if cats else "—"
