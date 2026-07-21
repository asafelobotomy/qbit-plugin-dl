"""Category enrich size limits and byte SHA consistency."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.categories import enrich_plugins_async, load_categories_cache
from qbit_plugin_dl.install import MAX_PLUGIN_BYTES
from qbit_plugin_dl.provenance import content_sha


def _plugin(**kwargs) -> Plugin:
    defaults = dict(
        name="Example",
        site_url="https://example.com/",
        author="Author",
        author_url="",
        version="1.0",
        last_update="",
        download_url="https://example.com/example.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    defaults.update(kwargs)
    return Plugin(**defaults)


def test_content_sha_bytes_stable():
    payload = b"supported_categories = {'movies': '1'}\n"
    assert content_sha(payload) == content_sha(
        payload.decode("utf-8", errors="replace").encode("utf-8", errors="replace")
    )


def test_enrich_oversized_falls_back_without_sha(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    plugin = _plugin(name="FitGirl Repacks", download_url="https://example.com/fit.py")
    body = b"x" * (MAX_PLUGIN_BYTES + 1)

    class FakeResponse:
        def __init__(self) -> None:
            self.content = body
            self.url = httpx.URL(plugin.download_url)

        def raise_for_status(self) -> None:
            return None

    class FakeClient:
        async def get(self, url: str) -> FakeResponse:
            return FakeResponse()

        async def aclose(self) -> None:
            return None

    cache_path = tmp_path / "categories.json"
    results = asyncio.run(
        enrich_plugins_async(
            [plugin],
            force_refresh=True,
            cache_path=cache_path,
            client=FakeClient(),  # type: ignore[arg-type]
        )
    )
    assert results[0].categories == frozenset({"games"})
    cache = load_categories_cache(cache_path)
    assert cache[plugin.download_url].get("sha") is None


def test_enrich_stores_byte_sha(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    plugin = _plugin(download_url="https://example.com/yts.py")
    body = b'supported_categories = {"all": "0", "movies": "1"}\n'

    class FakeResponse:
        def __init__(self) -> None:
            self.content = body
            self.url = httpx.URL(plugin.download_url)

        def raise_for_status(self) -> None:
            return None

    class FakeClient:
        async def get(self, url: str) -> FakeResponse:
            return FakeResponse()

        async def aclose(self) -> None:
            return None

    cache_path = tmp_path / "categories.json"
    results = asyncio.run(
        enrich_plugins_async(
            [plugin],
            force_refresh=True,
            cache_path=cache_path,
            client=FakeClient(),  # type: ignore[arg-type]
        )
    )
    assert results[0].categories == frozenset({"movies"})
    cache = load_categories_cache(cache_path)
    assert cache[plugin.download_url]["sha"] == content_sha(body)
