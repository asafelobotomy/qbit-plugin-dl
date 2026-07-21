"""Tests for multi-source catalog providers (no live network)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from qbit_plugin_dl.catalog import (
    Plugin,
    Visibility,
    group_plugins_for_display,
    parse_mediawiki,
)
from qbit_plugin_dl.sources import (
    CatalogFetchError,
    CatalogSource,
    engine_display_name,
    fetch_all_catalogs,
    parse_github_contents_listing,
)

FIXTURES = Path(__file__).parent / "fixtures"
GITHUB_FIXTURE = FIXTURES / "github_contents_official.json"
WIKI_FIXTURE = FIXTURES / "Unofficial-search-plugins.mediawiki"


def _plugin(**kwargs) -> Plugin:
    base = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1.0",
        last_update="1/Jan 2024",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    return replace(base, **kwargs) if kwargs else base


@pytest.fixture
def github_payload() -> list:
    return json.loads(GITHUB_FIXTURE.read_text(encoding="utf-8"))


def test_engine_display_name():
    assert engine_display_name("piratebay.py") == "Piratebay"
    assert engine_display_name("lime_torrents.py") == "Lime Torrents"


def test_parse_github_contents_skips_init_and_template(github_payload):
    plugins = parse_github_contents_listing(
        github_payload,
        owner="qbittorrent",
        repo="search-plugins",
        path="nova3/engines",
        ref="master",
        source_id="official",
        source_label="Official nova3",
    )
    names = {p.filename for p in plugins}
    assert "__init__.py" not in names
    assert "template.py" not in names
    assert "piratebay.py" in names
    assert "jackett.py" in names
    assert len(plugins) == 4


def test_parse_github_contents_urls_and_metadata(github_payload):
    plugins = parse_github_contents_listing(
        github_payload,
        owner="qbittorrent",
        repo="search-plugins",
        path="nova3/engines",
        ref="master",
        source_id="official",
        source_label="Official nova3",
    )
    by_file = {p.filename: p for p in plugins}
    pirate = by_file["piratebay.py"]
    assert pirate.source_id == "official"
    assert pirate.author == "qbittorrent"
    assert pirate.name == "Piratebay"
    assert pirate.visibility == Visibility.PUBLIC
    assert not pirate.warning
    assert pirate.comments == "Source: Official nova3"
    assert (
        pirate.download_url
        == "https://raw.githubusercontent.com/qbittorrent/search-plugins/master/nova3/engines/piratebay.py"
    )

    jackett = by_file["jackett.py"]
    assert "Jackett" in jackett.comments
    assert "local Jackett" in jackett.comments


def test_merge_wiki_and_official_grouping(github_payload):
    wiki = parse_mediawiki(WIKI_FIXTURE.read_text(encoding="utf-8"))
    official = parse_github_contents_listing(
        github_payload,
        owner="qbittorrent",
        repo="search-plugins",
        path="nova3/engines",
        ref="master",
        source_id="official",
        source_label="Official nova3",
    )
    merged = wiki + official
    groups = group_plugins_for_display(merged)

    # Official-only engines still appear as top-level rows.
    top_files = {g.primary.filename for g in groups}
    assert "jackett.py" in top_files

    # Same install filename collapses into one group (forks as alternates).
    pirate_groups = [g for g in groups if g.primary.filename == "piratebay.py"]
    assert len(pirate_groups) == 1
    members = [pirate_groups[0].primary, *pirate_groups[0].alternates]
    sources = {p.source_id for p in members}
    assert "wiki" in sources or "official" in sources
    assert len(members) >= 1


def test_fetch_all_catalogs_best_effort(monkeypatch):
    """One failing provider does not block others."""

    class OkProvider:
        source = CatalogSource(id="ok", label="OK")

        def fetch(self, client, *, force_refresh: bool = False):
            return [
                _plugin(
                    name="OnlyOk",
                    download_url="https://example.com/only_ok.py",
                    source_id="ok",
                )
            ]

    class BoomProvider:
        source = CatalogSource(id="boom", label="Boom")

        def fetch(self, client, *, force_refresh: bool = False):
            raise RuntimeError("network down")

    plugins, summary = fetch_all_catalogs(
        providers=[OkProvider(), BoomProvider()],
        client=object(),  # unused
    )
    assert len(plugins) == 1
    assert plugins[0].name == "OnlyOk"
    assert "ok=1" in summary
    assert "boom=err" in summary


def test_fetch_all_catalogs_all_fail():
    class BoomProvider:
        source = CatalogSource(id="boom", label="Boom")

        def fetch(self, client, *, force_refresh: bool = False):
            raise RuntimeError("network down")

    with pytest.raises(CatalogFetchError, match="All catalog sources failed"):
        fetch_all_catalogs(providers=[BoomProvider()], client=object())
    wiki = parse_mediawiki(WIKI_FIXTURE.read_text(encoding="utf-8"))
    assert wiki
    assert all(p.source_id == "wiki" for p in wiki)
