"""Tests for with-categories and author-fork plugin grouping."""

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from qbit_plugin_dl.catalog import (
    Plugin,
    PluginGroup,
    Visibility,
    base_plugin_name,
    group_category_variants,
    group_plugins_for_display,
    is_with_categories,
    parse_mediawiki,
    parse_wiki_date,
    parse_wiki_version,
    plugin_preference_score,
    prefer_plugin,
)

FIXTURE = Path(__file__).parent / "fixtures" / "Unofficial-search-plugins.mediawiki"


@pytest.fixture(scope="module")
def plugins():
    return parse_mediawiki(FIXTURE.read_text(encoding="utf-8"))


def _plugin(**kwargs) -> Plugin:
    base = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1.0",
        last_update="1/Jan 2024",
        download_url="https://example.com/demo.py",
        comments="✔ qbt 4.6.x",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    return replace(base, **kwargs) if kwargs else base


def test_is_with_categories():
    assert is_with_categories("TorrentDownload with categories")
    assert is_with_categories("Foo WITH CATEGORIES")
    assert not is_with_categories("TorrentDownload")
    assert not is_with_categories("categories")


def test_base_plugin_name():
    assert base_plugin_name("TorrentDownload with categories") == "TorrentDownload"
    assert base_plugin_name("TorrentDownload") is None


def test_parse_wiki_date_formats():
    assert parse_wiki_date("25/Nov 2023") == date(2023, 11, 25)
    assert parse_wiki_date("07/Nov/2024") == date(2024, 11, 7)
    assert parse_wiki_date("15/July 2026") == date(2026, 7, 15)
    assert parse_wiki_date("8/Jul 2024") == date(2024, 7, 8)
    assert parse_wiki_date("nope") == date.min


def test_parse_wiki_version():
    assert parse_wiki_version("2.2.1") == (2, 2, 1)
    assert parse_wiki_version("1.17") == (1, 17)
    assert parse_wiki_version("") == (0,)


def test_score_warning_loses():
    good = _plugin(warning=False, last_update="1/Jan 2020")
    bad = _plugin(warning=True, last_update="1/Jan 2025", author="z")
    assert prefer_plugin(good, bad) is good


def test_score_newer_date_wins():
    older = _plugin(last_update="1/Jan 2023", author="a")
    newer = _plugin(last_update="1/Jan 2024", author="b")
    assert prefer_plugin(older, newer) is newer


def test_score_official_beats_older_wiki_date():
    wiki = _plugin(
        last_update="1/Jan 2025",
        version="9.0",
        author="wiki-author",
        download_url="https://example.com/wiki/demo.py",
        source_id="wiki",
    )
    official = _plugin(
        last_update="",
        version="",
        author="qbittorrent",
        download_url="https://raw.githubusercontent.com/qbittorrent/search-plugins/master/nova3/engines/demo.py",
        source_id="official",
    )
    assert prefer_plugin(wiki, official) is official


def test_fixture_pairs_grouped(plugins):
    groups = group_category_variants(plugins)
    by_primary = {g.primary.name: g for g in groups}

    for base, preferred in (
        ("MagnetDL", "MagnetDL with categories"),
        ("ThePirateBay", "ThePirateBay with categories"),
        ("TorrentDownload", "TorrentDownload with categories"),
    ):
        group = by_primary[preferred]
        assert isinstance(group, PluginGroup)
        assert [a.name for a in group.alternates] == [base]
        assert base not in by_primary


def test_unpaired_plugin_stays_top_level(plugins):
    groups = group_category_variants(plugins)
    by_primary = {g.primary.name: g for g in groups}
    assert "acgrip" in by_primary
    assert by_primary["acgrip"].alternates == ()


def test_grouping_collapses_three_pairs(plugins):
    groups = group_category_variants(plugins)
    assert len(groups) == len(plugins) - 3
    seen = {(g.primary.name, g.primary.download_url) for g in groups}
    for g in groups:
        for alt in g.alternates:
            seen.add((alt.name, alt.download_url))
    assert seen == {(p.name, p.download_url) for p in plugins}


def test_partial_filter_only_preferred(plugins):
    preferred = next(p for p in plugins if p.name == "TorrentDownload with categories")
    groups = group_category_variants([preferred])
    assert len(groups) == 1
    assert groups[0].primary.name == preferred.name
    assert groups[0].alternates == ()


def test_partial_filter_only_base(plugins):
    base = next(p for p in plugins if p.name == "TorrentDownload")
    groups = group_category_variants([base])
    assert len(groups) == 1
    assert groups[0].primary.name == "TorrentDownload"
    assert groups[0].alternates == ()


def test_display_groups_author_forks(plugins):
    groups = group_plugins_for_display(plugins)
    by_file = {g.primary.filename.lower(): g for g in groups}

    dmhy = by_file["dmhy.py"]
    assert len(dmhy.alternates) == 1
    assert prefer_plugin(dmhy.primary, dmhy.alternates[0]) is dmhy.primary
    assert dmhy.primary.author == "dchika"  # newer date

    rutracker = by_file["rutracker.py"]
    assert len(rutracker.alternates) == 1
    assert rutracker.primary.author == "nbusseneau"

    union = by_file["unionfansub.py"]
    assert len(union.alternates) == 1
    assert union.primary.author == "CrimsonKoba"  # non-warned
    assert union.alternates[0].warning


def test_display_keeps_with_categories(plugins):
    groups = group_plugins_for_display(plugins)
    by_primary = {g.primary.name: g for g in groups}
    assert "TorrentDownload with categories" in by_primary
    assert "TorrentDownload" not in by_primary
    assert any(a.name == "TorrentDownload" for a in by_primary["TorrentDownload with categories"].alternates)


def test_nyaa_pantsu_not_forced_together(plugins):
    groups = group_plugins_for_display(plugins)
    pantsu = [g for g in groups if g.primary.filename.lower() in {"pantsu.py", "nyaapantsu.py"}]
    assert len(pantsu) == 2
    assert all(g.alternates == () for g in pantsu)


def test_display_covers_every_plugin_once(plugins):
    groups = group_plugins_for_display(plugins)
    seen = {(g.primary.name, g.primary.download_url) for g in groups}
    for g in groups:
        for alt in g.alternates:
            seen.add((alt.name, alt.download_url))
    assert seen == {(p.name, p.download_url) for p in plugins}
    # 3 with-categories pairs + 5 author-filename forks collapsed
    assert len(groups) == len(plugins) - 3 - 5
