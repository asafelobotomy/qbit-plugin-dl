"""Tests for plugin category parsing, heuristics, and filtering."""

from pathlib import Path

from qbit_plugin_dl.catalog import Plugin, Visibility, filter_plugins
from qbit_plugin_dl.categories import (
    apply_cached_categories,
    format_categories,
    heuristic_categories,
    parse_supported_categories,
    resolve_categories,
    save_categories_cache,
)


def _plugin(**kwargs) -> Plugin:
    defaults = dict(
        name="Example",
        site_url="https://example.com/",
        author="Author",
        author_url="https://github.com/example",
        version="1.0",
        last_update="01/Jan 2026",
        download_url="https://example.com/example.py",
        comments="✔",
        visibility=Visibility.PUBLIC,
        warning=False,
        categories=frozenset(),
    )
    defaults.update(kwargs)
    return Plugin(**defaults)


NYAA_SRC = """
class nyaasi(object):
    url = 'https://nyaa.si'
    name = 'Nyaa.si'
    supported_categories = {
             'all': '0_0',
             'anime': '1_0',
             'books': '3_0',
             'music': '2_0',
             'pictures': '5_0',
             'software': '6_0',
             'tv': '4_0',
             'movies': '4_0'}
"""

YTS_SRC = '''
class yts(object):
    supported_categories = {"all": "0", "movies": "1"}
'''

ALL_ONLY_SRC = """
class fitgirl(object):
    supported_categories = {'all': ''}
"""

MISSING_SRC = """
class bare(object):
    url = 'https://example.com'
    name = 'Bare'
"""


def test_parse_multi_categories():
    cats = parse_supported_categories(NYAA_SRC)
    assert cats == frozenset(
        {"anime", "books", "music", "pictures", "software", "tv", "movies"}
    )


def test_parse_yts_movies():
    assert parse_supported_categories(YTS_SRC) == frozenset({"movies"})


def test_parse_all_only_empty():
    assert parse_supported_categories(ALL_ONLY_SRC) == frozenset()


def test_parse_missing():
    assert parse_supported_categories(MISSING_SRC) == frozenset()


def test_heuristic_fitgirl():
    assert heuristic_categories("FitGirl Repacks") == frozenset({"games"})


def test_heuristic_adult():
    assert heuristic_categories("My Porn Club", "https://myporn.club/") == frozenset(
        {"adult"}
    )


def test_resolve_prefers_declared_over_heuristic():
    cats = resolve_categories(
        name="FitGirl Repacks",
        site_url="https://fitgirl-repacks.site/",
        source=YTS_SRC,  # declared movies only
    )
    assert cats == frozenset({"movies"})


def test_resolve_heuristic_when_all_only():
    cats = resolve_categories(
        name="FitGirl Repacks",
        site_url="https://fitgirl-repacks.site/",
        source=ALL_ONLY_SRC,
    )
    assert cats == frozenset({"games"})


def test_resolve_heuristic_when_fetch_failed():
    cats = resolve_categories(
        name="AudioBook Bay (ABB)",
        site_url="http://theaudiobookbay.se/",
        source=None,
    )
    assert cats == frozenset({"books"})


def test_filter_by_category():
    plugins = [
        _plugin(name="Nyaa", categories=frozenset({"anime", "movies"})),
        _plugin(name="YTS", categories=frozenset({"movies"})),
        _plugin(name="Plain", categories=frozenset()),
    ]
    anime = filter_plugins(plugins, category="anime")
    assert [p.name for p in anime] == ["Nyaa"]
    movies = filter_plugins(plugins, category="movies")
    assert [p.name for p in movies] == ["Nyaa", "YTS"]
    uncat = filter_plugins(plugins, category="uncategorized")
    assert [p.name for p in uncat] == ["Plain"]


def test_format_categories():
    assert format_categories(frozenset({"tv", "anime"})) == "anime, tv"
    assert format_categories(frozenset()) == "—"


def test_apply_cached_categories(tmp_path: Path):
    cache_path = tmp_path / "categories.json"
    plugin = _plugin(download_url="https://example.com/x.py")
    save_categories_cache(
        {
            plugin.download_url: {
                "categories": ["anime", "tv"],
                "sha": "abc",
                "fetched_at": 1.0,
            }
        },
        cache_path,
    )
    # apply_cached_categories uses default path — exercise via load + replace manually
    from qbit_plugin_dl.categories import load_categories_cache

    cache = load_categories_cache(cache_path)
    enriched = apply_cached_categories([plugin], cache)
    assert enriched[0].categories == frozenset({"anime", "tv"})
