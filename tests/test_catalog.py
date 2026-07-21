"""Tests for MediaWiki catalog parsing."""

from pathlib import Path

import pytest

from qbit_plugin_dl.catalog import (
    Visibility,
    normalize_download_url,
    parse_mediawiki,
)

FIXTURE = Path(__file__).parent / "fixtures" / "Unofficial-search-plugins.mediawiki"


@pytest.fixture(scope="module")
def mediawiki_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def plugins(mediawiki_text: str):
    return parse_mediawiki(mediawiki_text)


def test_parse_counts(plugins):
    public = [p for p in plugins if p.visibility == Visibility.PUBLIC]
    private = [p for p in plugins if p.visibility == Visibility.PRIVATE]
    assert len(public) >= 60
    assert len(private) >= 20
    assert len(plugins) == len(public) + len(private)


def test_all_plugins_have_py_download(plugins):
    missing = [p.name for p in plugins if not p.download_url.endswith(".py")]
    assert missing == []


def test_acgrip_entry(plugins):
    match = next(p for p in plugins if p.name == "acgrip")
    assert match.visibility == Visibility.PUBLIC
    assert match.author == "Yun"
    assert match.version == "1.0"
    assert match.download_url.endswith("/acgrip.py")
    assert not match.warning


def test_warning_flag(plugins):
    warned = [p for p in plugins if p.warning]
    assert warned
    assert any("❗" in p.comments or "✖" in p.comments or "❌" in p.comments for p in warned)


def test_private_bakabt(plugins):
    match = next(p for p in plugins if p.name == "BakaBT")
    assert match.visibility == Visibility.PRIVATE
    assert "bakabt.py" in match.download_url


def test_normalize_blob_url():
    blob = "https://github.com/Laiteux/YggAPI-qBittorrent-Search-Plugin/blob/main/yggapi.py#L13"
    assert (
        normalize_download_url(blob)
        == "https://raw.githubusercontent.com/Laiteux/YggAPI-qBittorrent-Search-Plugin/main/yggapi.py"
    )


def test_normalize_percent_encoding():
    url = (
        "https://raw.githubusercontent.com/hannsen/"
        "qbittorrent%5Fsearch%5Fplugins/master/ali213.py"
    )
    assert "_search_" in normalize_download_url(url)


def test_yggapi_blob_in_fixture(plugins):
    match = next(p for p in plugins if p.name == "YggAPI")
    assert "raw.githubusercontent.com" in match.download_url
    assert match.download_url.endswith("yggapi.py")
    assert "#" not in match.download_url


def test_http_download_url_skipped():
    snippet = """
== Plugins for Public Sites ==
{|
|-
| [https://example.com/ Site]
| [https://github.com/x Author]
| 1.0
| 01/Jan 2024
| [http://example.com/bad.py [[https://raw.githubusercontent.com/Pireo/hello-world/master/Download.gif]]]
| ok
|}
"""
    plugins = parse_mediawiki(snippet)
    assert plugins == []


def test_https_download_url_kept():
    snippet = """
== Plugins for Public Sites ==
{|
|-
| [https://example.com/ Site]
| [https://github.com/x Author]
| 1.0
| 01/Jan 2024
| [https://example.com/good.py [[https://raw.githubusercontent.com/Pireo/hello-world/master/Download.gif]]]
| ok
|}
"""
    plugins = parse_mediawiki(snippet)
    assert len(plugins) == 1
    assert plugins[0].download_url.startswith("https://")
