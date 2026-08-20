"""Tests for GitHub raw URL recovery when wiki paths go stale."""

from __future__ import annotations

import httpx

from qbit_plugin_dl.fetch import FetchError
from qbit_plugin_dl.url_recover import (
    build_github_raw_url,
    is_http_not_found,
    parse_github_raw_url,
    path_matches_basename,
    paths_from_tree_payload,
    rank_matching_paths,
    recover_github_raw_url,
    tree_api_url,
)


def test_parse_github_raw_url_simple():
    ref = parse_github_raw_url(
        "https://raw.githubusercontent.com/BurningMop/qBittorrent-Search-Plugins/"
        "main/torrenflix.py"
    )
    assert ref is not None
    assert ref.owner == "BurningMop"
    assert ref.repo == "qBittorrent-Search-Plugins"
    assert ref.ref == "main"
    assert ref.path == "torrenflix.py"


def test_parse_github_raw_url_refs_heads():
    ref = parse_github_raw_url(
        "https://raw.githubusercontent.com/tolotp/repo/refs/heads/main/Plugins/uindex.py"
    )
    assert ref is not None
    assert ref.ref == "refs/heads/main"
    assert ref.path == "Plugins/uindex.py"


def test_parse_github_raw_url_rejects_non_github():
    assert parse_github_raw_url("https://example.com/x.py") is None
    assert parse_github_raw_url("http://raw.githubusercontent.com/a/b/main/x.py") is None


def test_path_matches_basename_and_deprecated_rename():
    assert path_matches_basename("deprecated/torrenflix.py", "torrenflix.py")
    assert path_matches_basename("Plugins/(deprecated) uindex.py", "uindex.py")
    assert not path_matches_basename("other.py", "uindex.py")
    assert not path_matches_basename("Plugins/notuindex.py", "uindex.py")


def test_rank_matching_paths_prefers_live_over_deprecated():
    ranked = rank_matching_paths(
        [
            "deprecated/torrenflix.py",
            "engines/torrenflix.py",
            "README.md",
        ],
        "torrenflix.py",
    )
    assert ranked[0] == "engines/torrenflix.py"
    assert ranked[1] == "deprecated/torrenflix.py"


def test_build_and_tree_urls_encode_spaces():
    url = build_github_raw_url(
        "tolotp",
        "repo",
        "main",
        "Plugins/(deprecated) uindex.py",
    )
    assert "raw.githubusercontent.com/tolotp/repo/main/" in url
    assert "%28deprecated%29" in url
    assert tree_api_url("o", "r", "refs/heads/main").endswith(
        "/git/trees/main?recursive=1"
    )


def test_paths_from_tree_payload():
    paths = paths_from_tree_payload(
        {
            "tree": [
                {"type": "blob", "path": "deprecated/torrenflix.py"},
                {"type": "tree", "path": "deprecated"},
                {"type": "blob", "path": "README.md"},
            ]
        }
    )
    assert paths == ["deprecated/torrenflix.py", "README.md"]


def test_is_http_not_found():
    assert is_http_not_found(FetchError(message="404", code="not_found"))
    assert is_http_not_found(FetchError(message="Client error '404'", code="network"))
    assert not is_http_not_found(FetchError(message="timeout", code="network"))


def test_recover_github_raw_url_mocked():
    stale = (
        "https://raw.githubusercontent.com/BurningMop/qBittorrent-Search-Plugins/"
        "main/torrenflix.py"
    )
    payload = {
        "tree": [
            {"type": "blob", "path": "bitsearch.py"},
            {"type": "blob", "path": "deprecated/torrenflix.py"},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert "api.github.com" in str(request.url)
        assert "git/trees/main" in str(request.url)
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as client:
        recovered = recover_github_raw_url(client, stale, basename="torrenflix.py")
    assert recovered is not None
    assert recovered.endswith("/deprecated/torrenflix.py")
    assert "BurningMop/qBittorrent-Search-Plugins/main/" in recovered


def test_recover_skips_non_github():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError(f"unexpected request {request.url}")

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as client:
        assert (
            recover_github_raw_url(
                client,
                "https://example.com/missing.py",
                basename="missing.py",
            )
            is None
        )


def test_recover_rate_limit_soft_fails():
    stale = (
        "https://raw.githubusercontent.com/BurningMop/qBittorrent-Search-Plugins/"
        "main/torrenflix.py"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "API rate limit exceeded"})

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as client:
        assert recover_github_raw_url(client, stale, basename="torrenflix.py") is None


def test_remote_sha_cache_ttl(monkeypatch, tmp_path):
    import time

    from qbit_plugin_dl.updates import remote_sha_from_cache

    cache = {
        "https://example.com/a.py": {
            "sha": "abcd1234abcd1234",
            "sha256": "a" * 64,
            "fetched_at": time.time() - 10,
        }
    }
    assert (
        remote_sha_from_cache(
            "https://example.com/a.py",
            cache,
            max_age_seconds=60,
        )
        == "abcd1234abcd1234"
    )
    assert (
        remote_sha_from_cache(
            "https://example.com/a.py",
            cache,
            max_age_seconds=1,
        )
        is None
    )
