"""Tests for shared secure fetch helpers."""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.fetch import (
    ALLOWED_DOWNLOAD_HOSTS,
    ALLOWED_GITHUB_REPOS,
    FetchError,
    FetchResult,
    MAX_PLUGIN_BYTES,
    assert_host_not_private,
    check_download_host,
    fetch_plugin_bytes_async,
    github_repo_trust_key,
    host_is_trusted,
    is_allowlisted_host,
    is_url_allowlisted,
    trust_key_for_url,
    untrusted_hosts_in_urls,
    url_is_trusted,
)
from qbit_plugin_dl.provenance import content_sha, content_sha256
from qbit_plugin_dl.sources import default_providers
from qbit_plugin_dl.updates import find_outdated_filenames
from tests.http_fakes import AsyncRedirectClient, AsyncSingleClient, FakeStreamResponse


def test_allowlisted_hosts_are_known_cdns_not_auto_trust():
    assert is_allowlisted_host("raw.githubusercontent.com")
    assert is_allowlisted_host("gist.githubusercontent.com")
    assert "raw.githubusercontent.com" in ALLOWED_DOWNLOAD_HOSTS
    assert not is_allowlisted_host("example.com")
    # CDN host alone is not trust.
    assert not url_is_trusted(
        "https://raw.githubusercontent.com/evil/malware/main/x.py"
    )


def test_repo_allowlist_matches_catalog_providers():
    assert ("qbittorrent", "search-plugins") in ALLOWED_GITHUB_REPOS
    assert ("lightdestory", "qbittorrent-search-plugins") in ALLOWED_GITHUB_REPOS
    github_providers = [
        p for p in default_providers() if hasattr(p, "owner") and hasattr(p, "repo")
    ]
    for provider in github_providers:
        assert (
            provider.owner.lower(),
            provider.repo.lower(),
        ) in ALLOWED_GITHUB_REPOS


def test_url_allowlist_and_trust_keys():
    official = (
        "https://raw.githubusercontent.com/qbittorrent/search-plugins/"
        "master/nova3/engines/jackett.py"
    )
    other = "https://raw.githubusercontent.com/SomeAuthor/fork/main/x.py"
    assert is_url_allowlisted(official)
    assert url_is_trusted(official)
    assert not is_url_allowlisted(other)
    assert not url_is_trusted(other)
    assert trust_key_for_url(other) == "github:someauthor/fork"
    assert url_is_trusted(
        other, trusted_hosts={github_repo_trust_key("SomeAuthor", "fork")}
    )
    # Host-level raw.githubusercontent.com must not approve arbitrary repos.
    assert not url_is_trusted(
        other, trusted_hosts={"raw.githubusercontent.com"}
    )


def test_host_trust_and_untrusted_list():
    assert not host_is_trusted("raw.githubusercontent.com")
    assert not host_is_trusted("evil.example")
    assert host_is_trusted("evil.example", trusted_hosts={"evil.example"})
    urls = [
        "https://raw.githubusercontent.com/qbittorrent/search-plugins/main/x.py",
        "https://raw.githubusercontent.com/a/b/main/x.py",
        "https://cdn.example/x.py",
        "https://cdn.example/y.py",
        "http://nope.example/z.py",
    ]
    assert untrusted_hosts_in_urls(urls) == [
        "github:a/b",
        "cdn.example",
    ]
    assert untrusted_hosts_in_urls(
        urls, trusted_hosts={"cdn.example", "github:a/b"}
    ) == []


def test_private_ip_rejected():
    def resolver(host, *_a, **_k):  # noqa: ANN001
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("127.0.0.1", 0),
            )
        ]

    with pytest.raises(ValueError, match="private|loopback|link-local"):
        assert_host_not_private("localhost", resolver=resolver)

    err = check_download_host(
        "https://raw.githubusercontent.com/qbittorrent/search-plugins/main/z.py",
        resolver=resolver,
    )
    assert err is not None
    assert "127.0.0.1" in err or "private" in err.lower() or "loopback" in err.lower()


def test_metadata_ip_rejected():
    def resolver(host, *_a, **_k):  # noqa: ANN001
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("169.254.169.254", 0),
            )
        ]

    with pytest.raises(ValueError, match="169.254.169.254"):
        assert_host_not_private("metadata", resolver=resolver)


def test_stream_aborts_over_size():
    body = b"a" * (MAX_PLUGIN_BYTES + 50)
    url = (
        "https://raw.githubusercontent.com/qbittorrent/search-plugins/"
        "main/x.py"
    )
    client = AsyncSingleClient(body, url, chunk_size=1024)

    async def _run():
        return await fetch_plugin_bytes_async(
            client,  # type: ignore[arg-type]
            url,
            max_bytes=MAX_PLUGIN_BYTES,
            check_private=False,
        )

    result = asyncio.run(_run())
    assert isinstance(result, FetchError)
    assert result.code == "size"
    assert str(MAX_PLUGIN_BYTES) in result.message
    assert "too large" in result.message


def test_unknown_host_fails_without_trust():
    client = AsyncSingleClient(
        b"print('ok')\n",
        "https://evil.example/x.py",
    )

    async def _run():
        return await fetch_plugin_bytes_async(
            client,  # type: ignore[arg-type]
            "https://evil.example/x.py",
            check_private=False,
        )

    result = asyncio.run(_run())
    assert isinstance(result, FetchError)
    assert result.code == "host"
    assert "Untrusted download host" in result.message


def test_non_allowlisted_github_repo_fails_without_trust():
    url = "https://raw.githubusercontent.com/evil/malware/main/x.py"
    client = AsyncSingleClient(b"print('ok')\n", url)

    async def _run():
        return await fetch_plugin_bytes_async(
            client,  # type: ignore[arg-type]
            url,
            check_private=False,
        )

    result = asyncio.run(_run())
    assert isinstance(result, FetchError)
    assert result.code == "host"
    assert "Untrusted GitHub repo" in result.message


def test_trusted_host_accepted():
    url = "https://evil.example/x.py"
    client = AsyncSingleClient(b"print('ok')\n", url)

    async def _run():
        return await fetch_plugin_bytes_async(
            client,  # type: ignore[arg-type]
            url,
            trusted_hosts={"evil.example"},
            check_private=False,
        )

    result = asyncio.run(_run())
    assert isinstance(result, FetchResult)
    assert result.content == b"print('ok')\n"


def test_redirect_hop_checked_before_follow():
    start = (
        "https://raw.githubusercontent.com/qbittorrent/search-plugins/"
        "main/a.py"
    )
    evil = "https://evil.example/steal"
    client = AsyncRedirectClient(
        {
            start: FakeStreamResponse(
                b"",
                start,
                status=302,
                headers={"Location": evil},
            ),
            evil: FakeStreamResponse(b"pwned", evil),
        }
    )

    async def _run():
        return await fetch_plugin_bytes_async(
            client,  # type: ignore[arg-type]
            start,
            check_private=False,
        )

    result = asyncio.run(_run())
    assert isinstance(result, FetchError)
    assert result.code == "host"
    # Policy rejects the next hop before contacting it.
    assert client.gets == [start]
    assert "evil.example" in result.message or "Untrusted" in result.message


def test_content_length_early_reject():
    url = (
        "https://raw.githubusercontent.com/qbittorrent/search-plugins/"
        "main/x.py"
    )

    class BigCLClient:
        @asynccontextmanager
        async def stream(self, method, u, follow_redirects=True):  # noqa: ANN001
            del method, follow_redirects
            yield FakeStreamResponse(
                b"tiny",
                u,
                headers={"Content-Length": str(MAX_PLUGIN_BYTES + 1)},
            )

    async def _run():
        return await fetch_plugin_bytes_async(
            BigCLClient(),  # type: ignore[arg-type]
            url,
            check_private=False,
        )

    result = asyncio.run(_run())
    assert isinstance(result, FetchError)
    assert result.code == "size"


def test_update_prefers_full_sha256(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    body = b"engine-body\n"
    (engines / "demo.py").write_bytes(body)
    plugin = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1",
        last_update="",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    full = content_sha256(body)
    provenance = {
        "demo.py": {
            "download_url": plugin.download_url,
            "sha": "deadbeefdeadbeef",
            "sha256": full,
        }
    }
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: full},
    )
    assert outdated == set()

    outdated2 = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: content_sha256(b"other\n")},
    )
    assert outdated2 == {"demo.py"}


def test_update_truncated_fallback(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    body = b"legacy\n"
    (engines / "demo.py").write_bytes(body)
    plugin = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1",
        last_update="",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    provenance = {
        "demo.py": {
            "download_url": plugin.download_url,
            "sha": content_sha(body),
        }
    }
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: content_sha(body)},
    )
    assert outdated == set()
