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
    FetchError,
    FetchResult,
    MAX_PLUGIN_BYTES,
    assert_host_not_private,
    check_download_host,
    fetch_plugin_bytes_async,
    host_is_trusted,
    is_allowlisted_host,
    untrusted_hosts_in_urls,
)
from qbit_plugin_dl.provenance import (
    content_sha,
    content_sha256,
    load_installed_provenance,
    record_install_provenance,
)
from qbit_plugin_dl.updates import find_outdated_filenames
from tests.http_fakes import AsyncSingleClient, FakeStreamResponse


def test_allowlisted_hosts():
    assert is_allowlisted_host("raw.githubusercontent.com")
    assert is_allowlisted_host("gist.githubusercontent.com")
    assert "raw.githubusercontent.com" in ALLOWED_DOWNLOAD_HOSTS
    assert not is_allowlisted_host("example.com")


def test_host_trust_and_untrusted_list():
    assert host_is_trusted("raw.githubusercontent.com")
    assert not host_is_trusted("evil.example")
    assert host_is_trusted("evil.example", trusted_hosts={"evil.example"})
    urls = [
        "https://raw.githubusercontent.com/a/b/main/x.py",
        "https://cdn.example/x.py",
        "https://cdn.example/y.py",
        "http://nope.example/z.py",
    ]
    assert untrusted_hosts_in_urls(urls) == ["cdn.example"]
    assert untrusted_hosts_in_urls(urls, trusted_hosts={"cdn.example"}) == []


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
        "https://raw.githubusercontent.com/x/y/main/z.py",
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
    url = "https://raw.githubusercontent.com/org/repo/main/x.py"
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


def test_content_length_early_reject():
    url = "https://raw.githubusercontent.com/o/r/main/x.py"

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


def test_atomic_provenance_write(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    path = tmp_path / "installed.json"
    record_install_provenance(
        "demo.py",
        download_url="https://example.com/demo.py",
        sha="abcd",
        sha256=content_sha256(b"payload"),
        path=path,
    )
    assert path.is_file()
    assert not list(path.parent.glob("*.tmp"))
    data = load_installed_provenance(path)
    assert data["demo.py"]["sha256"] == content_sha256(b"payload")


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
