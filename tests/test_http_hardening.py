"""Low-severity network hardening: encodings, deadlines, ports, metadata caps."""

from __future__ import annotations

import asyncio
import gzip
from contextlib import asynccontextmanager

import httpx
import pytest

import qbit_plugin_dl.fetch as fetch_mod
from qbit_plugin_dl.categories import parse_supported_categories
from qbit_plugin_dl.fetch import (
    FetchError,
    FetchResult,
    _is_blocked_ip,
    check_download_host,
    fetch_plugin_bytes,
    fetch_plugin_bytes_async,
    require_https_url,
    trust_key_for_url,
    untrusted_hosts_in_urls,
)
from qbit_plugin_dl.http_util import MetadataFetchError, get_capped
from tests.http_fakes import FakeStreamResponse, SyncMapClient

RAW = "https://raw.githubusercontent.com/qbittorrent/search-plugins/master/x.py"


@pytest.mark.parametrize(
    "url",
    [
        "https://raw.githubusercontent.com./qbittorrent/search-plugins/master/x.py",
        "https://raw.githubusercontent.com:8443/qbittorrent/search-plugins/master/x.py",
        "https://example.com:99999/x.py",
    ],
)
def test_odd_hosts_and_ports_rejected(url: str):
    with pytest.raises(ValueError):
        require_https_url(url)
    assert trust_key_for_url(url) is None
    assert untrusted_hosts_in_urls([url]) == []
    assert check_download_host(url, check_private=False) is not None


def test_default_port_still_allowed():
    url = "https://raw.githubusercontent.com:443/qbittorrent/search-plugins/master/x.py"
    assert require_https_url(url) == url


@pytest.mark.parametrize("addr", ["100.64.0.1", "100.127.255.254", "192.0.2.1"])
def test_non_global_addresses_blocked(addr: str):
    assert _is_blocked_ip(addr)


def test_public_address_allowed():
    assert not _is_blocked_ip("140.82.112.3")


class _RecordingClient:
    def __init__(self, response: FakeStreamResponse, *, delay: float = 0.0) -> None:
        self.response = response
        self.delay = delay
        self.headers: list[dict] = []

    @asynccontextmanager
    async def stream(self, method, url, follow_redirects=True, **kwargs):  # noqa: ANN001
        del method, url, follow_redirects
        self.headers.append(dict(kwargs.get("headers") or {}))
        if self.delay:
            await asyncio.sleep(self.delay)
        yield self.response


def _run(client, url=RAW):  # noqa: ANN001
    return asyncio.run(
        fetch_plugin_bytes_async(client, url, check_private=False)  # type: ignore[arg-type]
    )


def test_download_requests_identity_encoding():
    client = _RecordingClient(FakeStreamResponse(b"print(1)\n", RAW))
    assert isinstance(_run(client), FetchResult)
    assert client.headers[0].get("Accept-Encoding") == "identity"


def test_compressed_download_refused_before_decoding():
    bomb = gzip.compress(b"\0" * (20 * 1024 * 1024))
    client = _RecordingClient(
        FakeStreamResponse(bomb, RAW, headers={"Content-Encoding": "gzip"})
    )
    result = _run(client)
    assert isinstance(result, FetchError)
    assert "Content-Encoding" in result.message


def test_async_download_deadline(monkeypatch):
    monkeypatch.setattr(fetch_mod, "DOWNLOAD_DEADLINE_S", 0.05)
    client = _RecordingClient(FakeStreamResponse(b"print(1)\n", RAW), delay=0.5)
    result = _run(client)
    assert isinstance(result, FetchError)
    assert "overall limit" in result.message


def test_sync_download_deadline(monkeypatch):
    monkeypatch.setattr(fetch_mod, "DOWNLOAD_DEADLINE_S", -1.0)
    result = fetch_plugin_bytes(
        SyncMapClient({RAW: b"print(1)\n"}),  # type: ignore[arg-type]
        RAW,
        check_private=False,
    )
    assert isinstance(result, FetchError)
    assert "overall limit" in result.message


def _mock_client(handler) -> httpx.Client:  # noqa: ANN001
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_metadata_get_capped_ok_and_identity():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"[]")

    with _mock_client(handler) as client:
        status, body = get_capped(
            client, "https://api.github.com/x", allowed_hosts={"api.github.com"}
        )
    assert (status, body) == (200, b"[]")
    assert seen[0].headers["Accept-Encoding"] == "identity"


def test_metadata_redirect_off_host_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(302, headers={"Location": "https://evil.example/x"})
        raise AssertionError("must not contact the redirect target")

    with _mock_client(handler) as client, pytest.raises(MetadataFetchError):
        get_capped(client, "https://api.github.com/x", allowed_hosts={"api.github.com"})


def test_metadata_same_host_redirect_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/old":
            return httpx.Response(301, headers={"Location": "/new"})
        return httpx.Response(200, content=b"ok")

    with _mock_client(handler) as client:
        assert get_capped(
            client, "https://api.github.com/old", allowed_hosts={"api.github.com"}
        ) == (200, b"ok")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"x" * 2048),
        httpx.Response(200, content=b"x", headers={"Content-Length": "999999"}),
        httpx.Response(200, content=gzip.compress(b"{}"), headers={"Content-Encoding": "gzip"}),
    ],
)
def test_metadata_oversize_or_compressed_refused(response: httpx.Response):
    with _mock_client(lambda _r: response) as client, pytest.raises(MetadataFetchError):
        get_capped(
            client,
            "https://api.github.com/x",
            allowed_hosts={"api.github.com"},
            max_bytes=1024,
        )


def test_metadata_non_200_returns_status():
    with _mock_client(lambda _r: httpx.Response(403, content=b"rate")) as client:
        assert get_capped(
            client, "https://api.github.com/x", allowed_hosts={"api.github.com"}
        ) == (403, b"")


def test_category_literal_eval_recursion_is_contained(monkeypatch):
    import ast

    def boom(_text):  # noqa: ANN001
        raise RecursionError

    monkeypatch.setattr(ast, "literal_eval", boom)
    assert parse_supported_categories("supported_categories = {'all': ''}") == frozenset()
