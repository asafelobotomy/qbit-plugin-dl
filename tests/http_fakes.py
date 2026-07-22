"""Shared httpx fakes that support streamed GET (fetch_plugin_bytes)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

import httpx

# Catalog URLs in unit tests use example.com — not on the product allowlist.
TRUSTED_TEST_HOSTS: frozenset[str] = frozenset({"example.com"})


class FakeStreamResponse:
    def __init__(
        self,
        content: bytes,
        url: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        history: list | None = None,
        chunk_size: int = 65536,
    ) -> None:
        self.content = content
        self.url = httpx.URL(url)
        self.status_code = status
        self.headers = headers or {}
        self.history = history or []
        self._chunk_size = chunk_size

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", str(self.url))
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=request,
                response=httpx.Response(self.status_code, request=request),
            )

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        data = self.content
        size = self._chunk_size
        for i in range(0, len(data), size):
            yield data[i : i + size]

    def iter_bytes(self) -> Iterator[bytes]:
        data = self.content
        size = self._chunk_size
        for i in range(0, len(data), size):
            yield data[i : i + size]


class AsyncMapClient:
    """Async client: URL → bytes or (status, bytes). Supports ``stream``."""

    def __init__(
        self,
        mapping: dict[str, bytes | tuple[int, bytes]],
        *,
        chunk_size: int = 65536,
    ) -> None:
        self.mapping = mapping
        self.gets: list[str] = []
        self._chunk_size = chunk_size

    def _response(self, url: str) -> FakeStreamResponse:
        self.gets.append(url)
        value = self.mapping[url]
        if isinstance(value, tuple):
            status, content = value
            return FakeStreamResponse(
                content, url, status=status, chunk_size=self._chunk_size
            )
        return FakeStreamResponse(value, url, chunk_size=self._chunk_size)

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        follow_redirects: bool = True,
    ):
        del method, follow_redirects
        yield self._response(url)

    async def get(self, url: str) -> FakeStreamResponse:
        return self._response(url)

    async def aclose(self) -> None:
        return None


class AsyncSingleClient:
    """Return the same body for any URL; optional final URL override."""

    def __init__(
        self,
        content: bytes,
        final_url: str,
        *,
        chunk_size: int = 65536,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._content = content
        self._final_url = final_url
        self._chunk_size = chunk_size
        self._headers = headers
        self.gets: list[str] = []

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        follow_redirects: bool = True,
    ):
        del method, follow_redirects
        self.gets.append(url)
        yield FakeStreamResponse(
            self._content,
            self._final_url,
            headers=self._headers,
            chunk_size=self._chunk_size,
        )

    async def get(self, url: str) -> FakeStreamResponse:
        self.gets.append(url)
        return FakeStreamResponse(
            self._content,
            self._final_url,
            headers=self._headers,
            chunk_size=self._chunk_size,
        )

    async def aclose(self) -> None:
        return None


class SyncMapClient:
    """Sync client for updates.fetch_remote_sha."""

    def __init__(
        self,
        mapping: dict[str, bytes],
        *,
        chunk_size: int = 65536,
    ) -> None:
        self.mapping = mapping
        self.gets: list[str] = []
        self._chunk_size = chunk_size

    @contextmanager
    def stream(
        self,
        method: str,
        url: str,
        follow_redirects: bool = True,
    ):
        del method, follow_redirects
        self.gets.append(url)
        yield FakeStreamResponse(
            self.mapping[url], url, chunk_size=self._chunk_size
        )

    def get(self, url: str) -> FakeStreamResponse:
        self.gets.append(url)
        return FakeStreamResponse(
            self.mapping[url], url, chunk_size=self._chunk_size
        )
