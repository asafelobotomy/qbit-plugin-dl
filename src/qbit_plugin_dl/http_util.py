"""Size-capped, host-pinned HTTPS GETs for catalog and GitHub API metadata.

Plugin bytes go through :mod:`qbit_plugin_dl.fetch` (consent, private-IP
checks). This module covers the remaining reads — the wiki catalog, the GitHub
Contents API and the Git Trees API — so none of them can follow a redirect off
their expected host or buffer an unbounded response.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from urllib.parse import urljoin, urlparse

import httpx

# Git trees for large repos run to several MB; the wiki page is ~100 KB.
METADATA_MAX_BYTES = 32 * 1024 * 1024
METADATA_MAX_REDIRECTS = 5

# Ask for the raw body: a server-side compressed response could otherwise
# inflate far past the byte cap inside a single decoded chunk.
IDENTITY_HEADERS: Mapping[str, str] = {"Accept-Encoding": "identity"}


class MetadataFetchError(Exception):
    """Policy violation or oversize response while reading metadata."""


def _check_url(url: str, allowed_hosts: Collection[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise MetadataFetchError(f"HTTPS required: {url}")
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts or parsed.port not in (None, 443):
        raise MetadataFetchError(f"Unexpected metadata host: {url}")


def check_identity_encoding(response: httpx.Response) -> str | None:
    """Error message when a response is compressed despite ``identity``."""
    encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if encoding and encoding != "identity":
        return f"Unexpected Content-Encoding {encoding!r} (identity requested)"
    return None


def _declared_too_large(response: httpx.Response, max_bytes: int) -> bool:
    try:
        return int(response.headers.get("Content-Length", "")) > max_bytes
    except ValueError:
        return False


def _merged_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    merged = dict(headers or {})
    merged.update(IDENTITY_HEADERS)
    return merged


def get_capped(
    client: httpx.Client,
    url: str,
    *,
    allowed_hosts: Collection[str],
    headers: Mapping[str, str] | None = None,
    max_bytes: int = METADATA_MAX_BYTES,
    timeout: float | None = None,
) -> tuple[int, bytes]:
    """
    GET *url* following redirects only within *allowed_hosts*.

    Returns ``(status_code, body)``; the body is empty for non-200 responses.
    Raises :class:`MetadataFetchError` on policy violations or oversize bodies.
    """
    current = url
    extra = {} if timeout is None else {"timeout": timeout}
    for _hop in range(METADATA_MAX_REDIRECTS + 1):
        _check_url(current, allowed_hosts)
        with client.stream(
            "GET",
            current,
            headers=_merged_headers(headers),
            follow_redirects=False,
            **extra,
        ) as response:
            if response.is_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise MetadataFetchError("Redirect without Location header")
                current = urljoin(current, location)
                continue
            if response.status_code != 200:
                return response.status_code, b""
            problem = check_identity_encoding(response)
            if problem:
                raise MetadataFetchError(problem)
            if _declared_too_large(response, max_bytes):
                raise MetadataFetchError(f"Metadata response too large: {url}")
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise MetadataFetchError(f"Metadata response too large: {url}")
                chunks.append(chunk)
            return response.status_code, b"".join(chunks)
    raise MetadataFetchError(f"Too many redirects (>{METADATA_MAX_REDIRECTS})")


async def get_capped_async(
    client: httpx.AsyncClient,
    url: str,
    *,
    allowed_hosts: Collection[str],
    headers: Mapping[str, str] | None = None,
    max_bytes: int = METADATA_MAX_BYTES,
    timeout: float | None = None,
) -> tuple[int, bytes]:
    """Async variant of :func:`get_capped`."""
    current = url
    extra = {} if timeout is None else {"timeout": timeout}
    for _hop in range(METADATA_MAX_REDIRECTS + 1):
        _check_url(current, allowed_hosts)
        async with client.stream(
            "GET",
            current,
            headers=_merged_headers(headers),
            follow_redirects=False,
            **extra,
        ) as response:
            if response.is_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise MetadataFetchError("Redirect without Location header")
                current = urljoin(current, location)
                continue
            if response.status_code != 200:
                return response.status_code, b""
            problem = check_identity_encoding(response)
            if problem:
                raise MetadataFetchError(problem)
            if _declared_too_large(response, max_bytes):
                raise MetadataFetchError(f"Metadata response too large: {url}")
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise MetadataFetchError(f"Metadata response too large: {url}")
                chunks.append(chunk)
            return response.status_code, b"".join(chunks)
    raise MetadataFetchError(f"Too many redirects (>{METADATA_MAX_REDIRECTS})")
