"""Shared HTTPS download helpers with size, host, and private-IP controls."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from qbit_plugin_dl.http_util import IDENTITY_HEADERS, check_identity_encoding
from qbit_plugin_dl.url_recover import (
    is_github_raw_host,
    is_http_not_found,
    parse_github_raw_url,
    recover_github_raw_url,
    recover_github_raw_url_async,
)

# Keep in sync with install / categories / updates callers.
MAX_PLUGIN_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
# Wall-clock cap per plugin download. httpx timeouts are per operation, so a
# server trickling one byte per read could otherwise hold a slot indefinitely.
DOWNLOAD_DEADLINE_S = 120.0

GITHUB_RAW_HOST = "raw.githubusercontent.com"
GIST_RAW_HOST = "gist.githubusercontent.com"

# Catalog GitHub repos whose raw URLs are auto-trusted (owner/repo, lowercased).
# Not CDN-wide: wiki rows pointing at other repos need explicit consent.
ALLOWED_GITHUB_REPOS: frozenset[tuple[str, str]] = frozenset(
    {
        ("qbittorrent", "search-plugins"),
        ("lightdestory", "qbittorrent-search-plugins"),
    }
)

# Legacy name kept for tests/docs: hosts that *may* appear in allowlisted URLs.
# Auto-trust is repo-scoped via ALLOWED_GITHUB_REPOS, not these hosts alone.
ALLOWED_DOWNLOAD_HOSTS: frozenset[str] = frozenset(
    {
        GITHUB_RAW_HOST,
        GIST_RAW_HOST,
    }
)


@dataclass(frozen=True, slots=True)
class FetchResult:
    """Successful download body and final URL after redirects."""

    content: bytes
    final_url: str


@dataclass(frozen=True, slots=True)
class FetchError:
    """Failed download with a stable reason code for callers/UI."""

    message: str
    code: str  # https | size | empty | host | private | network | redirect | not_found
    host: str = ""


def require_https_url(url: str) -> str:
    """Reject non-HTTPS download URLs, non-default ports and trailing-dot hosts."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"HTTPS required for plugin downloads: {url}")
    if not parsed.netloc:
        raise ValueError(f"Invalid download URL: {url}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid download URL: {url}") from exc
    # Trust keys are per host (or per GitHub repo): a custom port could be a
    # different service on an approved host.
    if port not in (None, 443):
        raise ValueError(f"Non-default port not allowed for downloads: {url}")
    # ``raw.githubusercontent.com.`` resolves like the real host but would get
    # its own (CDN-wide) consent key, sidestepping repo-scoped trust.
    if (parsed.hostname or "").endswith("."):
        raise ValueError(f"Trailing-dot hostname not allowed: {url}")
    return url


def hostname_from_url(url: str) -> str:
    """Return lowercase hostname from a URL (no port)."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host


def github_repo_trust_key(owner: str, repo: str) -> str:
    """Stable trust key for a GitHub owner/repo pair."""
    return f"github:{owner.lower()}/{repo.lower()}"


def trust_key_for_url(url: str) -> str | None:
    """
    Trust principal for *url*.

    GitHub raw URLs use ``github:owner/repo`` so consent is repo-scoped.
    Other hosts (including gist CDN) use the hostname.
    """
    try:
        require_https_url(url)
    except ValueError:
        return None
    raw = parse_github_raw_url(url)
    if raw is not None:
        return github_repo_trust_key(raw.owner, raw.repo)
    if is_github_raw_host(url):
        # Malformed raw URL (dot segments, encoded separators, …): never offer a
        # CDN-wide hostname key, which would bypass repo-scoped consent.
        return None
    host = hostname_from_url(url)
    return host or None


def is_allowlisted_github_repo(owner: str, repo: str) -> bool:
    return (owner.lower(), repo.lower()) in ALLOWED_GITHUB_REPOS


def is_url_allowlisted(url: str) -> bool:
    """True when *url* is on the built-in catalog repo allowlist."""
    raw = parse_github_raw_url(url)
    if raw is None:
        return False
    return is_allowlisted_github_repo(raw.owner, raw.repo)


def is_allowlisted_host(host: str) -> bool:
    """True when *host* is a known download CDN (not sufficient alone for trust)."""
    return host.lower() in ALLOWED_DOWNLOAD_HOSTS


def host_is_trusted(host: str, trusted_hosts: Collection[str] | None = None) -> bool:
    """
    True when *host* is present in the caller-supplied trust set.

    Built-in auto-trust is URL/repo scoped via :func:`url_is_trusted`, not host-wide
    for GitHub raw.
    """
    host = host.lower()
    if not trusted_hosts:
        return False
    return host in {h.lower() for h in trusted_hosts}


def url_is_trusted(
    url: str,
    trusted_hosts: Collection[str] | None = None,
) -> bool:
    """
    True when *url* is allowlisted or covered by caller trust keys.

    *trusted_hosts* may contain hostnames (``codeberg.org``) and/or GitHub repo
    keys (``github:owner/repo``). Host-level trust of ``raw.githubusercontent.com``
    does **not** approve arbitrary repos.
    """
    if is_url_allowlisted(url):
        return True
    if not trusted_hosts:
        return False
    keys = {k.lower() for k in trusted_hosts}
    key = trust_key_for_url(url)
    if key is not None and key in keys:
        return True
    # Non-GitHub-raw hosts (incl. gist CDN): hostname consent.
    if is_github_raw_host(url):
        return False
    host = hostname_from_url(url)
    return bool(host) and host in keys


def untrusted_hosts_in_urls(
    urls: Iterable[str],
    *,
    trusted_hosts: Collection[str] | None = None,
) -> list[str]:
    """
    Unique trust keys that need consent for the given URLs.

    Returns ``github:owner/repo`` for non-allowlisted GitHub raw URLs and bare
    hostnames for other HTTPS hosts.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for url in urls:
        try:
            require_https_url(url)
        except ValueError:
            continue
        if url_is_trusted(url, trusted_hosts):
            continue
        key = trust_key_for_url(url)
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return bool(
        # Not globally routable: also covers carrier-grade NAT (100.64.0.0/10)
        # and other special-use ranges that is_private does not.
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or addr == "169.254.169.254"
    )


def assert_host_not_private(
    host: str,
    *,
    resolver: Callable[..., list] | None = None,
) -> None:
    """
    Best-effort reject hosts that resolve to private/link-local/metadata IPs.

    DNS rebinding is not fully eliminated; this is defense in depth.
    """
    resolve = resolver or socket.getaddrinfo
    try:
        infos = resolve(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"DNS lookup failed for download host: {host}") from exc
    if not infos:
        raise ValueError(f"DNS lookup failed for download host: {host}")
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        addr = sockaddr[0]
        if _is_blocked_ip(addr):
            raise ValueError(
                f"Refusing download host resolving to private/link-local "
                f"address ({addr}): {host}"
            )


def _host_error_code(message: str) -> str:
    lower = message.lower()
    if "private" in lower or "link-local" in lower:
        return "private"
    if "dns" in lower:
        return "network"
    return "host"


def check_download_host(
    url: str,
    *,
    trusted_hosts: Collection[str] | None = None,
    check_private: bool = True,
    resolver: Callable[..., list] | None = None,
) -> str | None:
    """
    Validate host/repo policy for *url*.

    Returns None when OK, otherwise an error message.
    """
    try:
        require_https_url(url)
    except ValueError as exc:
        return str(exc)
    host = hostname_from_url(url)
    if not host:
        return f"Invalid download URL: {url}"
    if not url_is_trusted(url, trusted_hosts):
        if is_github_raw_host(url) and parse_github_raw_url(url) is None:
            return (
                f"Refusing malformed GitHub raw URL (dot segments or encoded "
                f"separators): {url}"
            )
        key = trust_key_for_url(url) or host
        if key.startswith("github:"):
            return (
                f"Untrusted GitHub repo: {key.removeprefix('github:')} — "
                "approve this repository and re-run install"
            )
        return (
            f"Untrusted download host: {host} — approve this host and re-run install"
        )
    if check_private:
        try:
            assert_host_not_private(host, resolver=resolver)
        except ValueError as exc:
            return str(exc)
    return None


def _redirect_target(current_url: str, response: httpx.Response) -> str | None:
    if not response.is_redirect:
        return None
    location = response.headers.get("Location")
    if not location:
        return None
    return urljoin(current_url, location)


def _check_body_headers(
    response: httpx.Response, *, max_bytes: int
) -> FetchError | None:
    """Final-URL, encoding and declared-size checks before reading the body."""
    try:
        require_https_url(str(response.url))
    except ValueError as exc:
        return FetchError(message=str(exc), code="https")
    problem = check_identity_encoding(response)
    if problem:
        # A compressed body would be inflated chunk-by-chunk by httpx before
        # the size cap could see it (decompression bomb).
        return FetchError(message=problem, code="size")
    cl = response.headers.get("Content-Length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                return FetchError(
                    message=(
                        f"Response too large ({int(cl)} bytes > "
                        f"{max_bytes} bytes limit)"
                    ),
                    code="size",
                )
        except ValueError:
            pass
    return None


class _BodyAccumulator:
    """Collect body chunks under a byte cap and an overall deadline."""

    def __init__(self, *, max_bytes: int, deadline: float) -> None:
        self.max_bytes = max_bytes
        self.deadline = deadline
        self.total = 0
        self.chunks: list[bytes] = []

    def add(self, chunk: bytes) -> FetchError | None:
        if time.monotonic() > self.deadline:
            return _deadline_error()
        if not chunk:
            return None
        self.total += len(chunk)
        if self.total > self.max_bytes:
            return FetchError(
                message=(
                    f"Response too large ({self.total} bytes > "
                    f"{self.max_bytes} bytes limit)"
                ),
                code="size",
            )
        self.chunks.append(chunk)
        return None

    def result(self, final_url: str) -> FetchResult | FetchError:
        content = b"".join(self.chunks)
        if not content.strip():
            return FetchError(message="Empty response", code="empty")
        return FetchResult(content=content, final_url=final_url)


def _deadline_error() -> FetchError:
    return FetchError(
        message=f"Download exceeded {DOWNLOAD_DEADLINE_S:.0f}s overall limit",
        code="network",
    )


def _read_limited_body(
    response: httpx.Response,
    *,
    max_bytes: int,
    iter_chunks: Callable[[], Iterable[bytes]],
    deadline: float,
) -> FetchResult | FetchError:
    problem = _check_body_headers(response, max_bytes=max_bytes)
    if problem:
        return problem
    body = _BodyAccumulator(max_bytes=max_bytes, deadline=deadline)
    for chunk in iter_chunks():
        error = body.add(chunk)
        if error:
            return error
    return body.result(str(response.url))


async def fetch_plugin_bytes_async(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int = MAX_PLUGIN_BYTES,
    trusted_hosts: Collection[str] | None = None,
    check_private: bool = True,
    resolver: Callable[..., list] | None = None,
) -> FetchResult | FetchError:
    """
    Stream HTTPS plugin bytes with size, host, and private-IP controls.

    Redirect hops are checked **before** each request (SSRF defense).
    """
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_S
    try:
        async with asyncio.timeout(DOWNLOAD_DEADLINE_S):
            return await _fetch_plugin_bytes_async(
                client,
                url,
                max_bytes=max_bytes,
                trusted_hosts=trusted_hosts,
                check_private=check_private,
                resolver=resolver,
                deadline=deadline,
            )
    except TimeoutError:
        return _deadline_error()


async def _fetch_plugin_bytes_async(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    trusted_hosts: Collection[str] | None,
    check_private: bool,
    resolver: Callable[..., list] | None,
    deadline: float,
) -> FetchResult | FetchError:
    current = url
    try:
        for _hop in range(MAX_REDIRECTS + 1):
            try:
                require_https_url(current)
            except ValueError as exc:
                return FetchError(message=str(exc), code="https")

            pre_host_err = check_download_host(
                current,
                trusted_hosts=trusted_hosts,
                check_private=check_private,
                resolver=resolver,
            )
            if pre_host_err:
                return FetchError(
                    message=pre_host_err,
                    code=_host_error_code(pre_host_err),
                    host=hostname_from_url(current),
                )

            async with client.stream(
                "GET",
                current,
                headers=IDENTITY_HEADERS,
                follow_redirects=False,
            ) as response:
                target = _redirect_target(current, response)
                if target is not None:
                    # Close without reading body; advance to next hop.
                    current = target
                    continue

                if response.is_redirect:
                    return FetchError(
                        message="Redirect without Location header",
                        code="redirect",
                    )
                response.raise_for_status()
                problem = _check_body_headers(response, max_bytes=max_bytes)
                if problem:
                    return problem
                body = _BodyAccumulator(max_bytes=max_bytes, deadline=deadline)
                async for chunk in response.aiter_bytes():
                    error = body.add(chunk)
                    if error:
                        return error
                return body.result(str(response.url))

        return FetchError(
            message=f"Too many redirects (>{MAX_REDIRECTS})",
            code="redirect",
        )
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        code = "not_found" if status == 404 else "network"
        return FetchError(message=str(exc), code=code)
    except Exception as exc:  # noqa: BLE001
        return FetchError(message=str(exc), code="network")


def fetch_plugin_bytes(
    client: httpx.Client,
    url: str,
    *,
    max_bytes: int = MAX_PLUGIN_BYTES,
    trusted_hosts: Collection[str] | None = None,
    check_private: bool = True,
    resolver: Callable[..., list] | None = None,
) -> FetchResult | FetchError:
    """Synchronous variant of :func:`fetch_plugin_bytes_async`."""
    current = url
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_S
    try:
        for _hop in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                return _deadline_error()
            try:
                require_https_url(current)
            except ValueError as exc:
                return FetchError(message=str(exc), code="https")

            pre_host_err = check_download_host(
                current,
                trusted_hosts=trusted_hosts,
                check_private=check_private,
                resolver=resolver,
            )
            if pre_host_err:
                return FetchError(
                    message=pre_host_err,
                    code=_host_error_code(pre_host_err),
                    host=hostname_from_url(current),
                )

            with client.stream(
                "GET",
                current,
                headers=IDENTITY_HEADERS,
                follow_redirects=False,
            ) as response:
                target = _redirect_target(current, response)
                if target is not None:
                    current = target
                    continue

                if response.is_redirect:
                    return FetchError(
                        message="Redirect without Location header",
                        code="redirect",
                    )
                response.raise_for_status()
                result = _read_limited_body(
                    response,
                    max_bytes=max_bytes,
                    iter_chunks=response.iter_bytes,
                    deadline=deadline,
                )
                return result

        return FetchError(
            message=f"Too many redirects (>{MAX_REDIRECTS})",
            code="redirect",
        )
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        code = "not_found" if status == 404 else "network"
        return FetchError(message=str(exc), code=code)
    except Exception as exc:  # noqa: BLE001
        return FetchError(message=str(exc), code="network")


async def fetch_with_github_recovery_async(
    client: httpx.AsyncClient,
    url: str,
    *,
    basename: str | None = None,
    max_bytes: int = MAX_PLUGIN_BYTES,
    trusted_hosts: Collection[str] | None = None,
    check_private: bool = True,
    resolver: Callable[..., list] | None = None,
) -> FetchResult | FetchError:
    """Fetch *url*, recovering moved GitHub raw paths on HTTP 404."""
    result = await fetch_plugin_bytes_async(
        client,
        url,
        max_bytes=max_bytes,
        trusted_hosts=trusted_hosts,
        check_private=check_private,
        resolver=resolver,
    )
    if not isinstance(result, FetchError) or not is_http_not_found(result):
        return result
    recovered = await recover_github_raw_url_async(
        client,
        url,
        basename=basename,
    )
    if not recovered:
        return result
    return await fetch_plugin_bytes_async(
        client,
        recovered,
        max_bytes=max_bytes,
        trusted_hosts=trusted_hosts,
        check_private=check_private,
        resolver=resolver,
    )


def fetch_with_github_recovery(
    client: httpx.Client,
    url: str,
    *,
    basename: str | None = None,
    max_bytes: int = MAX_PLUGIN_BYTES,
    trusted_hosts: Collection[str] | None = None,
    check_private: bool = True,
    resolver: Callable[..., list] | None = None,
) -> FetchResult | FetchError:
    """Synchronous variant of :func:`fetch_with_github_recovery_async`."""
    result = fetch_plugin_bytes(
        client,
        url,
        max_bytes=max_bytes,
        trusted_hosts=trusted_hosts,
        check_private=check_private,
        resolver=resolver,
    )
    if not isinstance(result, FetchError) or not is_http_not_found(result):
        return result
    recovered = recover_github_raw_url(
        client,
        url,
        basename=basename,
    )
    if not recovered:
        return result
    return fetch_plugin_bytes(
        client,
        recovered,
        max_bytes=max_bytes,
        trusted_hosts=trusted_hosts,
        check_private=check_private,
        resolver=resolver,
    )
