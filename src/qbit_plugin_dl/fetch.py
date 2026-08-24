"""Shared HTTPS download helpers with size, host, and private-IP controls."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from qbit_plugin_dl.url_recover import (
    is_http_not_found,
    parse_github_raw_url,
    recover_github_raw_url,
    recover_github_raw_url_async,
)

# Keep in sync with install / categories / updates callers.
MAX_PLUGIN_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5

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
    """Reject non-HTTPS download URLs."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"HTTPS required for plugin downloads: {url}")
    if not parsed.netloc:
        raise ValueError(f"Invalid download URL: {url}")
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
    raw = parse_github_raw_url(url)
    if raw is not None:
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
        ip.is_private
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


def _read_limited_body(
    response: httpx.Response,
    *,
    max_bytes: int,
    iter_chunks: Callable[[], Iterable[bytes]],
) -> FetchResult | FetchError:
    final_url = str(response.url)
    try:
        require_https_url(final_url)
    except ValueError as exc:
        return FetchError(message=str(exc), code="https")

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

    chunks: list[bytes] = []
    total = 0
    for chunk in iter_chunks():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            return FetchError(
                message=(
                    f"Response too large ({total} bytes > "
                    f"{max_bytes} bytes limit)"
                ),
                code="size",
            )
        chunks.append(chunk)
    content = b"".join(chunks)
    if not content.strip():
        return FetchError(message="Empty response", code="empty")
    return FetchResult(content=content, final_url=final_url)


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
                "GET", current, follow_redirects=False
            ) as response:
                target = _redirect_target(current, response)
                if target is not None:
                    # Drain / close without reading body; advance to next hop.
                    current = target
                    continue

                if response.is_redirect:
                    return FetchError(
                        message="Redirect without Location header",
                        code="redirect",
                    )
                if len(response.history) > MAX_REDIRECTS:
                    return FetchError(
                        message=f"Too many redirects (>{MAX_REDIRECTS})",
                        code="redirect",
                    )
                response.raise_for_status()
                final_url = str(response.url)
                try:
                    require_https_url(final_url)
                except ValueError as exc:
                    return FetchError(message=str(exc), code="https")

                chunks: list[bytes] = []
                total = 0
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
                async for chunk in response.aiter_bytes():
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        return FetchError(
                            message=(
                                f"Response too large ({total} bytes > "
                                f"{max_bytes} bytes limit)"
                            ),
                            code="size",
                        )
                    chunks.append(chunk)
                content = b"".join(chunks)
                if not content.strip():
                    return FetchError(message="Empty response", code="empty")
                return FetchResult(content=content, final_url=final_url)

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

            with client.stream("GET", current, follow_redirects=False) as response:
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
