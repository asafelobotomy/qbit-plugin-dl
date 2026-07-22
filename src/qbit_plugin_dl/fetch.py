"""Shared HTTPS download helpers with size, host, and private-IP controls."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

# Keep in sync with install / categories / updates callers.
MAX_PLUGIN_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5

# Final download hosts that do not need user consent.
ALLOWED_DOWNLOAD_HOSTS: frozenset[str] = frozenset(
    {
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
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
    code: str  # https | size | empty | host | private | network | redirect
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


def is_allowlisted_host(host: str) -> bool:
    return host.lower() in ALLOWED_DOWNLOAD_HOSTS


def host_is_trusted(host: str, trusted_hosts: Collection[str] | None = None) -> bool:
    """True when host is allowlisted or present in the caller-supplied trust set."""
    host = host.lower()
    if is_allowlisted_host(host):
        return True
    if not trusted_hosts:
        return False
    return host in {h.lower() for h in trusted_hosts}


def untrusted_hosts_in_urls(
    urls: Iterable[str],
    *,
    trusted_hosts: Collection[str] | None = None,
) -> list[str]:
    """Unique non-allowlisted hosts from catalog URLs (pre-prompt hint)."""
    seen: set[str] = set()
    ordered: list[str] = []
    for url in urls:
        try:
            require_https_url(url)
        except ValueError:
            continue
        host = hostname_from_url(url)
        if not host or host_is_trusted(host, trusted_hosts):
            continue
        if host not in seen:
            seen.add(host)
            ordered.append(host)
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


def check_download_host(
    url: str,
    *,
    trusted_hosts: Collection[str] | None = None,
    check_private: bool = True,
    resolver: Callable[..., list] | None = None,
) -> str | None:
    """
    Validate host policy for *url*.

    Returns None when OK, otherwise an error message.
    """
    try:
        require_https_url(url)
    except ValueError as exc:
        return str(exc)
    host = hostname_from_url(url)
    if not host:
        return f"Invalid download URL: {url}"
    if not host_is_trusted(host, trusted_hosts):
        return (
            f"Untrusted download host: {host} — approve this host and re-run install"
        )
    if check_private:
        try:
            assert_host_not_private(host, resolver=resolver)
        except ValueError as exc:
            return str(exc)
    return None


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
    """
    try:
        require_https_url(url)
    except ValueError as exc:
        return FetchError(message=str(exc), code="https")

    pre_host_err = check_download_host(
        url,
        trusted_hosts=trusted_hosts,
        check_private=check_private,
        resolver=resolver,
    )
    if pre_host_err:
        code = "private" if "private" in pre_host_err.lower() or "link-local" in pre_host_err.lower() or "DNS" in pre_host_err else "host"
        if "DNS" in pre_host_err:
            code = "network"
        return FetchError(
            message=pre_host_err,
            code=code,
            host=hostname_from_url(url),
        )

    try:
        async with client.stream("GET", url, follow_redirects=True) as response:
            # Cap redirect hops when transport exposes history.
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

            final_err = check_download_host(
                final_url,
                trusted_hosts=trusted_hosts,
                check_private=check_private,
                resolver=resolver,
            )
            if final_err:
                code = "host"
                lower = final_err.lower()
                if "private" in lower or "link-local" in lower:
                    code = "private"
                elif "dns" in lower:
                    code = "network"
                return FetchError(
                    message=final_err,
                    code=code,
                    host=hostname_from_url(final_url),
                )

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
    except httpx.HTTPStatusError as exc:
        return FetchError(message=str(exc), code="network")
    except Exception as exc:  # noqa: BLE001
        return FetchError(message=str(exc), code="network")

    if not content.strip():
        return FetchError(message="Empty response", code="empty")
    return FetchResult(content=content, final_url=final_url)


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
    try:
        require_https_url(url)
    except ValueError as exc:
        return FetchError(message=str(exc), code="https")

    pre_host_err = check_download_host(
        url,
        trusted_hosts=trusted_hosts,
        check_private=check_private,
        resolver=resolver,
    )
    if pre_host_err:
        code = "host"
        lower = pre_host_err.lower()
        if "private" in lower or "link-local" in lower:
            code = "private"
        elif "dns" in lower:
            code = "network"
        return FetchError(
            message=pre_host_err,
            code=code,
            host=hostname_from_url(url),
        )

    try:
        with client.stream("GET", url, follow_redirects=True) as response:
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

            final_err = check_download_host(
                final_url,
                trusted_hosts=trusted_hosts,
                check_private=check_private,
                resolver=resolver,
            )
            if final_err:
                code = "host"
                lower = final_err.lower()
                if "private" in lower or "link-local" in lower:
                    code = "private"
                elif "dns" in lower:
                    code = "network"
                return FetchError(
                    message=final_err,
                    code=code,
                    host=hostname_from_url(final_url),
                )

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
            for chunk in response.iter_bytes():
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
    except httpx.HTTPStatusError as exc:
        return FetchError(message=str(exc), code="network")
    except Exception as exc:  # noqa: BLE001
        return FetchError(message=str(exc), code="network")

    if not content.strip():
        return FetchError(message="Empty response", code="empty")
    return FetchResult(content=content, final_url=final_url)
