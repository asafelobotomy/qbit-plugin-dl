"""Shared pytest fixtures for qbit-plugin-dl tests."""

from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def _public_dns_for_download_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Avoid real DNS (and private-IP fails) in unit tests that hit fetch host checks.

    Individual tests that need private-IP behavior should patch
    ``qbit_plugin_dl.fetch.socket.getaddrinfo`` themselves.
    """

    def fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001
        del args, kwargs
        # Public address — never blocked by assert_host_not_private.
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("1.1.1.1", 0),
            )
        ]

    monkeypatch.setattr(
        "qbit_plugin_dl.fetch.socket.getaddrinfo",
        fake_getaddrinfo,
    )
