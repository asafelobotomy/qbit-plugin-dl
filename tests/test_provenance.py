"""Tests for install provenance sidecar."""

from __future__ import annotations

from pathlib import Path

from qbit_plugin_dl.provenance import (
    content_sha256,
    load_installed_provenance,
    record_install_provenance,
)


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
