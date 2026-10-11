"""Tests for install provenance sidecar."""

from __future__ import annotations

from pathlib import Path

import pytest

from qbit_plugin_dl.categories import load_categories_cache
from qbit_plugin_dl.provenance import (
    content_sha256,
    list_fixed_filenames,
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

_CORRUPT_SIDECARS = {
    "non_utf8": b"\xff\xfe\x00garbage",
    "deep_nesting": b"[" * 100_000 + b"]" * 100_000,
    "truncated": b'{"demo.py": {"sha": ',
    "top_level_list": b'["demo.py"]',
    "non_dict_entries": b'{"demo.py": "oops", "ok.py": {"fixed": true}}',
}


@pytest.mark.parametrize("case", sorted(_CORRUPT_SIDECARS))
def test_corrupt_provenance_never_raises(tmp_path: Path, case: str):
    path = tmp_path / "installed.json"
    path.write_bytes(_CORRUPT_SIDECARS[case])
    data = load_installed_provenance(path)
    assert all(isinstance(v, dict) for v in data.values())
    expected_fixed = {"ok.py"} if case == "non_dict_entries" else set()
    assert list_fixed_filenames(path) == expected_fixed
    # A fresh install record replaces the damaged file instead of raising.
    record_install_provenance(
        "demo.py", download_url="https://example.com/demo.py", sha="ab", path=path
    )
    assert load_installed_provenance(path)["demo.py"]["sha"] == "ab"


@pytest.mark.parametrize("case", sorted(_CORRUPT_SIDECARS))
def test_corrupt_categories_cache_never_raises(tmp_path: Path, case: str):
    path = tmp_path / "categories.json"
    path.write_bytes(_CORRUPT_SIDECARS[case])
    cache = load_categories_cache(path)
    assert all(isinstance(v, dict) for v in cache.values())
