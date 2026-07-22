"""Tests for install provenance and content-hash update detection."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.provenance import (
    content_sha,
    content_sha256,
    load_installed_provenance,
    record_install_provenance,
    remove_install_provenance,
)
from qbit_plugin_dl.updates import (
    find_outdated_filenames,
    plugins_for_updates,
    resolve_catalog_plugin,
)


def _plugin(**kwargs) -> Plugin:
    base = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1.0",
        last_update="1/Jan 2024",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    return replace(base, **kwargs) if kwargs else base


def test_content_sha_stable():
    assert content_sha("hello") == content_sha(b"hello")
    assert content_sha("a") != content_sha("b")
    # Truncated hash is the prefix of the full raw-byte digest.
    payload = b"raw\xffbytes"
    assert content_sha(payload) == content_sha256(payload)[:16]


def test_record_and_load_provenance(tmp_path: Path, monkeypatch):
    path = tmp_path / "installed.json"
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    record_install_provenance(
        "demo.py",
        download_url="https://example.com/demo.py",
        sha="abcd",
        path=path,
    )
    data = load_installed_provenance(path)
    assert data["demo.py"]["download_url"] == "https://example.com/demo.py"
    assert data["demo.py"]["sha"] == "abcd"
    assert "installed_at" in data["demo.py"]


def test_remove_install_provenance(tmp_path: Path):
    path = tmp_path / "installed.json"
    record_install_provenance(
        "demo.py",
        download_url="https://example.com/demo.py",
        sha="abcd",
        path=path,
    )
    record_install_provenance(
        "other.py",
        download_url="https://example.com/other.py",
        sha="ef01",
        path=path,
    )
    assert remove_install_provenance("demo.py", path=path) is True
    data = load_installed_provenance(path)
    assert "demo.py" not in data
    assert "other.py" in data
    assert remove_install_provenance("demo.py", path=path) is False


def test_resolve_prefers_provenance_url():
    primary = _plugin(
        name="Demo",
        author="preferred",
        download_url="https://example.com/primary/demo.py",
    )
    alternate = _plugin(
        name="Demo Alt",
        author="alt",
        download_url="https://example.com/alt/demo.py",
    )
    catalog = [primary, alternate]
    provenance = {
        "demo.py": {"download_url": alternate.download_url, "sha": "x"},
    }
    resolved = resolve_catalog_plugin(
        "demo.py",
        catalog=catalog,
        provenance=provenance,
    )
    assert resolved is not None
    assert resolved.download_url == alternate.download_url


def test_resolve_falls_back_to_preferred_primary():
    older = _plugin(
        name="Demo",
        author="old",
        version="1.0",
        last_update="1/Jan 2020",
        download_url="https://example.com/old/demo.py",
        warning=True,
    )
    newer = _plugin(
        name="Demo",
        author="new",
        version="2.0",
        last_update="1/Jan 2025",
        download_url="https://example.com/new/demo.py",
        warning=False,
    )
    # Same filename → grouping picks preferred; no provenance.
    resolved = resolve_catalog_plugin(
        "demo.py",
        catalog=[older, newer],
        provenance={},
    )
    assert resolved is not None
    assert resolved.download_url == newer.download_url


def test_find_outdated_when_hashes_differ(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    local = engines / "demo.py"
    local.write_text("local-version\n", encoding="utf-8")
    plugin = _plugin(download_url="https://example.com/demo.py")
    remote = content_sha("remote-version\n")
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance={},
        remote_shas={plugin.download_url: remote},
    )
    assert outdated == {"demo.py"}


def test_find_outdated_when_hashes_match(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    body = "same-content\n"
    (engines / "demo.py").write_text(body, encoding="utf-8")
    plugin = _plugin(download_url="https://example.com/demo.py")
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance={},
        remote_shas={plugin.download_url: content_sha(body)},
    )
    assert outdated == set()


def test_skip_non_catalog_filename(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    (engines / "orphan.py").write_text("x\n", encoding="utf-8")
    plugin = _plugin(download_url="https://example.com/demo.py")
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance={},
        remote_shas={plugin.download_url: content_sha("y\n")},
    )
    assert outdated == set()


def test_plugins_for_updates_uses_provenance():
    primary = _plugin(
        name="Demo",
        download_url="https://example.com/primary/demo.py",
    )
    alt = _plugin(
        name="Demo Alt",
        author="alt",
        download_url="https://example.com/alt/demo.py",
    )
    plugins = plugins_for_updates(
        ["demo.py"],
        [primary, alt],
        provenance={"demo.py": {"download_url": alt.download_url}},
    )
    assert len(plugins) == 1
    assert plugins[0].download_url == alt.download_url


def test_rewritten_stable_not_outdated(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    written = b"# rewritten body\n"
    source = b"# original body\n"
    (engines / "demo.py").write_bytes(written)
    plugin = _plugin()
    provenance = {
        "demo.py": {
            "download_url": plugin.download_url,
            "sha": content_sha(written),
            "rewritten": True,
            "source_sha": content_sha(source),
        }
    }
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: content_sha(source)},
    )
    assert outdated == set()


def test_rewritten_outdated_when_upstream_changes(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    written = b"# rewritten body\n"
    source = b"# original body\n"
    upstream = b"# new upstream\n"
    (engines / "demo.py").write_bytes(written)
    plugin = _plugin()
    provenance = {
        "demo.py": {
            "download_url": plugin.download_url,
            "sha": content_sha(written),
            "rewritten": True,
            "source_sha": content_sha(source),
        }
    }
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: content_sha(upstream)},
    )
    assert outdated == {"demo.py"}


def test_rewritten_outdated_when_local_drifts(tmp_path: Path):
    """Local edits alone must not count as a catalog source update."""
    engines = tmp_path / "engines"
    engines.mkdir()
    written = b"# rewritten body\n"
    drifted = b"# manually edited\n"
    source = b"# original body\n"
    (engines / "demo.py").write_bytes(drifted)
    plugin = _plugin()
    provenance = {
        "demo.py": {
            "download_url": plugin.download_url,
            "sha": content_sha(written),
            "rewritten": True,
            "source_sha": content_sha(source),
        }
    }
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: content_sha(source)},
    )
    assert outdated == set()


def test_full_sha_not_confused_with_truncated_cache(tmp_path: Path):
    """Regression: sha256 provenance must not compare against truncated cache sha."""
    engines = tmp_path / "engines"
    engines.mkdir()
    body = b"# engine\n"
    (engines / "demo.py").write_bytes(body)
    plugin = _plugin()
    full = content_sha256(body)
    trunc = content_sha(body)
    provenance = {
        "demo.py": {
            "download_url": plugin.download_url,
            "sha": trunc,
            "sha256": full,
        }
    }
    # Categories cache only has truncated sha (pre-sha256 enrich).
    categories_cache = {
        plugin.download_url: {"sha": trunc, "fetched_at": 1.0},
    }
    outdated = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        categories_cache=categories_cache,
        remote_shas={},  # force cache path; empty map means "try cache then skip fetch"
    )
    # With empty remote_shas dict, code treats remote_shas as provided and won't fetch.
    # Cache has no sha256 → no remote → not outdated (avoid false positive).
    assert outdated == set()

    # Same-width remote match → not outdated.
    outdated_ok = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: full},
    )
    assert outdated_ok == set()

    # Real upstream change → outdated.
    outdated_real = find_outdated_filenames(
        engines,
        [plugin],
        provenance=provenance,
        remote_shas={plugin.download_url: content_sha256(b"# newer\n")},
    )
    assert outdated_real == {"demo.py"}
