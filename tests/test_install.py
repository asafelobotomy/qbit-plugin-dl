"""Tests for install path helpers and download hardening."""

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qbit_plugin_dl.audit_clamav import ClamAvSession
from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.install import (
    MAX_PLUGIN_BYTES,
    candidate_engine_dirs,
    detect_engine_dirs,
    engine_dir_kind,
    format_engine_dir_label,
    install_plugins_async,
    require_https_url,
    resolve_install_dir,
    resolve_plugin_dest,
    uninstall_plugin,
    uninstall_plugins,
    validate_plugin_filename,
)
from qbit_plugin_dl.provenance import (
    content_sha,
    content_sha256,
    load_installed_provenance,
    record_install_provenance,
)
from tests.fixtures.engine_stubs import CLEAN_ENGINE_BYTES, engine_source
from tests.http_fakes import TRUSTED_TEST_HOSTS, AsyncSingleClient


def _plugin(**kwargs) -> Plugin:
    base = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1",
        last_update="",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    return replace(base, **kwargs) if kwargs else base

def test_candidate_order(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    dirs = candidate_engine_dirs(tmp_path)
    assert dirs[0].as_posix().endswith(
        ".var/app/org.qbittorrent.qBittorrent/data/qBittorrent/nova3/engines"
    )
    assert dirs[1] == tmp_path / "xdg" / "qBittorrent" / "nova3" / "engines"
    assert dirs[2] == tmp_path / "xdg" / "data" / "qBittorrent" / "nova3" / "engines"


def test_resolve_creates_native(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target = resolve_install_dir(tmp_path)
    assert target == tmp_path / "xdg" / "qBittorrent" / "nova3" / "engines"
    assert target.is_dir()


def test_resolve_prefers_existing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    legacy = tmp_path / "xdg" / "data" / "qBittorrent" / "nova3" / "engines"
    legacy.mkdir(parents=True)
    found = detect_engine_dirs(tmp_path)
    assert found == [legacy]
    assert resolve_install_dir(tmp_path) == legacy


def test_resolve_preferred(tmp_path: Path):
    custom = tmp_path / "custom" / "engines"
    assert resolve_install_dir(tmp_path, preferred=custom) == custom
    assert custom.is_dir()


def test_engine_dir_labels(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    flatpak, native, legacy = candidate_engine_dirs(tmp_path)
    assert engine_dir_kind(flatpak, home=tmp_path) == "Flatpak"
    assert engine_dir_kind(native, home=tmp_path) == "Native"
    assert engine_dir_kind(legacy, home=tmp_path) == "Legacy"
    assert "Flatpak —" in format_engine_dir_label(flatpak, home=tmp_path)
    assert "(will create)" in format_engine_dir_label(
        native, will_create=True, home=tmp_path
    )


def test_validate_plugin_filename_ok():
    assert validate_plugin_filename("engine.py") == "engine.py"


@pytest.mark.parametrize(
    "name",
    ["", "..", "../x.py", "a/b.py", "a\\b.py", "nope.txt", "."],
)
def test_validate_plugin_filename_rejects(name: str):
    with pytest.raises(ValueError):
        validate_plugin_filename(name)


def test_resolve_plugin_dest_contains(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    dest = resolve_plugin_dest(engines, "ok.py")
    assert dest == (engines / "ok.py").resolve()
    assert dest.parent == engines.resolve()


def test_require_https_url():
    assert require_https_url("https://example.com/a.py").startswith("https://")
    with pytest.raises(ValueError):
        require_https_url("http://example.com/a.py")
    with pytest.raises(ValueError):
        require_https_url("ftp://example.com/a.py")


def test_install_rejects_http(tmp_path: Path):
    engines = tmp_path / "engines"
    plugin = _plugin(download_url="http://example.com/demo.py")
    results = asyncio.run(install_plugins_async([plugin], engines))
    assert len(results) == 1
    assert not results[0].ok
    assert "HTTPS" in (results[0].error or "")


def test_install_rejects_oversize(tmp_path: Path):
    engines = tmp_path / "engines"
    plugin = _plugin()
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncSingleClient(  # type: ignore[arg-type]
                b"x" * (MAX_PLUGIN_BYTES + 1),
                plugin.download_url,
                chunk_size=64 * 1024,
            ),
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert not results[0].ok
    assert "too large" in (results[0].error or "")


def test_install_writes_under_engines(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncSingleClient(  # type: ignore[arg-type]
                CLEAN_ENGINE_BYTES, plugin.download_url
            ),
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert results[0].ok
    assert results[0].path is not None
    assert results[0].path.parent == engines.resolve()
    assert results[0].path.read_bytes() == CLEAN_ENGINE_BYTES
    assert results[0].audit is not None
    assert not results[0].audit.blocked
    assert not (engines / "demo.py.tmp").exists()
    assert list(engines.glob("*.tmp")) == []

    provenance = load_installed_provenance()
    assert provenance["demo.py"]["download_url"] == plugin.download_url
    assert provenance["demo.py"]["sha"] == content_sha(CLEAN_ENGINE_BYTES)
    assert provenance["demo.py"]["sha256"] == content_sha256(CLEAN_ENGINE_BYTES)


def test_install_rejects_https_redirect_to_http(tmp_path: Path):
    engines = tmp_path / "engines"
    plugin = _plugin()
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncSingleClient(  # type: ignore[arg-type]
                CLEAN_ENGINE_BYTES, "http://example.com/demo.py"
            ),
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert not results[0].ok
    assert "HTTPS" in (results[0].error or "")


def test_install_does_not_write_on_safety_fail(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()
    malicious = engine_source(body="exec('bad')").encode()
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncSingleClient(  # type: ignore[arg-type]
                malicious, plugin.download_url
            ),
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert not results[0].ok
    assert results[0].audit is not None
    assert results[0].audit.blocked
    assert "Safety check" in (results[0].error or "")
    assert not (engines / "demo.py").exists()
    assert list(engines.glob("*.py")) == []


def test_install_blocks_on_clam_hit(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()

    def which(name: str) -> str | None:
        return "/usr/bin/clamdscan" if name == "clamdscan" else None

    def run(argv, **kwargs):  # noqa: ANN001
        if "--ping" in argv:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(
            returncode=1,
            stdout="demo.py: Eicar-Test-Signature FOUND\n",
            stderr="",
        )

    session = ClamAvSession(enabled=True, which=which, run=run)
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncSingleClient(  # type: ignore[arg-type]
                CLEAN_ENGINE_BYTES, plugin.download_url
            ),
            clamav_session=session,
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert not results[0].ok
    assert results[0].audit is not None
    assert results[0].audit.clamav_status == "infected"
    assert not (engines / "demo.py").exists()

def test_uninstall_removes_engine_companions_and_provenance(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    nova3 = tmp_path / "nova3"
    engines = nova3 / "engines"
    engines.mkdir(parents=True)
    (engines / "jackett.py").write_text("# engine\n", encoding="utf-8")
    (engines / "jackett.py.tmp").write_text("tmp", encoding="utf-8")
    (engines / "jackett.json").write_text('{"api_key": "x"}', encoding="utf-8")
    pycache = engines / "__pycache__"
    pycache.mkdir()
    (pycache / "jackett.cpython-312.pyc").write_bytes(b"\0")
    nova_cache = nova3 / "__pycache__"
    nova_cache.mkdir()
    (nova_cache / "jackett.cpython-312.pyc").write_bytes(b"\0")
    # Unrelated engine must survive.
    (engines / "other.py").write_text("# keep\n", encoding="utf-8")
    (engines / "other.json").write_text("{}", encoding="utf-8")

    record_install_provenance(
        "jackett.py",
        download_url="https://example.com/jackett.py",
        sha="deadbeef",
    )
    record_install_provenance(
        "other.py",
        download_url="https://example.com/other.py",
        sha="cafebabe",
    )

    plugin = _plugin(
        name="Jackett",
        download_url="https://example.com/jackett.py",
    )
    assert plugin.filename == "jackett.py"

    results = uninstall_plugins([plugin], engines)
    assert len(results) == 1
    assert results[0].ok
    assert not (engines / "jackett.py").exists()
    assert not (engines / "jackett.py.tmp").exists()
    assert not (engines / "jackett.json").exists()
    assert list(pycache.glob("jackett*")) == []
    assert list(nova_cache.glob("jackett*")) == []
    assert (engines / "other.py").exists()
    assert (engines / "other.json").exists()

    provenance = load_installed_provenance()
    assert "jackett.py" not in provenance
    assert "other.py" in provenance


def test_uninstall_idempotent_when_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    engines.mkdir()
    plugin = _plugin()
    result = uninstall_plugin(plugin.filename, engines, plugin=plugin)
    assert result.ok
    assert result.removed == ()


def test_uninstall_dedupes_shared_filename(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    engines.mkdir()
    (engines / "demo.py").write_text("x", encoding="utf-8")
    a = _plugin(name="A", author="one")
    b = _plugin(name="B", author="two")
    results = uninstall_plugins([a, b], engines)
    assert len(results) == 1
    assert results[0].ok
    assert not (engines / "demo.py").exists()


def test_uninstall_rejects_path_trick(tmp_path: Path):
    engines = tmp_path / "engines"
    engines.mkdir()
    result = uninstall_plugin("../etc/passwd.py", engines)
    assert not result.ok
    assert "basename" in (result.error or "").lower() or "Invalid" in (
        result.error or ""
    )
