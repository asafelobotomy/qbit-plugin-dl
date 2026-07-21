"""Tests for install path helpers and download hardening."""

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
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
    validate_plugin_filename,
)
from qbit_plugin_dl.provenance import content_sha, load_installed_provenance
from tests.fixtures.engine_stubs import CLEAN_ENGINE_BYTES, engine_source


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


class _FakeResponse:
    def __init__(self, content: bytes, url: str) -> None:
        self.content = content
        self.url = httpx.URL(url)

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    def __init__(self, content: bytes, url: str) -> None:
        self._content = content
        self._url = url

    async def get(self, url: str) -> _FakeResponse:
        return _FakeResponse(self._content, self._url)

    async def aclose(self) -> None:
        return None


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
            client=_FakeClient(b"x" * (MAX_PLUGIN_BYTES + 1), plugin.download_url),  # type: ignore[arg-type]
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
            client=_FakeClient(CLEAN_ENGINE_BYTES, plugin.download_url),  # type: ignore[arg-type]
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


def test_install_rejects_https_redirect_to_http(tmp_path: Path):
    engines = tmp_path / "engines"
    plugin = _plugin()
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=_FakeClient(CLEAN_ENGINE_BYTES, "http://example.com/demo.py"),  # type: ignore[arg-type]
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
            client=_FakeClient(malicious, plugin.download_url),  # type: ignore[arg-type]
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
            client=_FakeClient(CLEAN_ENGINE_BYTES, plugin.download_url),  # type: ignore[arg-type]
            clamav_session=session,
        )
    )
    assert not results[0].ok
    assert results[0].audit is not None
    assert results[0].audit.clamav_status == "infected"
    assert not (engines / "demo.py").exists()