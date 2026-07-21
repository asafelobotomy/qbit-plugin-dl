"""Tests for XDG cache paths and legacy migration."""

from pathlib import Path

from qbit_plugin_dl import paths


def test_cache_dir_uses_xdg(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    target = paths.cache_dir()
    assert target == tmp_path / "cache" / "qbit-plugin-dl"
    assert target.is_dir()


def test_cache_migrates_legacy(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    legacy = tmp_path / "cache" / "qbitPluginDL"
    legacy.mkdir(parents=True)
    (legacy / "catalog.mediawiki").write_text("old", encoding="utf-8")
    (legacy / "categories.json").write_text("{}", encoding="utf-8")

    target = paths.cache_dir()
    assert target == tmp_path / "cache" / "qbit-plugin-dl"
    assert (target / "catalog.mediawiki").read_text(encoding="utf-8") == "old"
    assert (target / "categories.json").read_text(encoding="utf-8") == "{}"
    assert not legacy.exists()


def test_config_dir_uses_xdg(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    target = paths.config_dir()
    assert target == tmp_path / "config" / "qbit-plugin-dl"
    assert target.is_dir()
