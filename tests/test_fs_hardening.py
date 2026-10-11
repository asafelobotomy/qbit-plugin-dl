"""Low-severity filesystem hardening: temp files, bytecode cleanup, XDG paths."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from qbit_plugin_dl.install import (
    candidate_engine_dirs,
    companion_paths_for_engine,
    uninstall_plugin,
)
from qbit_plugin_dl.paths import atomic_write_bytes, atomic_write_text, cache_home


def test_atomic_write_ignores_planted_tmp_symlink(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    target = tmp_path / "engines" / "evil.py"
    target.parent.mkdir()
    # Old code opened "<dest>.tmp" with O_TRUNC, following this symlink.
    (target.parent / "evil.py.tmp").symlink_to(victim)

    atomic_write_bytes(target, b"print('engine')\n")

    assert victim.read_text() == "keep me"
    assert not target.is_symlink()
    assert target.read_bytes() == b"print('engine')\n"
    assert oct(target.stat().st_mode & 0o777) == oct(0o600)
    assert not list(target.parent.glob(".evil.py.*.tmp"))


def test_concurrent_atomic_writes_never_interleave(tmp_path: Path):
    path = tmp_path / "categories.json"
    payloads = [f'{{"writer": {i}, "pad": "{"x" * 50_000}"}}' for i in range(8)]

    threads = [
        threading.Thread(target=atomic_write_text, args=(path, payload))
        for payload in payloads
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert path.read_text() in payloads
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".*.tmp"))


def test_uninstall_bytecode_is_exact(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "nova3" / "engines"
    pycache = engines / "__pycache__"
    pycache.mkdir(parents=True)
    (engines / "foo.py").write_text("x = 1\n")
    keep = [
        pycache / "foobar.cpython-312.pyc",
        pycache / "foo_extra.cpython-312.pyc",
        tmp_path / "nova3" / "__pycache__" / "novaprinter.cpython-312.pyc",
    ]
    drop = [pycache / "foo.cpython-312.pyc", pycache / "foo.pyc"]
    keep[2].parent.mkdir(parents=True)
    for path in keep + drop:
        path.write_bytes(b"\0")
    leftover = engines / ".foo.py.abc123.tmp"
    leftover.write_bytes(b"partial")

    companions = set(companion_paths_for_engine(engines, "foo.py"))
    assert leftover in companions
    result = uninstall_plugin("foo.py", engines)

    assert result.ok
    assert all(p.exists() for p in keep)
    assert not any(p.exists() for p in drop)
    assert not leftover.exists()


@pytest.mark.parametrize("value", ["", "relative/dir", "./x"])
def test_invalid_xdg_values_ignored(tmp_path: Path, monkeypatch, value: str):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", value)
    monkeypatch.setenv("XDG_CACHE_HOME", value)
    dirs = candidate_engine_dirs(tmp_path)
    assert all(d.is_absolute() for d in dirs)
    assert dirs[1] == tmp_path / ".local" / "share" / "qBittorrent" / "nova3" / "engines"
    assert cache_home() == Path(os.path.expanduser("~")) / ".cache"
