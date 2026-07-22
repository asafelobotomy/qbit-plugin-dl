"""XDG-aware cache/config paths for qbit-plugin-dl."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

APP_DIR_NAME = "qbit-plugin-dl"
LEGACY_CACHE_DIR_NAME = "qbitPluginDL"


def cache_home() -> Path:
    """Return XDG cache home (or ~/.cache)."""
    override = os.environ.get("XDG_CACHE_HOME")
    if override:
        return Path(override)
    return Path.home() / ".cache"


def config_home() -> Path:
    """Return XDG config home (or ~/.config)."""
    override = os.environ.get("XDG_CONFIG_HOME")
    if override:
        return Path(override)
    return Path.home() / ".config"


def cache_dir() -> Path:
    """
    Application cache directory under XDG_CACHE_HOME.

    Migrates once from the legacy ~/.cache/qbitPluginDL directory when present.
    """
    target = cache_home() / APP_DIR_NAME
    legacy = cache_home() / LEGACY_CACHE_DIR_NAME
    if not target.exists() and legacy.is_dir():
        try:
            shutil.move(str(legacy), str(target))
        except OSError:
            # Fall back to copy if move fails (e.g. cross-device issues).
            target.mkdir(parents=True, exist_ok=True)
            for item in legacy.iterdir():
                dest = target / item.name
                if item.is_file() and not dest.exists():
                    shutil.copy2(item, dest)
    target.mkdir(parents=True, exist_ok=True)
    return target


def config_dir() -> Path:
    """
    Application config directory under XDG_CONFIG_HOME.

    Reserved for future file-based config. Runtime preferences (e.g. safety
    acceptance) currently use Qt ``QSettings``, not this directory.
    """
    path = config_home() / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write *text* via a sibling ``.tmp`` then ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
