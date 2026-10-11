"""XDG-aware cache/config paths for qbit-plugin-dl."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

APP_DIR_NAME = "qbit-plugin-dl"
LEGACY_CACHE_DIR_NAME = "qbitPluginDL"


def xdg_base_dir(env_var: str, default: Path) -> Path:
    """
    Resolve an XDG base directory variable.

    Per the XDG spec, unset, empty or relative values are ignored — a relative
    value would otherwise place data under the current working directory.
    """
    value = os.environ.get(env_var, "")
    if value and os.path.isabs(value):
        return Path(value)
    return default


def cache_home() -> Path:
    """Return XDG cache home (or ~/.cache)."""
    return xdg_base_dir("XDG_CACHE_HOME", Path.home() / ".cache")


def config_home() -> Path:
    """Return XDG config home (or ~/.config)."""
    return xdg_base_dir("XDG_CONFIG_HOME", Path.home() / ".config")


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


def read_json_file(path: Path) -> object | None:
    """
    Parse a JSON sidecar, or None when missing/unreadable/corrupt.

    Catches non-UTF-8 bytes (``UnicodeDecodeError``) and pathological nesting
    (``RecursionError``) as well as plain syntax errors, so a damaged cache
    never crashes startup or aborts an install batch.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def read_json_object_of_dicts(path: Path) -> dict[str, dict]:
    """Load a ``{str: {...}}`` sidecar, dropping malformed entries."""
    data = read_json_file(path)
    if not isinstance(data, dict):
        return {}
    return {
        key: value
        for key, value in data.items()
        if isinstance(key, str) and isinstance(value, dict)
    }


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """
    Write *data* to *path* atomically (unique sibling temp file + ``os.replace``).

    The temp file is created with ``O_EXCL`` and mode 0600 under a random name,
    so a pre-planted symlink cannot redirect the write and concurrent writers
    never share a temp file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    """Best-effort: persist the rename itself."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Text wrapper around :func:`atomic_write_bytes`."""
    atomic_write_bytes(path, text.encode(encoding))
