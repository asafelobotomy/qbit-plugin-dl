"""Install provenance sidecar for tracking which catalog URL was written."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from pathlib import Path

from qbit_plugin_dl.paths import cache_dir


def installed_provenance_file() -> Path:
    """Path to the install provenance JSON (XDG-aware)."""
    return cache_dir() / "installed.json"


def content_sha(data: str | bytes) -> str:
    """Truncated SHA-256 matching categories cache style."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def load_installed_provenance(path: Path | None = None) -> dict[str, dict]:
    path = path or installed_provenance_file()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_installed_provenance(
    provenance: Mapping[str, dict],
    path: Path | None = None,
) -> None:
    path = path or installed_provenance_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(provenance), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def record_install_provenance(
    filename: str,
    *,
    download_url: str,
    sha: str,
    path: Path | None = None,
) -> None:
    """Upsert one successful install into the provenance sidecar."""
    cache_path = path or installed_provenance_file()
    data = load_installed_provenance(cache_path)
    data[filename] = {
        "download_url": download_url,
        "sha": sha,
        "installed_at": time.time(),
    }
    save_installed_provenance(data, cache_path)
