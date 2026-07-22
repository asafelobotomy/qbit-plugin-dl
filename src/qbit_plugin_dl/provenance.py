"""Install provenance sidecar for tracking which catalog URL was written."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from qbit_plugin_dl.paths import atomic_write_text, cache_dir


def installed_provenance_file() -> Path:
    """Path to the install provenance JSON (XDG-aware)."""
    return cache_dir() / "installed.json"


def content_sha(data: str | bytes) -> str:
    """Truncated SHA-256 matching categories cache style (legacy)."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def content_sha256(data: str | bytes) -> str:
    """Full SHA-256 of raw bytes (strings encoded as UTF-8)."""
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    return hashlib.sha256(payload).hexdigest()


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
    atomic_write_text(
        path,
        json.dumps(dict(provenance), indent=2, sort_keys=True),
    )


def record_install_provenance(
    filename: str,
    *,
    download_url: str,
    sha: str,
    path: Path | None = None,
    fixed: bool = False,
    rewritten: bool = False,
    fix_kinds: Sequence[str] | None = None,
    source_sha: str | None = None,
    sha256: str | None = None,
    source_sha256: str | None = None,
) -> None:
    """Upsert one successful install into the provenance sidecar.

    ``sha`` / ``sha256`` are hashes of bytes written to disk (post-fix expected).
    ``source_sha`` / ``source_sha256`` are hashes of the downloaded body before AST.
    """
    cache_path = path or installed_provenance_file()
    data = load_installed_provenance(cache_path)
    entry: dict = {
        "download_url": download_url,
        "sha": sha,
        "installed_at": time.time(),
    }
    if sha256:
        entry["sha256"] = sha256
    if fixed:
        entry["fixed"] = True
        entry["rewritten"] = bool(rewritten)
        entry["fix_kinds"] = list(fix_kinds or [])
    if rewritten and source_sha:
        entry["source_sha"] = source_sha
    if rewritten and source_sha256:
        entry["source_sha256"] = source_sha256
    data[filename] = entry
    save_installed_provenance(data, cache_path)


def remove_install_provenance(
    filename: str,
    *,
    path: Path | None = None,
) -> bool:
    """Remove one install record. Returns True if an entry was deleted."""
    cache_path = path or installed_provenance_file()
    data = load_installed_provenance(cache_path)
    if filename not in data:
        return False
    del data[filename]
    save_installed_provenance(data, cache_path)
    return True


def list_fixed_filenames(path: Path | None = None) -> set[str]:
    """Basenames whose provenance marks a successful install-time Fix."""
    data = load_installed_provenance(path)
    fixed: set[str] = set()
    for filename, entry in data.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("fixed") or entry.get("rewritten"):
            fixed.add(filename)
    return fixed


def fix_kinds_for_filename(filename: str, path: Path | None = None) -> list[str]:
    """Return stored fix_kinds for a basename, or empty."""
    entry = load_installed_provenance(path).get(filename)
    if not isinstance(entry, dict):
        return []
    kinds = entry.get("fix_kinds")
    if isinstance(kinds, list):
        return [str(k) for k in kinds]
    return []
