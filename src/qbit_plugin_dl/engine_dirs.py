"""Find qBittorrent's engines directories and validate engine filenames."""

from __future__ import annotations

import re
from pathlib import Path

from qbit_plugin_dl.paths import xdg_base_dir


def candidate_engine_dirs(home: Path | None = None) -> list[Path]:
    """Return known Linux engines paths in preference order."""
    home = home or Path.home()
    xdg_data = xdg_base_dir("XDG_DATA_HOME", home / ".local" / "share")
    return [
        home
        / ".var"
        / "app"
        / "org.qbittorrent.qBittorrent"
        / "data"
        / "qBittorrent"
        / "nova3"
        / "engines",
        xdg_data / "qBittorrent" / "nova3" / "engines",
        xdg_data / "data" / "qBittorrent" / "nova3" / "engines",
    ]


def detect_engine_dirs(home: Path | None = None) -> list[Path]:
    """Return existing engines directories (may be empty)."""
    return [path for path in candidate_engine_dirs(home) if path.is_dir()]


def resolve_install_dir(home: Path | None = None, preferred: Path | None = None) -> Path:
    """
    Choose an install directory.

    Prefer an explicit path, else the first existing candidate, else create the
    modern native path.
    """
    if preferred is not None:
        preferred.mkdir(parents=True, exist_ok=True)
        return preferred

    existing = detect_engine_dirs(home)
    if existing:
        return existing[0]

    target = candidate_engine_dirs(home)[1]
    target.mkdir(parents=True, exist_ok=True)
    return target


def engine_dir_kind(path: Path, home: Path | None = None) -> str:
    """Classify an engines path as Flatpak, Native, Legacy, or Custom."""
    candidates = candidate_engine_dirs(home)
    resolved = path.expanduser()
    try:
        resolved = resolved.resolve()
    except OSError:
        pass
    labels = ("Flatpak", "Native", "Legacy")
    for label, candidate in zip(labels, candidates, strict=True):
        try:
            if resolved == candidate.resolve():
                return label
        except OSError:
            if resolved == candidate:
                return label
    return "Custom"


def format_engine_dir_label(
    path: Path,
    *,
    will_create: bool = False,
    home: Path | None = None,
) -> str:
    """Human-readable combo label for an engines directory."""
    kind = engine_dir_kind(path, home=home)
    label = f"{kind} — {path}"
    if will_create:
        label = f"{label} (will create)"
    return label


def list_installed_filenames(engines_dir: Path) -> set[str]:
    if not engines_dir.is_dir():
        return set()
    return {path.name for path in engines_dir.glob("*.py")}


# qBittorrent imports engines as ``engines.<stem>``, so a valid engine name is a
# plain ASCII identifier. A leading letter also rules out ``__init__.py``.
_ENGINE_FILENAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\.py")

# nova3 / engines package modules an engine must never replace or shadow.
_RESERVED_ENGINE_STEMS: frozenset[str] = frozenset(
    {"helpers", "novaprinter", "nova2", "nova2dl", "socks", "sgmllib3", "template"}
)


def validate_plugin_filename(name: str) -> str:
    """
    Require a safe engine basename: ``<identifier>.py`` with no path components.

    Raises ValueError for empty names, paths, non-``.py`` files, names that are
    not plain ASCII identifiers (``__init__.py``, globs, spaces, control or
    bidi characters, over-long names) and qBittorrent's own module names.
    """
    if not name or name in {".", ".."}:
        raise ValueError("Invalid plugin filename")
    if "/" in name or "\\" in name or name != Path(name).name:
        raise ValueError(f"Plugin filename must be a basename: {name!r}")
    if ".." in Path(name).parts:
        raise ValueError(f"Plugin filename must not contain '..': {name!r}")
    if not name.endswith(".py"):
        raise ValueError(f"Plugin filename must end with .py: {name!r}")
    if not _ENGINE_FILENAME_RE.fullmatch(name):
        raise ValueError(
            "Plugin filename must be a letter followed by up to 63 letters, "
            f"digits or underscores, ending in .py: {name!r}"
        )
    if name[:-3].lower() in _RESERVED_ENGINE_STEMS:
        raise ValueError(f"Plugin filename is reserved by qBittorrent: {name!r}")
    return name


def resolve_plugin_dest(engines_dir: Path, filename: str) -> Path:
    """Return dest path under engines_dir after validating containment."""
    safe_name = validate_plugin_filename(filename)
    engines_root = engines_dir.resolve()
    dest = (engines_dir / safe_name).resolve()
    try:
        dest.relative_to(engines_root)
    except ValueError as exc:
        raise ValueError(
            f"Refusing to write outside engines dir: {dest}"
        ) from exc
    return dest
