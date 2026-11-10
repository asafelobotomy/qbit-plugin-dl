"""The app icon and the persisted user settings."""

from __future__ import annotations

from importlib.resources import as_file, files
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtGui import QIcon

from qbit_plugin_dl.audit_clamav import (
    ClamAvSession,
)


def load_app_icon() -> QIcon:
    """Load the bundled application icon from package resources."""
    resource = files("qbit_plugin_dl.resources").joinpath("icon.png")
    with as_file(resource) as path:
        return QIcon(str(path))


def _settings() -> QSettings:
    return QSettings()


def safety_accepted() -> bool:
    return bool(_settings().value("safety/accepted", False, type=bool))


def set_safety_accepted(accepted: bool = True) -> None:
    settings = _settings()
    settings.setValue("safety/accepted", accepted)
    settings.sync()


def clamav_enabled() -> bool:
    return bool(_settings().value("safety/clamav_enabled", True, type=bool))


def set_clamav_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("safety/clamav_enabled", enabled)
    settings.sync()


def hide_discouraged_enabled() -> bool:
    return bool(_settings().value("ui/hide_discouraged", True, type=bool))


def set_hide_discouraged_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("ui/hide_discouraged", enabled)
    settings.sync()


def auto_refresh_enabled() -> bool:
    return bool(_settings().value("updates/auto_refresh_enabled", True, type=bool))


def set_auto_refresh_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("updates/auto_refresh_enabled", enabled)
    settings.sync()


def preferred_engines_dir() -> Path | None:
    raw = _settings().value("install/engines_dir", "", type=str)
    text = str(raw).strip() if raw is not None else ""
    if not text:
        return None
    return Path(text)


def set_preferred_engines_dir(path: Path | None) -> None:
    settings = _settings()
    if path is None:
        settings.remove("install/engines_dir")
    else:
        settings.setValue("install/engines_dir", str(path))
    settings.sync()


def auto_fix_enabled() -> bool:
    """Whether safe install-time fixes are enabled (default off)."""
    return bool(_settings().value("install/auto_fix", False, type=bool))


def set_auto_fix_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("install/auto_fix", enabled)
    settings.sync()


def allow_ast_without_clamav_enabled() -> bool:
    """AST rewrites when ClamAV did not return clean (default off)."""
    return bool(
        _settings().value("install/allow_ast_without_clamav", False, type=bool)
    )


def set_allow_ast_without_clamav_enabled(enabled: bool) -> None:
    settings = _settings()
    settings.setValue("install/allow_ast_without_clamav", enabled)
    settings.sync()


def trusted_download_hosts() -> set[str]:
    """Persisted trust keys the user chose to always trust for downloads.

    Keys are hostnames (``scare.ca``) or code-hosting projects
    (``github:owner/repo``, ``gitlab:group/project``, …).
    """
    raw = _settings().value("security/trusted_download_hosts", [], type=list)
    if not isinstance(raw, list):
        return set()
    return {str(h).lower() for h in raw if str(h).strip()}


def add_trusted_download_host(host: str) -> None:
    """Persist a trust key (hostname or ``prefix:owner/project``)."""
    host = host.lower().strip()
    if not host:
        return
    hosts = trusted_download_hosts()
    hosts.add(host)
    settings = _settings()
    settings.setValue("security/trusted_download_hosts", sorted(hosts))
    settings.sync()


def clamav_allow_clamscan_fallback() -> bool | None:
    """Return remembered clamscan consent, or None if unset."""
    settings = _settings()
    if not settings.contains("safety/allow_clamscan_fallback"):
        return None
    return bool(settings.value("safety/allow_clamscan_fallback", False, type=bool))


def set_clamav_allow_clamscan_fallback(allowed: bool) -> None:
    settings = _settings()
    settings.setValue("safety/allow_clamscan_fallback", allowed)
    settings.sync()


def build_clamav_session() -> ClamAvSession:
    return ClamAvSession(
        enabled=clamav_enabled(),
        allow_clamscan_fallback=clamav_allow_clamscan_fallback(),
    )
