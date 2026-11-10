"""Background threads for the catalog, categories, installs, uninstalls and update checks."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from qbit_plugin_dl.audit_clamav import (
    ClamAvSession,
)
from qbit_plugin_dl.catalog import (
    Plugin,
    fetch_catalog,
)
from qbit_plugin_dl.categories import (
    apply_cached_categories,
    enrich_plugins,
)
from qbit_plugin_dl.fetch import (
    FetchError,
)
from qbit_plugin_dl.install import (
    InstallResult,
    UninstallResult,
    install_plugins,
    uninstall_plugins,
)
from qbit_plugin_dl.updates import (
    find_outdated_filenames,
)

# A redirect chain can hop through several unapproved projects; stop asking
# after this many approve-and-retry rounds for one install batch.
_MAX_REDIRECT_TRUST_ROUNDS = 3


class WorkerCancelled(Exception):
    """Raised from a progress callback to stop a worker early (app closing)."""


class _CancellableWorker(QThread):
    """QThread with a cooperative cancel flag checked from progress callbacks."""

    def __init__(self) -> None:
        super().__init__()
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def _check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise WorkerCancelled()


class CatalogWorker(QThread):
    finished_ok = Signal(list, str)
    failed = Signal(str)

    def __init__(self, force_refresh: bool = False) -> None:
        super().__init__()
        self.force_refresh = force_refresh

    def run(self) -> None:
        try:
            plugins, summary = fetch_catalog(force_refresh=self.force_refresh)
            plugins = apply_cached_categories(plugins)
            self.finished_ok.emit(plugins, summary)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class CategoryWorker(_CancellableWorker):
    progress = Signal(int, int)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(
        self,
        plugins: list[Plugin],
        force_refresh: bool = False,
        *,
        trusted_hosts: set[str] | None = None,
    ) -> None:
        super().__init__()
        self.plugins = plugins
        self.force_refresh = force_refresh
        self.trusted_hosts = trusted_hosts or set()
        # Catalog URL → refused redirect; complete before finished_ok fires.
        self.untrusted_redirects: dict[str, FetchError] = {}

    def run(self) -> None:
        try:

            def on_progress(done: int, total: int, _plugin: Plugin) -> None:
                self._check_cancelled()
                self.progress.emit(done, total)

            enriched = enrich_plugins(
                self.plugins,
                force_refresh=self.force_refresh,
                on_progress=on_progress,
                trusted_hosts=self.trusted_hosts,
                untrusted_redirects=self.untrusted_redirects,
            )
            self.finished_ok.emit(enriched)
        except WorkerCancelled:
            return
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class InstallWorker(_CancellableWorker):
    progress = Signal(int, int, str)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(
        self,
        plugins: list[Plugin],
        engines_dir: Path,
        clamav_session: ClamAvSession | None = None,
        *,
        auto_fix: bool = False,
        catalog: list[Plugin] | None = None,
        trusted_hosts: set[str] | None = None,
        allow_ast_without_clamav: bool = False,
    ) -> None:
        super().__init__()
        self.plugins = plugins
        self.engines_dir = engines_dir
        self.clamav_session = clamav_session
        self.auto_fix = auto_fix
        self.catalog = catalog
        self.trusted_hosts = trusted_hosts or set()
        self.allow_ast_without_clamav = allow_ast_without_clamav

    def run(self) -> None:
        try:

            def on_progress(
                done: int,
                total: int,
                plugin: Plugin,
                result: InstallResult | None,
            ) -> None:
                # Engine writes are atomic (tmp + replace) and finish before
                # this callback, so stopping here never leaves a partial file.
                self._check_cancelled()
                status = "ok"
                if result is not None and not result.ok:
                    status = result.error or "error"
                elif result is not None and result.fix is not None and result.fix.applied:
                    status = f"ok (fixed: {', '.join(k.value for k in result.fix.kinds)})"
                self.progress.emit(done, total, f"{plugin.name}: {status}")

            results = install_plugins(
                self.plugins,
                self.engines_dir,
                on_progress=on_progress,
                clamav_session=self.clamav_session,
                auto_fix=self.auto_fix,
                catalog=self.catalog,
                trusted_hosts=self.trusted_hosts,
                allow_ast_without_clamav=self.allow_ast_without_clamav,
            )
            self.finished_ok.emit(results)
        except WorkerCancelled:
            return
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UninstallWorker(_CancellableWorker):
    progress = Signal(int, int, str)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(self, plugins: list[Plugin], engines_dir: Path) -> None:
        super().__init__()
        self.plugins = plugins
        self.engines_dir = engines_dir

    def run(self) -> None:
        try:

            def on_progress(
                done: int,
                total: int,
                filename: str,
                result: UninstallResult | None,
            ) -> None:
                self._check_cancelled()
                status = "ok"
                if result is not None and not result.ok:
                    status = result.error or "error"
                label = (
                    result.plugin.name
                    if result is not None and result.plugin is not None
                    else filename
                )
                self.progress.emit(done, total, f"{label}: {status}")

            results = uninstall_plugins(
                self.plugins,
                self.engines_dir,
                on_progress=on_progress,
            )
            self.finished_ok.emit(results)
        except WorkerCancelled:
            return
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UpdateCheckWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        engines_dir: Path,
        plugins: list[Plugin],
        *,
        trusted_hosts: set[str] | None = None,
    ) -> None:
        super().__init__()
        self.engines_dir = engines_dir
        self.plugins = plugins
        self.trusted_hosts = trusted_hosts or set()
        # Catalog URL → refused redirect; complete before finished_ok fires.
        self.untrusted_redirects: dict[str, FetchError] = {}

    def run(self) -> None:
        try:
            outdated = find_outdated_filenames(
                self.engines_dir,
                self.plugins,
                trusted_hosts=self.trusted_hosts,
                untrusted_redirects=self.untrusted_redirects,
            )
            self.finished_ok.emit(outdated)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
