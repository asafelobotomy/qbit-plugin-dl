"""MainWindow behaviour: tracking busy workers and closing safely."""

from __future__ import annotations

import warnings

from PySide6.QtCore import QThread, QTimer
from PySide6.QtGui import QCloseEvent

from qbit_plugin_dl.gui.workers import _CancellableWorker


class LifecycleMixin:
    """Busy state across workers, and closing only once they stop."""

    def _workers_busy(self) -> bool:
        return bool(
            (self._catalog_worker and self._catalog_worker.isRunning())
            or (self._category_worker and self._category_worker.isRunning())
            or (self._install_worker and self._install_worker.isRunning())
            or (self._uninstall_worker and self._uninstall_worker.isRunning())
            or (self._update_worker and self._update_worker.isRunning())
        )

    def _set_busy_for_install(self, busy: bool) -> None:
        self.install_btn.setEnabled(not busy)
        self.uninstall_btn.setEnabled(not busy)
        # Changing the target dir mid-install would report results for, and
        # refresh "Installed" against, the wrong folder.
        self.path_combo.setEnabled(not busy)
        self.browse_btn.setEnabled(not busy)
        self._sync_refresh_button()
        self._sync_update_all_button(busy=busy)

    def _on_worker_thread_finished(self) -> None:
        # Result slots run before the QThread reports finished; re-sync once
        # it really has, so buttons never stay stuck disabled.
        if self._closing:
            return
        self._sync_refresh_button()
        self._sync_update_all_button()

    def _sync_refresh_button(self) -> None:
        """Refresh is available only when no catalog/category/install job runs."""
        busy = any(
            worker is not None and worker.isRunning()
            for worker in (
                self._catalog_worker,
                self._category_worker,
                self._install_worker,
                self._uninstall_worker,
            )
        )
        self.refresh_btn.setEnabled(not busy and not self._closing)

    def _sync_update_all_button(self, *, busy: bool | None = None) -> None:
        if busy is None:
            busy = bool(
                (self._install_worker and self._install_worker.isRunning())
                or (self._uninstall_worker and self._uninstall_worker.isRunning())
                or (self._catalog_worker and self._catalog_worker.isRunning())
                or (self._update_worker and self._update_worker.isRunning())
            )
        self.update_all_btn.setEnabled(bool(self._updates) and not busy)

    def _all_workers(self) -> list[QThread]:
        return [
            worker
            for worker in (
                self._catalog_worker,
                self._category_worker,
                self._install_worker,
                self._uninstall_worker,
                self._update_worker,
            )
            if worker is not None
        ]

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        running = [w for w in self._all_workers() if w.isRunning()]
        if not running:
            super().closeEvent(event)
            return
        # Never let a running QThread be destroyed (Qt aborts the process).
        # Ask workers to stop at their next checkpoint and close once they do.
        event.ignore()
        if self._closing:
            return
        self._closing = True
        self._catalog_refresh_timer.stop()
        self._set_status("Stopping background tasks before closing…")
        self.centralWidget().setEnabled(False)
        for worker in running:
            for signal in (worker.finished_ok, worker.failed):  # type: ignore[attr-defined]
                # PySide warns (rather than raises) when nothing is connected.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", RuntimeWarning)
                    try:
                        signal.disconnect()
                    except (RuntimeError, TypeError):
                        pass
            if isinstance(worker, _CancellableWorker):
                worker.cancel()
            worker.finished.connect(self._close_when_workers_done)

    def _close_when_workers_done(self) -> None:
        if any(w.isRunning() for w in self._all_workers()):
            return
        # Defer so the finishing thread's own signal delivery completes first.
        QTimer.singleShot(0, self.close)
