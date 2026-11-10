"""MainWindow behaviour: loading the catalog, categories and update checks."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QMessageBox,
)

from qbit_plugin_dl.catalog import (
    Visibility,
    filter_plugins,
)
from qbit_plugin_dl.gui.dialogs import show_plain_message
from qbit_plugin_dl.gui.workers import (
    _MAX_REDIRECT_TRUST_ROUNDS,
    CatalogWorker,
    CategoryWorker,
    UpdateCheckWorker,
)


class CatalogMixin:
    """Catalog, category and update-check workers and their results."""

    def refresh_catalog(self, force_refresh: bool = True) -> None:
        if self._catalog_worker and self._catalog_worker.isRunning():
            return
        if self._category_worker and self._category_worker.isRunning():
            return
        self._force_category_refresh = force_refresh
        self.refresh_btn.setEnabled(False)
        self.status_label.setText("Fetching catalog…")
        worker = CatalogWorker(force_refresh=force_refresh)
        self._catalog_worker = worker
        worker.finished_ok.connect(self._on_catalog_loaded)
        worker.failed.connect(self._on_catalog_failed)
        worker.finished.connect(self._on_worker_thread_finished)
        worker.start()

    def _on_catalog_loaded(self, plugins: list, summary: str = "") -> None:
        self._all_plugins = plugins
        self.apply_filters()
        public = sum(1 for p in plugins if p.visibility == Visibility.PUBLIC)
        private = sum(1 for p in plugins if p.visibility == Visibility.PRIVATE)
        counts = f" — {summary}" if summary else ""
        self._status_base = (
            f"Loaded {len(plugins)} plugins "
            f"({public} public, {private} private){counts}"
        )
        self.status_label.setText(self._status_base)
        self._start_category_enrichment(force_refresh=self._force_category_refresh)

    def _start_category_enrichment(
        self,
        force_refresh: bool = False,
        *,
        redirect_round: int = 0,
    ) -> None:
        if self._category_worker and self._category_worker.isRunning():
            return
        self._category_redirect_round = redirect_round
        if not self._all_plugins:
            self._sync_refresh_button()
            self._start_update_check()
            return
        self.refresh_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(self._all_plugins))
        self.progress.setValue(0)
        self.status_label.setText(
            f"Resolving categories… 0/{len(self._all_plugins)}"
        )
        self._prompt_untrusted_hosts(
            self._all_plugins,
            purpose="category resolve",
            required=False,
        )
        worker = CategoryWorker(
            self._all_plugins,
            force_refresh=force_refresh,
            trusted_hosts=self._effective_trusted_hosts(install=False),
        )
        self._category_worker = worker
        worker.progress.connect(self._on_category_progress)
        worker.finished_ok.connect(self._on_categories_loaded)
        worker.failed.connect(self._on_categories_failed)
        worker.finished.connect(self._on_worker_thread_finished)
        worker.start()

    def _on_category_progress(self, done: int, total: int) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.status_label.setText(f"Resolving categories… {done}/{total}")

    def _on_categories_loaded(self, plugins: list) -> None:
        self._all_plugins = plugins
        worker = self._category_worker
        if (
            worker is not None
            and worker.untrusted_redirects
            and self._category_redirect_round < _MAX_REDIRECT_TRUST_ROUNDS
            and self._prompt_redirect_trust(
                self._redirect_items(worker.untrusted_redirects, plugins),
                purpose="category resolve",
                required=False,
            )
        ):
            # Redirected rows were not cached, so a normal pass refetches only
            # them; everything else comes from the cache.
            worker.wait()
            self._start_category_enrichment(
                redirect_round=self._category_redirect_round + 1
            )
            return
        self._sync_refresh_button()
        self.progress.setVisible(False)
        categorized = sum(1 for p in plugins if p.categories)
        self._status_base = f"{self._status_base} — {categorized} categorized"
        self.apply_filters()
        self._refresh_status_label()
        self._start_update_check()

    def _on_categories_failed(self, message: str) -> None:
        self._sync_refresh_button()
        self.progress.setVisible(False)
        self.status_label.setText(f"{self._status_base} — category resolve failed")
        show_plain_message(
            self, QMessageBox.Icon.Warning, "Category resolve", message
        )
        self._start_update_check()

    def _on_catalog_failed(self, message: str) -> None:
        self._sync_refresh_button()
        self.status_label.setText("Catalog fetch failed")
        show_plain_message(
            self, QMessageBox.Icon.Critical, "Catalog error", message
        )

    def apply_filters(self) -> None:
        visibility = self.visibility_combo.currentData()
        category = self.category_combo.currentData()
        self._visible_plugins = filter_plugins(
            self._all_plugins,
            query=self.filter_edit.text(),
            visibility=visibility,
            hide_discouraged=self.hide_discouraged.isChecked(),
            category=category,
        )
        show_note = visibility in (None, Visibility.PRIVATE)
        self.private_note.setVisible(show_note)
        self._rebuild_tree()
        if self._all_plugins and not self._visible_plugins:
            self.status_label.setText("No plugins match the current filters.")
        elif self._all_plugins:
            self._refresh_status_label()

    def _refresh_status_label(self) -> None:
        if self._all_plugins and not self._visible_plugins:
            return
        text = self._status_base
        if self._status_updates_suffix:
            text = f"{text}{self._status_updates_suffix}"
        self.status_label.setText(text)

    def _start_update_check(self, *, redirect_round: int = 0) -> None:
        if self._closing:
            return
        self._update_redirect_round = redirect_round
        if self._update_worker and self._update_worker.isRunning():
            # Results of the running check may be for an old directory or
            # predate an install; re-check once it ends.
            self._update_recheck_pending = True
            return
        self._update_recheck_pending = False
        if not self._all_plugins:
            self._updates = set()
            self._status_updates_suffix = ""
            self._sync_update_all_button()
            return
        installed = [
            p for p in self._all_plugins if p.filename in self._installed
        ]
        self._prompt_untrusted_hosts(
            installed,
            purpose="update check",
            required=False,
        )
        worker = UpdateCheckWorker(
            self._engines_dir,
            list(self._all_plugins),
            trusted_hosts=self._effective_trusted_hosts(install=False),
        )
        self._update_worker = worker
        self._sync_update_all_button(busy=True)
        worker.finished_ok.connect(self._on_updates_checked)
        worker.failed.connect(self._on_updates_failed)
        worker.finished.connect(self._on_update_worker_done)
        worker.finished.connect(self._on_worker_thread_finished)
        worker.start()

    def _update_result_is_current(self) -> bool:
        worker = self._update_worker
        return (
            not self._update_recheck_pending
            and worker is not None
            and worker.engines_dir == self._engines_dir
        )

    def _on_update_worker_done(self) -> None:
        if self._update_recheck_pending and not self._closing:
            self._start_update_check()

    def _on_updates_checked(self, outdated: object) -> None:
        if not self._update_result_is_current():
            # Stale (directory changed or install finished meanwhile); the
            # pending re-check will publish fresh results.
            self._update_recheck_pending = True
            return
        self._updates = set(outdated) if isinstance(outdated, set) else set()
        count = len(self._updates)
        self._status_updates_suffix = (
            f" — {count} update{'s' if count != 1 else ''}" if count else ""
        )
        self._rebuild_tree()
        self._refresh_status_label()
        self._sync_update_all_button()

        worker = self._update_worker
        if (
            worker is not None
            and worker.untrusted_redirects
            and self._update_redirect_round < _MAX_REDIRECT_TRUST_ROUNDS
            and self._prompt_redirect_trust(
                self._redirect_items(worker.untrusted_redirects, self._all_plugins),
                purpose="update check",
                required=False,
            )
        ):
            worker.wait()
            self._start_update_check(redirect_round=self._update_redirect_round + 1)

    def _on_updates_failed(self, message: str) -> None:
        if not self._update_result_is_current():
            self._update_recheck_pending = True
            return
        self.status_label.setText(f"{self._status_base} — update check failed")
        self._sync_update_all_button()
        if message:
            show_plain_message(
            self, QMessageBox.Icon.Warning, "Update check", message
        )
