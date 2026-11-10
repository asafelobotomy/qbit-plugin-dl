"""MainWindow behaviour: installing and uninstalling."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QMessageBox,
)

from qbit_plugin_dl.audit_clamav import (
    ClamAvSession,
)
from qbit_plugin_dl.catalog import (
    Plugin,
)
from qbit_plugin_dl.fix import alternates_from_catalog
from qbit_plugin_dl.gui.dialogs import InstallSummaryDialog, show_plain_message
from qbit_plugin_dl.gui.notes import _format_name_list
from qbit_plugin_dl.gui.settings import (
    build_clamav_session,
    set_clamav_allow_clamscan_fallback,
)
from qbit_plugin_dl.gui.summary import (
    format_install_summary,
    format_uninstall_summary,
    plugin_too_large,
)
from qbit_plugin_dl.gui.workers import (
    _MAX_REDIRECT_TRUST_ROUNDS,
    InstallWorker,
    UninstallWorker,
)
from qbit_plugin_dl.install import (
    InstallResult,
    resolve_install_dir,
)
from qbit_plugin_dl.updates import (
    plugins_for_updates,
)


class ActionsMixin:
    """Install and uninstall flows and their worker progress."""

    def _selected_plugins(self) -> list[Plugin]:
        selected: list[Plugin] = []
        for plugin in self._all_plugins:
            if plugin_too_large(plugin):
                continue
            if self._plugin_key(plugin) in self._checked:
                selected.append(plugin)
        return selected

    def install_selected(self) -> None:
        plugins = self._selected_plugins()
        if not plugins:
            show_plain_message(
            self, QMessageBox.Icon.Information, "Nothing selected", "Select at least one plugin."
        )
            return
        plugins = self._confirm_hidden_selection(plugins)
        if plugins:
            self._start_install(plugins)

    def _confirm_hidden_selection(self, plugins: list[Plugin]) -> list[Plugin]:
        """
        Ask before installing checked plugins the current filters hide.

        Returns the plugins to install (possibly only visible ones), or an
        empty list when the user cancels.
        """
        visible = {self._plugin_key(p) for p in self._visible_plugins}
        hidden = [p for p in plugins if self._plugin_key(p) not in visible]
        if not hidden:
            return plugins
        shown = [p for p in plugins if self._plugin_key(p) in visible]

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Hidden selections")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            f"{len(hidden)} checked plugin(s) are hidden by the current filters:"
            f"\n\n{_format_name_list([p.name for p in hidden])}"
        )
        box.setInformativeText("Install them too, or only the visible selection?")
        all_btn = box.addButton("Install all", QMessageBox.ButtonRole.AcceptRole)
        visible_btn = box.addButton(
            "Visible only", QMessageBox.ButtonRole.AcceptRole
        )
        cancel_btn = box.addButton(QMessageBox.StandardButton.Cancel)
        visible_btn.setEnabled(bool(shown))
        box.setDefaultButton(visible_btn if shown else cancel_btn)
        box.setEscapeButton(cancel_btn)
        box.exec()
        clicked = box.clickedButton()
        if clicked is all_btn:
            return plugins
        if clicked is visible_btn:
            return shown
        return []

    def uninstall_selected(self) -> None:
        plugins = self._selected_plugins()
        if not plugins:
            show_plain_message(
            self, QMessageBox.Icon.Information, "Nothing selected", "Select at least one plugin."
        )
            return

        # Dedupe by filename for the confirm message (same as uninstall API).
        by_filename: dict[str, Plugin] = {}
        for plugin in plugins:
            by_filename.setdefault(plugin.filename, plugin)
        installed = [
            p for p in by_filename.values() if p.filename in self._installed
        ]
        if not installed:
            show_plain_message(
                self,
                QMessageBox.Icon.Information,
                "Nothing installed",
                "None of the selected plugins are installed in the current "
                "engines directory.",
            )
            return

        names = _format_name_list([p.name for p in installed])
        answer = show_plain_message(
            self,
            QMessageBox.Icon.Question,
            "Uninstall selected",
            (
                f"Permanently remove {len(installed)} installed engine(s) "
                f"from:\n{self._engines_dir}\n\n"
                f"{names}\n\n"
                "This deletes the .py file, any stem-named config "
                "(e.g. jackett.json), leftover .tmp files, matching "
                "bytecode, and this app’s install provenance. "
                "This cannot be undone."
            ),
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            default=QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_uninstall(installed)

    def update_all_outdated(self) -> None:
        if not self._updates:
            return
        plugins = plugins_for_updates(self._updates, self._all_plugins)
        if not plugins:
            show_plain_message(
                self,
                QMessageBox.Icon.Information,
                "Nothing to update",
                "No catalog matches were found for the outdated engines.",
            )
            return
        names = _format_name_list([p.name for p in plugins])
        answer = show_plain_message(
            self,
            QMessageBox.Icon.Question,
            "Update all",
            f"Reinstall {len(plugins)} plugin(s) from the catalog?\n\n{names}",
            buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            # A bulk reinstall should never be one stray Enter away.
            default=QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_install(plugins)

    def _prompt_clamscan_consent(self, session: ClamAvSession) -> bool:
        """
        Ask whether to use slow clamscan when clamd is unavailable.

        Returns False if the user cancels the whole install.
        """
        if not session.needs_clamscan_consent():
            return True

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("ClamAV virus scan")
        box.setText(
            "ClamAV daemon (clamd) is not running or not reachable.\n\n"
            "One-shot clamscan reloads the virus database into memory for every "
            "file and can use a large amount of RAM — avoid it for bulk installs. "
            "Prefer starting clamd, or skip the virus scan "
            "(static safety checks still run)."
        )
        use_btn = box.addButton(
            "Use clamscan",
            QMessageBox.ButtonRole.AcceptRole,
        )
        skip_btn = box.addButton(
            "Skip virus scan",
            QMessageBox.ButtonRole.DestructiveRole,
        )
        cancel_btn = box.addButton(QMessageBox.StandardButton.Cancel)
        remember = QCheckBox("Remember this choice")
        box.setCheckBox(remember)
        box.exec()

        clicked = box.clickedButton()
        if clicked is cancel_btn or clicked is None:
            return False
        if clicked is use_btn:
            session.grant_clamscan_fallback()
            if remember.isChecked():
                set_clamav_allow_clamscan_fallback(True)
            return True
        if clicked is skip_btn:
            session.deny_clamscan_fallback()
            if remember.isChecked():
                set_clamav_allow_clamscan_fallback(False)
            return True
        return False

    def _start_install(
        self,
        plugins: list[Plugin],
        *,
        session: ClamAvSession | None = None,
        carried: list[InstallResult] | None = None,
        redirect_round: int = 0,
    ) -> None:
        if self._install_worker and self._install_worker.isRunning():
            return
        if self._uninstall_worker and self._uninstall_worker.isRunning():
            return

        if redirect_round == 0:
            session = build_clamav_session()
            if not self._prompt_clamscan_consent(session):
                return
        if not self._prompt_untrusted_hosts(plugins):
            return
        # Retries after a redirect approval reuse the batch's ClamAV choice and
        # report one combined summary.
        self._install_session = session
        self._install_carried = list(carried or [])
        self._install_redirect_round = redirect_round

        self._engines_dir = resolve_install_dir(preferred=self._engines_dir)
        self._set_busy_for_install(True)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(plugins))
        self.progress.setValue(0)
        self.status_label.setText(f"Installing {len(plugins)} plugin(s)…")

        worker = InstallWorker(
            plugins,
            self._engines_dir,
            clamav_session=session,
            auto_fix=self.auto_fix_cb.isChecked(),
            catalog=list(self._all_plugins),
            trusted_hosts=self._effective_trusted_hosts(install=True),
            allow_ast_without_clamav=self.ast_without_clam_cb.isChecked(),
        )
        self._install_worker = worker
        worker.progress.connect(self._on_install_progress)
        worker.finished_ok.connect(self._on_install_finished)
        worker.failed.connect(self._on_install_failed)
        worker.finished.connect(self._on_worker_thread_finished)
        worker.start()

    def _start_uninstall(self, plugins: list[Plugin]) -> None:
        if self._install_worker and self._install_worker.isRunning():
            return
        if self._uninstall_worker and self._uninstall_worker.isRunning():
            return

        self._set_busy_for_install(True)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(plugins))
        self.progress.setValue(0)
        self.status_label.setText(f"Uninstalling {len(plugins)} plugin(s)…")

        worker = UninstallWorker(plugins, self._engines_dir)
        self._uninstall_worker = worker
        worker.progress.connect(self._on_install_progress)
        worker.finished_ok.connect(self._on_uninstall_finished)
        worker.failed.connect(self._on_uninstall_failed)
        worker.finished.connect(self._on_worker_thread_finished)
        worker.start()

    def _set_status(self, text: str) -> None:
        """Update status without letting long lines grow the window width."""
        # Tooltips auto-detect rich text; escape and mark as rich so the
        # literal text is shown.
        self.status_label.setToolTip(f"<qt>{html.escape(text)}</qt>")
        display = text if len(text) <= 96 else f"{text[:93]}…"
        self.status_label.setText(display)

    def _on_install_progress(self, done: int, total: int, message: str) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        # Prefer short progress text; full detail stays in the tooltip.
        short = message
        if ": " in message:
            name, _, rest = message.partition(": ")
            if rest.startswith("Safety check") or len(rest) > 40:
                short = f"{name}: blocked" if "blocked" in rest.lower() else f"{name}: {rest[:24]}…"
        self._set_status(f"[{done}/{total}] {short}")

    def _on_install_finished(self, results: list) -> None:
        carried = self._install_carried
        self._install_carried = []
        if self._install_redirect_round < _MAX_REDIRECT_TRUST_ROUNDS:
            retry = self._prompt_redirect_trust(
                [
                    (r.plugin, r.untrusted_redirect)
                    for r in results
                    if r.untrusted_redirect is not None
                ]
            )
            if retry:
                retry_ids = {id(p) for p in retry}
                keep = carried + [r for r in results if id(r.plugin) not in retry_ids]
                worker = self._install_worker
                if worker is not None:
                    # finished_ok is emitted from run(); let the thread exit.
                    worker.wait()
                self._start_install(
                    retry,
                    session=self._install_session,
                    carried=keep,
                    redirect_round=self._install_redirect_round + 1,
                )
                if self._install_worker is not worker:
                    return
                # Retry did not start (e.g. trust prompt cancelled).
                results = keep + [
                    r for r in results if id(r.plugin) in retry_ids
                ]
                carried = []
        results = carried + results
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        ok = sum(1 for r in results if r.ok)
        fail = len(results) - ok
        self._refresh_installed()
        self._rebuild_tree()
        self._set_status(f"Installed {ok}, failed {fail}")

        title, msg, icon_kind = format_install_summary(
            results,
            self._engines_dir,
            alternates_by_filename=alternates_from_catalog(self._all_plugins),
        )
        dialog = InstallSummaryDialog(title, msg, icon_kind, parent=self)
        dialog.exec()
        self._start_update_check()

    def _on_install_failed(self, message: str) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        self._set_status("Install error")
        show_plain_message(
            self, QMessageBox.Icon.Critical, "Install error", message
        )

    def _on_uninstall_finished(self, results: list) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        ok = sum(1 for r in results if r.ok)
        fail = len(results) - ok
        self._refresh_installed()
        self._rebuild_tree()
        self._set_status(f"Uninstalled {ok}, failed {fail}")

        title, msg, icon_kind = format_uninstall_summary(results, self._engines_dir)
        dialog = InstallSummaryDialog(title, msg, icon_kind, parent=self)
        dialog.exec()
        self._start_update_check()

    def _on_uninstall_failed(self, message: str) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        self._set_status("Uninstall error")
        show_plain_message(
            self, QMessageBox.Icon.Critical, "Uninstall error", message
        )
