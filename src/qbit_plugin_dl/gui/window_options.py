"""MainWindow behaviour: the engines folder and the settings checkboxes."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
)

from qbit_plugin_dl.gui.settings import (
    set_allow_ast_without_clamav_enabled,
    set_auto_fix_enabled,
    set_clamav_enabled,
    set_hide_discouraged_enabled,
    set_preferred_engines_dir,
)
from qbit_plugin_dl.install import (
    candidate_engine_dirs,
    detect_engine_dirs,
    format_engine_dir_label,
    list_installed_filenames,
)
from qbit_plugin_dl.provenance import list_fixed_filenames


class OptionsMixin:
    """The engines folder picker and the settings toggles."""

    def _populate_path_combo(self) -> None:
        self.path_combo.blockSignals(True)
        self.path_combo.clear()
        existing = detect_engine_dirs()
        existing_keys = {str(path) for path in existing}
        seen: set[str] = set()
        for path in existing:
            key = str(path)
            if key not in seen:
                self.path_combo.addItem(format_engine_dir_label(path), path)
                seen.add(key)
        for path in candidate_engine_dirs():
            key = str(path)
            if key not in seen:
                self.path_combo.addItem(
                    format_engine_dir_label(path, will_create=True),
                    path,
                )
                seen.add(key)
        # Select current engines dir
        for i in range(self.path_combo.count()):
            if self.path_combo.itemData(i) == self._engines_dir:
                self.path_combo.setCurrentIndex(i)
                break
        else:
            will_create = str(self._engines_dir) not in existing_keys
            self.path_combo.insertItem(
                0,
                format_engine_dir_label(self._engines_dir, will_create=will_create),
                self._engines_dir,
            )
            self.path_combo.setCurrentIndex(0)
        self.path_combo.blockSignals(False)
        self._refresh_installed()

    def _on_path_changed(self) -> None:
        path = self.path_combo.currentData()
        if isinstance(path, Path):
            self._engines_dir = path
            set_preferred_engines_dir(path)
            self._refresh_installed()
            self._rebuild_tree()
            self._start_update_check()

    def _browse_path(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self,
            "Select qBittorrent engines directory",
            str(self._engines_dir),
        )
        if chosen:
            self._engines_dir = Path(chosen)
            set_preferred_engines_dir(self._engines_dir)
            self._populate_path_combo()
            self._rebuild_tree()
            self._start_update_check()

    def _refresh_installed(self) -> None:
        self._installed = list_installed_filenames(self._engines_dir)
        self._fixed = list_fixed_filenames()

    def _on_auto_fix_toggled(self, _state: int = 0) -> None:
        set_auto_fix_enabled(self.auto_fix_cb.isChecked())

    def _on_ast_without_clam_toggled(self, _state: int = 0) -> None:
        set_allow_ast_without_clamav_enabled(self.ast_without_clam_cb.isChecked())

    def _on_clamav_toggled(self, _state: int = 0) -> None:
        set_clamav_enabled(self.clamav_cb.isChecked())

    def _on_hide_discouraged_toggled(self, _state: int = 0) -> None:
        set_hide_discouraged_enabled(self.hide_discouraged.isChecked())
        self.apply_filters()
