"""PySide6 UI for selecting and installing unofficial search plugins."""

from __future__ import annotations

from importlib.resources import as_file, files
from pathlib import Path

from PySide6.QtCore import Qt, QSettings, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from qbit_plugin_dl import __version__
from qbit_plugin_dl.catalog import (
    Plugin,
    Visibility,
    fetch_catalog,
    filter_plugins,
    group_plugins_for_display,
)
from qbit_plugin_dl.categories import (
    ADULT_CATEGORY,
    FILTER_CATEGORIES,
    UNCATEGORIZED,
    apply_cached_categories,
    enrich_plugins,
    format_categories,
)
from qbit_plugin_dl.install import (
    InstallResult,
    candidate_engine_dirs,
    detect_engine_dirs,
    format_engine_dir_label,
    install_plugins,
    list_installed_filenames,
    resolve_install_dir,
)
from qbit_plugin_dl.updates import (
    UPDATE_INDICATOR,
    find_outdated_filenames,
    plugins_for_updates,
)

DISCLAIMER = (
    "Unofficial qBittorrent search plugins are community-provided Python scripts "
    "and are not inherently safe. Use them at your own risk. Prefer auditing a "
    "plugin before installing it.\n\n"
    "Plugins marked with warning symbols (✖ / ❗ / ❌) are strongly discouraged "
    "by the upstream wiki because they can slow down or break other plugins."
)

COLS = (
    "",
    "Name",
    "Visibility",
    "Categories",
    "Version",
    "Updated",
    "Author",
    "Source",
    "Comments",
    "Installed",
)

SOURCE_LABELS = {
    "wiki": "Wiki",
    "official": "Official",
    "lightdestory": "LightDestory",
}


def plugin_included_in_select_all(plugin: Plugin) -> bool:
    """Whether Select all should check this plugin (skips discouraged)."""
    return not plugin.warning


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


class CategoryWorker(QThread):
    progress = Signal(int, int)
    finished_ok = Signal(list)
    failed = Signal(str)

    def __init__(self, plugins: list[Plugin], force_refresh: bool = False) -> None:
        super().__init__()
        self.plugins = plugins
        self.force_refresh = force_refresh

    def run(self) -> None:
        try:

            def on_progress(done: int, total: int, _plugin: Plugin) -> None:
                self.progress.emit(done, total)

            enriched = enrich_plugins(
                self.plugins,
                force_refresh=self.force_refresh,
                on_progress=on_progress,
            )
            self.finished_ok.emit(enriched)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class InstallWorker(QThread):
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
                plugin: Plugin,
                result: InstallResult | None,
            ) -> None:
                status = "ok"
                if result is not None and not result.ok:
                    status = result.error or "error"
                self.progress.emit(done, total, f"{plugin.name}: {status}")

            results = install_plugins(
                self.plugins,
                self.engines_dir,
                on_progress=on_progress,
            )
            self.finished_ok.emit(results)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UpdateCheckWorker(QThread):
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, engines_dir: Path, plugins: list[Plugin]) -> None:
        super().__init__()
        self.engines_dir = engines_dir
        self.plugins = plugins

    def run(self) -> None:
        try:
            outdated = find_outdated_filenames(self.engines_dir, self.plugins)
            self.finished_ok.emit(outdated)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class DisclaimerDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Safety notice")
        self.setModal(True)
        self.resize(560, 360)
        self.setMinimumSize(480, 300)
        layout = QVBoxLayout(self)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(DISCLAIMER)
        text.setMinimumHeight(200)
        text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(text)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Yes | QDialogButtonBox.StandardButton.No
        )
        buttons.button(QDialogButtonBox.StandardButton.Yes).setText("Accept")
        buttons.button(QDialogButtonBox.StandardButton.No).setText("Decline")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class MainWindow(QMainWindow):
    def __init__(self, icon: QIcon | None = None) -> None:
        super().__init__()
        self.setWindowTitle("qBittorrent Plugin Downloader")
        self.resize(1100, 700)
        if icon is not None and not icon.isNull():
            self.setWindowIcon(icon)

        self._all_plugins: list[Plugin] = []
        self._visible_plugins: list[Plugin] = []
        self._checked: set[tuple[str, str]] = set()
        self._installed: set[str] = set()
        self._updates: set[str] = set()
        self._engines_dir = resolve_install_dir()
        self._catalog_worker: CatalogWorker | None = None
        self._category_worker: CategoryWorker | None = None
        self._install_worker: InstallWorker | None = None
        self._update_worker: UpdateCheckWorker | None = None
        self._force_category_refresh = False
        self._status_base = "Loading catalog…"
        self._status_updates_suffix = ""

        self._build_menu()

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh catalog")
        self.refresh_btn.clicked.connect(self.refresh_catalog)
        toolbar.addWidget(self.refresh_btn)

        toolbar.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search name, author, comments…")
        self.filter_edit.textChanged.connect(self.apply_filters)
        toolbar.addWidget(self.filter_edit, stretch=1)

        toolbar.addWidget(QLabel("Show:"))
        self.visibility_combo = QComboBox()
        self.visibility_combo.addItem("All", None)
        self.visibility_combo.addItem("Public", Visibility.PUBLIC)
        self.visibility_combo.addItem("Private", Visibility.PRIVATE)
        self.visibility_combo.currentIndexChanged.connect(self.apply_filters)
        toolbar.addWidget(self.visibility_combo)

        toolbar.addWidget(QLabel("Category:"))
        self.category_combo = QComboBox()
        self.category_combo.addItem("All", None)
        for cat in FILTER_CATEGORIES:
            label = "Adult" if cat == ADULT_CATEGORY else cat.capitalize()
            self.category_combo.addItem(label, cat)
        self.category_combo.addItem("Uncategorized", UNCATEGORIZED)
        self.category_combo.currentIndexChanged.connect(self.apply_filters)
        toolbar.addWidget(self.category_combo)

        self.hide_discouraged = QCheckBox("Hide discouraged")
        self.hide_discouraged.setChecked(True)
        self.hide_discouraged.stateChanged.connect(self.apply_filters)
        toolbar.addWidget(self.hide_discouraged)
        layout.addLayout(toolbar)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Install to:"))
        self.path_combo = QComboBox()
        self.path_combo.setMinimumWidth(480)
        self._populate_path_combo()
        self.path_combo.currentIndexChanged.connect(self._on_path_changed)
        path_row.addWidget(self.path_combo, stretch=1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_path)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        self.private_note = QLabel(
            "Private plugins often need credentials edited into the script after install."
        )
        self.private_note.setWordWrap(True)
        layout.addWidget(self.private_note)

        self.catalog_note = QLabel(
            "Catalogs: Unofficial wiki · Official nova3 · LightDestory "
            "(duplicates merge by install filename)."
        )
        self.catalog_note.setWordWrap(True)
        layout.addWidget(self.catalog_note)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(COLS))
        self.tree.setHeaderLabels(COLS)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setColumnWidth(0, 44)
        self.tree.setColumnWidth(1, 200)
        self.tree.setColumnWidth(2, 80)
        self.tree.setColumnWidth(3, 140)
        self.tree.setColumnWidth(4, 70)
        self.tree.setColumnWidth(5, 110)
        self.tree.setColumnWidth(6, 120)
        self.tree.setColumnWidth(7, 90)
        self.tree.setColumnWidth(8, 220)
        self.tree.header().setStretchLastSection(True)
        self.tree.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.tree, stretch=1)

        footer = QHBoxLayout()
        self.select_all_btn = QPushButton("Select all visible")
        self.select_all_btn.clicked.connect(self.select_all_visible)
        footer.addWidget(self.select_all_btn)

        self.clear_btn = QPushButton("Clear selection")
        self.clear_btn.clicked.connect(self.clear_selection)
        footer.addWidget(self.clear_btn)

        footer.addStretch(1)
        self.status_label = QLabel("Loading catalog…")
        footer.addWidget(self.status_label)

        self.install_btn = QPushButton("Install selected")
        self.install_btn.clicked.connect(self.install_selected)
        footer.addWidget(self.install_btn)

        self.update_all_btn = QPushButton("Update all")
        self.update_all_btn.setEnabled(False)
        self.update_all_btn.clicked.connect(self.update_all_outdated)
        footer.addWidget(self.update_all_btn)
        layout.addLayout(footer)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        QTimer.singleShot(0, lambda: self.refresh_catalog(force_refresh=False))

    def _build_menu(self) -> None:
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)
        help_menu = menu_bar.addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About qBittorrent Plugin Downloader",
            (
                f"<b>qBittorrent Plugin Downloader</b> {__version__}<br><br>"
                "Selective installer for qBittorrent search plugins from multiple "
                "allowlisted catalogs (unofficial wiki, official nova3 engines, "
                "and LightDestory).<br><br>"
                "Plugins are community Python scripts — use them at your own risk."
            ),
        )

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
            self._populate_path_combo()
            self._rebuild_tree()
            self._start_update_check()

    def _refresh_installed(self) -> None:
        self._installed = list_installed_filenames(self._engines_dir)

    def _plugin_key(self, plugin: Plugin) -> tuple[str, str]:
        return (plugin.name, plugin.download_url)

    def _plugin_from_item(self, item: QTreeWidgetItem) -> Plugin | None:
        value = item.data(0, Qt.ItemDataRole.UserRole)
        return value if isinstance(value, Plugin) else None

    def _fill_plugin_item(self, item: QTreeWidgetItem, plugin: Plugin) -> None:
        item.setFlags(
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsUserCheckable
        )
        item.setData(0, Qt.ItemDataRole.UserRole, plugin)
        key = self._plugin_key(plugin)
        item.setCheckState(
            0,
            Qt.CheckState.Checked if key in self._checked else Qt.CheckState.Unchecked,
        )
        has_update = plugin.filename in self._updates
        display_name = (
            f"{UPDATE_INDICATOR}{plugin.name}" if has_update else plugin.name
        )
        source_label = SOURCE_LABELS.get(plugin.source_id, plugin.source_id)
        values = (
            display_name,
            plugin.visibility.value,
            format_categories(plugin.categories),
            plugin.version,
            plugin.last_update,
            plugin.author,
            source_label,
            plugin.comments,
            "Yes" if plugin.filename in self._installed else "No",
        )
        for col, value in enumerate(values, start=1):
            item.setText(col, value)
        if has_update:
            item.setToolTip(
                1,
                "Update available (local file differs from catalog)",
            )
        elif plugin.warning:
            item.setToolTip(1, "Discouraged by upstream wiki")
        elif item.parent() is not None:
            item.setToolTip(
                1,
                f"Alternate fork by {plugin.author} (same install filename)",
            )

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

    def _start_category_enrichment(self, force_refresh: bool = False) -> None:
        if self._category_worker and self._category_worker.isRunning():
            return
        if not self._all_plugins:
            self.refresh_btn.setEnabled(True)
            self._start_update_check()
            return
        self.refresh_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(self._all_plugins))
        self.progress.setValue(0)
        self.status_label.setText(
            f"Resolving categories… 0/{len(self._all_plugins)}"
        )
        worker = CategoryWorker(self._all_plugins, force_refresh=force_refresh)
        self._category_worker = worker
        worker.progress.connect(self._on_category_progress)
        worker.finished_ok.connect(self._on_categories_loaded)
        worker.failed.connect(self._on_categories_failed)
        worker.start()

    def _on_category_progress(self, done: int, total: int) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.status_label.setText(f"Resolving categories… {done}/{total}")

    def _on_categories_loaded(self, plugins: list) -> None:
        self._all_plugins = plugins
        self.refresh_btn.setEnabled(True)
        self.progress.setVisible(False)
        categorized = sum(1 for p in plugins if p.categories)
        self._status_base = f"{self._status_base} — {categorized} categorized"
        self.apply_filters()
        self._refresh_status_label()
        self._start_update_check()

    def _on_categories_failed(self, message: str) -> None:
        self.refresh_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.status_label.setText(f"{self._status_base} — category resolve failed")
        QMessageBox.warning(self, "Category resolve", message)
        self._start_update_check()

    def _on_catalog_failed(self, message: str) -> None:
        self.refresh_btn.setEnabled(True)
        self.status_label.setText("Catalog fetch failed")
        QMessageBox.critical(self, "Catalog error", message)

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

    def _set_busy_for_install(self, busy: bool) -> None:
        self.install_btn.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self._sync_update_all_button(busy=busy)

    def _sync_update_all_button(self, *, busy: bool | None = None) -> None:
        if busy is None:
            busy = bool(
                (self._install_worker and self._install_worker.isRunning())
                or (self._catalog_worker and self._catalog_worker.isRunning())
                or (self._update_worker and self._update_worker.isRunning())
            )
        self.update_all_btn.setEnabled(bool(self._updates) and not busy)

    def _start_update_check(self) -> None:
        if self._update_worker and self._update_worker.isRunning():
            return
        if not self._all_plugins:
            self._updates = set()
            self._status_updates_suffix = ""
            self._sync_update_all_button()
            return
        worker = UpdateCheckWorker(self._engines_dir, list(self._all_plugins))
        self._update_worker = worker
        self._sync_update_all_button(busy=True)
        worker.finished_ok.connect(self._on_updates_checked)
        worker.failed.connect(self._on_updates_failed)
        worker.start()

    def _on_updates_checked(self, outdated: object) -> None:
        self._updates = set(outdated) if isinstance(outdated, set) else set()
        count = len(self._updates)
        self._status_updates_suffix = (
            f" — {count} update{'s' if count != 1 else ''}" if count else ""
        )
        self._rebuild_tree()
        self._refresh_status_label()
        self._sync_update_all_button()

    def _on_updates_failed(self, message: str) -> None:
        self.status_label.setText(f"{self._status_base} — update check failed")
        self._sync_update_all_button()
        if message:
            QMessageBox.warning(self, "Update check", message)

    def _rebuild_tree(self) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()
        for group in group_plugins_for_display(self._visible_plugins):
            parent = QTreeWidgetItem(self.tree)
            self._fill_plugin_item(parent, group.primary)
            for alternate in group.alternates:
                child = QTreeWidgetItem(parent)
                self._fill_plugin_item(child, alternate)
            parent.setExpanded(False)
        self.tree.blockSignals(False)

    def _uncheck_filename_conflicts(
        self,
        item: QTreeWidgetItem,
        plugin: Plugin,
    ) -> None:
        """Uncheck other checked rows that would write the same .py basename."""
        target = plugin.filename
        root = self.tree.invisibleRootItem()
        stack = [root.child(i) for i in range(root.childCount())]
        while stack:
            current = stack.pop()
            for i in range(current.childCount()):
                stack.append(current.child(i))
            if current is item:
                continue
            other = self._plugin_from_item(current)
            if other is None or other.filename != target:
                continue
            if current.checkState(0) != Qt.CheckState.Checked:
                continue
            current.setCheckState(0, Qt.CheckState.Unchecked)
            self._checked.discard(self._plugin_key(other))

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if column != 0:
            return
        plugin = self._plugin_from_item(item)
        if plugin is None:
            return
        key = self._plugin_key(plugin)
        if item.checkState(0) == Qt.CheckState.Checked:
            self._checked.add(key)
            self.tree.blockSignals(True)
            self._uncheck_filename_conflicts(item, plugin)
            self.tree.blockSignals(False)
        else:
            self._checked.discard(key)

    def select_all_visible(self) -> None:
        """Check top-level (preferred) rows only — not collapsed alternates."""
        self.tree.blockSignals(True)
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            plugin = self._plugin_from_item(item)
            if plugin is None or not plugin_included_in_select_all(plugin):
                continue
            self._checked.add(self._plugin_key(plugin))
            item.setCheckState(0, Qt.CheckState.Checked)
            self._uncheck_filename_conflicts(item, plugin)
        self.tree.blockSignals(False)

    def clear_selection(self) -> None:
        self._checked.clear()
        self.tree.blockSignals(True)
        root = self.tree.invisibleRootItem()
        stack = [root.child(i) for i in range(root.childCount())]
        while stack:
            item = stack.pop()
            for i in range(item.childCount()):
                stack.append(item.child(i))
            item.setCheckState(0, Qt.CheckState.Unchecked)
        self.tree.blockSignals(False)

    def _selected_plugins(self) -> list[Plugin]:
        selected: list[Plugin] = []
        for plugin in self._all_plugins:
            if self._plugin_key(plugin) in self._checked:
                selected.append(plugin)
        return selected

    def install_selected(self) -> None:
        plugins = self._selected_plugins()
        if not plugins:
            QMessageBox.information(self, "Nothing selected", "Select at least one plugin.")
            return
        self._start_install(plugins)

    def update_all_outdated(self) -> None:
        if not self._updates:
            return
        plugins = plugins_for_updates(self._updates, self._all_plugins)
        if not plugins:
            QMessageBox.information(
                self,
                "Nothing to update",
                "No catalog matches were found for the outdated engines.",
            )
            return
        answer = QMessageBox.question(
            self,
            "Update all",
            f"Update {len(plugins)} plugin(s) from the catalog?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_install(plugins)

    def _start_install(self, plugins: list[Plugin]) -> None:
        if self._install_worker and self._install_worker.isRunning():
            return

        self._engines_dir = resolve_install_dir(preferred=self._engines_dir)
        self._set_busy_for_install(True)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(plugins))
        self.progress.setValue(0)
        self.status_label.setText(f"Installing {len(plugins)} plugin(s)…")

        worker = InstallWorker(plugins, self._engines_dir)
        self._install_worker = worker
        worker.progress.connect(self._on_install_progress)
        worker.finished_ok.connect(self._on_install_finished)
        worker.failed.connect(self._on_install_failed)
        worker.start()

    def _on_install_progress(self, done: int, total: int, message: str) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.status_label.setText(message)

    def _on_install_finished(self, results: list) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        ok = sum(1 for r in results if r.ok)
        fail = len(results) - ok
        self._refresh_installed()
        self._rebuild_tree()
        self.status_label.setText(f"Installed {ok}, failed {fail}")
        details = "\n".join(
            f"{r.plugin.name}: {r.error}" for r in results if not r.ok
        )
        msg = (
            f"Installed {ok} of {len(results)} plugin(s) to:\n{self._engines_dir}\n\n"
            "Restart qBittorrent (or refresh Search plugins) to load new engines."
        )
        if details:
            msg += f"\n\nFailures:\n{details}"
        QMessageBox.information(self, "Install complete", msg)
        self._start_update_check()

    def _on_install_failed(self, message: str) -> None:
        self._set_busy_for_install(False)
        self.progress.setVisible(False)
        QMessageBox.critical(self, "Install error", message)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        for worker in (
            self._catalog_worker,
            self._category_worker,
            self._install_worker,
            self._update_worker,
        ):
            if worker is not None and worker.isRunning():
                worker.wait(10000)
        super().closeEvent(event)


def run_app() -> int:
    import sys

    app = QApplication(sys.argv)
    app.setApplicationName("qbit-plugin-dl")
    app.setApplicationDisplayName("qBittorrent Plugin Downloader")
    app.setOrganizationName("qbit-plugin-dl")
    app.setOrganizationDomain("qbit-plugin-dl.local")
    app.setDesktopFileName("qbit-plugin-dl")
    app.setApplicationVersion(__version__)
    icon = load_app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)

    if QApplication.platformName() not in {"offscreen", "minimal"}:
        if not safety_accepted():
            dialog = DisclaimerDialog()
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return 1
            set_safety_accepted(True)

    window = MainWindow(icon=icon)
    window.show()
    return app.exec()
