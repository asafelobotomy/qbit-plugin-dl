"""The main window: layout and menus. Behaviour lives in the window_* mixins."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from qbit_plugin_dl import __version__
from qbit_plugin_dl.audit_clamav import (
    ClamAvSession,
)
from qbit_plugin_dl.catalog import (
    CACHE_TTL_SECONDS,
    Plugin,
    Visibility,
)
from qbit_plugin_dl.categories import (
    ADULT_CATEGORY,
    FILTER_CATEGORIES,
    UNCATEGORIZED,
)
from qbit_plugin_dl.gui.columns import COLS
from qbit_plugin_dl.gui.dialogs import DisclaimerDialog
from qbit_plugin_dl.gui.settings import (
    allow_ast_without_clamav_enabled,
    auto_fix_enabled,
    auto_refresh_enabled,
    clamav_enabled,
    hide_discouraged_enabled,
    load_app_icon,
    preferred_engines_dir,
    safety_accepted,
    set_safety_accepted,
)
from qbit_plugin_dl.gui.window_actions import ActionsMixin
from qbit_plugin_dl.gui.window_catalog import CatalogMixin
from qbit_plugin_dl.gui.window_lifecycle import LifecycleMixin
from qbit_plugin_dl.gui.window_options import OptionsMixin
from qbit_plugin_dl.gui.window_tree import TreeMixin
from qbit_plugin_dl.gui.window_trust import TrustMixin
from qbit_plugin_dl.gui.workers import (
    CatalogWorker,
    CategoryWorker,
    InstallWorker,
    UninstallWorker,
    UpdateCheckWorker,
)
from qbit_plugin_dl.install import (
    InstallResult,
    resolve_install_dir,
)


class MainWindow(
    TrustMixin,
    TreeMixin,
    CatalogMixin,
    ActionsMixin,
    OptionsMixin,
    LifecycleMixin,
    QMainWindow,
):
    def __init__(self, icon: QIcon | None = None) -> None:
        super().__init__()
        self.setWindowTitle(f"qbit - Torrent Plugin Manager {__version__}")
        self.resize(1100, 700)
        if icon is not None and not icon.isNull():
            self.setWindowIcon(icon)

        self._all_plugins: list[Plugin] = []
        self._visible_plugins: list[Plugin] = []
        self._checked: set[tuple[str, str]] = set()
        self._installed: set[str] = set()
        self._fixed: set[str] = set()
        self._updates: set[str] = set()
        # "Trust once" is scoped: approving a read-only fetch (category resolve,
        # update check) must not silently approve installing from that source.
        # Install approval also covers reads.
        self._session_trusted_hosts: set[str] = set()
        self._session_read_trusted_hosts: set[str] = set()
        # Only suppresses repeat prompts for optional (read-only) fetches.
        self._declined_download_hosts: set[str] = set()
        preferred = preferred_engines_dir()
        self._engines_dir = resolve_install_dir(preferred=preferred)
        self._catalog_worker: CatalogWorker | None = None
        self._category_worker: CategoryWorker | None = None
        self._install_worker: InstallWorker | None = None
        self._uninstall_worker: UninstallWorker | None = None
        self._update_worker: UpdateCheckWorker | None = None
        # Set when an update check is requested while one is running (path
        # change, install finished); a fresh check runs once it ends.
        self._update_recheck_pending = False
        self._install_session: ClamAvSession | None = None
        self._install_carried: list[InstallResult] = []
        self._install_redirect_round = 0
        self._category_redirect_round = 0
        self._update_redirect_round = 0
        # Window close requested while workers run: cancel them, keep the
        # event loop alive, and close for real once every thread has finished.
        self._closing = False
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
        self.hide_discouraged.setChecked(hide_discouraged_enabled())
        self.hide_discouraged.stateChanged.connect(self._on_hide_discouraged_toggled)
        toolbar.addWidget(self.hide_discouraged)

        self.clamav_cb = QCheckBox("ClamAV scan")
        self.clamav_cb.setChecked(clamav_enabled())
        self.clamav_cb.setToolTip(
            "When enabled, prefer clamd / optional clamscan before install. "
            "Static safety checks always run."
        )
        self.clamav_cb.stateChanged.connect(self._on_clamav_toggled)
        toolbar.addWidget(self.clamav_cb)

        self.auto_fix_cb = QCheckBox("Safe fixes during install")
        self.auto_fix_cb.setChecked(auto_fix_enabled())
        self.auto_fix_cb.setToolTip(
            "When enabled, install may try alternate catalog forks and "
            "allowlisted AST rewrites. AST requires a clean ClamAV scan "
            "unless “Allow AST without ClamAV” is also enabled. "
            "Off by default."
        )
        self.auto_fix_cb.stateChanged.connect(self._on_auto_fix_toggled)
        toolbar.addWidget(self.auto_fix_cb)

        self.ast_without_clam_cb = QCheckBox("Allow AST without ClamAV")
        self.ast_without_clam_cb.setChecked(allow_ast_without_clamav_enabled())
        self.ast_without_clam_cb.setToolTip(
            "Permit allowlisted AST rewrites when ClamAV is skipped, "
            "unavailable, or errors. Alternates still work without this. "
            "Off by default."
        )
        self.ast_without_clam_cb.stateChanged.connect(self._on_ast_without_clam_toggled)
        toolbar.addWidget(self.ast_without_clam_cb)
        layout.addLayout(toolbar)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Install to:"))
        self.path_combo = QComboBox()
        self.path_combo.setMinimumWidth(480)
        self._populate_path_combo()
        self.path_combo.currentIndexChanged.connect(self._on_path_changed)
        path_row.addWidget(self.path_combo, stretch=1)
        self.browse_btn = QPushButton("Browse…")
        self.browse_btn.clicked.connect(self._browse_path)
        path_row.addWidget(self.browse_btn)
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
        self.tree.setColumnWidth(2, 70)
        self.tree.setColumnWidth(3, 80)
        self.tree.setColumnWidth(4, 140)
        self.tree.setColumnWidth(5, 110)
        self.tree.setColumnWidth(6, 120)
        self.tree.setColumnWidth(7, 90)
        self.tree.setColumnWidth(8, 220)
        header = self.tree.header()
        header.setStretchLastSection(True)
        header.setSortIndicatorShown(True)
        # Manual sort on click so catalog order is kept until the user sorts.
        # IMPORTANT: setSortingEnabled(False) forces sectionsClickable=False, so
        # re-enable clickable *after* that call or header clicks do nothing.
        self._sort_column: int | None = None
        self._sort_order = Qt.SortOrder.AscendingOrder
        self.tree.setSortingEnabled(False)
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._on_header_section_clicked)
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

        self.install_btn = QPushButton("Install selected")
        self.install_btn.clicked.connect(self.install_selected)
        footer.addWidget(self.install_btn)

        self.uninstall_btn = QPushButton("Uninstall selected")
        self.uninstall_btn.clicked.connect(self.uninstall_selected)
        footer.addWidget(self.uninstall_btn)

        self.update_all_btn = QPushButton("Update all")
        self.update_all_btn.setEnabled(False)
        self.update_all_btn.clicked.connect(self.update_all_outdated)
        footer.addWidget(self.update_all_btn)
        layout.addLayout(footer)

        # Own row so long install status text cannot widen the main window.
        self.status_label = QLabel("Loading catalog…")
        # Status lines include catalog-controlled names and URLs.
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        status_policy = QSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Minimum,
        )
        status_policy.setHorizontalStretch(1)
        self.status_label.setSizePolicy(status_policy)
        self.status_label.setMinimumWidth(0)
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(True)
        self.progress.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        layout.addWidget(self.progress)

        # Always fetch a fresh catalog on launch so Version/Updated and ⬆ markers
        # reflect current allowlisted sources (Update all stays confirm-gated).
        QTimer.singleShot(0, lambda: self.refresh_catalog(force_refresh=True))
        self._catalog_refresh_timer = QTimer(self)
        self._catalog_refresh_timer.setInterval(CACHE_TTL_SECONDS * 1000)
        self._catalog_refresh_timer.timeout.connect(self._on_auto_catalog_refresh)
        if auto_refresh_enabled():
            self._catalog_refresh_timer.start()

    def _on_auto_catalog_refresh(self) -> None:
        if not auto_refresh_enabled():
            return
        if self._workers_busy():
            return
        self.refresh_catalog(force_refresh=True)

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
            "About qbit - Torrent Plugin Manager",
            (
                f"<b>qbit - Torrent Plugin Manager</b> {__version__}<br><br>"
                "Selective installer for qBittorrent search plugins from multiple "
                "allowlisted catalogs (unofficial wiki, official nova3 engines, "
                "and LightDestory).<br><br>"
                "Before writing engines, the app runs a static safety check. "
                "When ClamAV is available it prefers a running <code>clamd</code> "
                "(via <code>clamdscan --fdpass</code>); one-shot "
                "<code>clamscan</code> needs your consent. Optional "
                "<b>ClamAV scan</b> can be turned off in the toolbar. Optional "
                "<b>Safe fixes during install</b> (off by default) may try "
                "alternate catalog forks and allowlisted AST rewrites. AST "
                "rewrites require a <b>clean</b> ClamAV result unless "
                "<b>Allow AST without ClamAV</b> is enabled. Infected content "
                "is never fixed; after any rewrite ClamAV runs again when "
                "available. Downloads stream with a size cap (10 MB); "
                "allowlisted catalog GitHub repos "
                "(<code>qbittorrent/search-plugins</code>, "
                "<code>LightDestory/qBittorrent-Search-Plugins</code>) are "
                "auto-trusted; other repos and HTTPS hosts need confirmation. "
                "Fixed engines show 🔧 in the list. "
                "This is a review aid, not a sandbox or guarantee of safety.<br><br>"
                "Plugins are community Python scripts — use them at your own risk."
            ),
        )

def run_app() -> int:
    import sys

    app = QApplication(sys.argv)
    app.setApplicationName("qbit-plugin-dl")
    app.setApplicationDisplayName("qbit - Torrent Plugin Manager")
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
