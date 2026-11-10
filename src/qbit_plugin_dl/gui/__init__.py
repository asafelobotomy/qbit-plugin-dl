"""PySide6 UI for selecting and installing unofficial search plugins.

The window is split across the modules in this package; everything the old single
`gui` module exposed is still importable from here.
"""

from __future__ import annotations

from qbit_plugin_dl.gui.columns import (
    COL_AUTHOR,
    COL_CATEGORIES,
    COL_CHECK,
    COL_COMMENTS,
    COL_INSTALLED,
    COL_NAME,
    COL_SOURCE,
    COL_UPDATED,
    COL_VERSION,
    COL_VISIBILITY,
    COLS,
    DISCLAIMER,
    SOURCE_LABELS,
    PluginTreeItem,
    plugin_column_sort_key,
)
from qbit_plugin_dl.gui.dialogs import (
    DisclaimerDialog,
    InstallSummaryDialog,
    TrustPromptDialog,
    show_plain_message,
)
from qbit_plugin_dl.gui.settings import (
    add_trusted_download_host,
    allow_ast_without_clamav_enabled,
    auto_fix_enabled,
    auto_refresh_enabled,
    build_clamav_session,
    clamav_allow_clamscan_fallback,
    clamav_enabled,
    hide_discouraged_enabled,
    load_app_icon,
    preferred_engines_dir,
    safety_accepted,
    set_allow_ast_without_clamav_enabled,
    set_auto_fix_enabled,
    set_auto_refresh_enabled,
    set_clamav_allow_clamscan_fallback,
    set_clamav_enabled,
    set_hide_discouraged_enabled,
    set_preferred_engines_dir,
    set_safety_accepted,
    trusted_download_hosts,
)
from qbit_plugin_dl.gui.summary import (
    format_install_summary,
    format_uninstall_summary,
    plugin_included_in_select_all,
    plugin_too_large,
)
from qbit_plugin_dl.gui.window import MainWindow, run_app
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
    WorkerCancelled,
)

__all__ = [
    "ActionsMixin",
    "COLS",
    "COL_AUTHOR",
    "COL_CATEGORIES",
    "COL_CHECK",
    "COL_COMMENTS",
    "COL_INSTALLED",
    "COL_NAME",
    "COL_SOURCE",
    "COL_UPDATED",
    "COL_VERSION",
    "COL_VISIBILITY",
    "CatalogMixin",
    "CatalogWorker",
    "CategoryWorker",
    "DISCLAIMER",
    "DisclaimerDialog",
    "InstallSummaryDialog",
    "InstallWorker",
    "LifecycleMixin",
    "MainWindow",
    "OptionsMixin",
    "PluginTreeItem",
    "SOURCE_LABELS",
    "TreeMixin",
    "TrustMixin",
    "TrustPromptDialog",
    "UninstallWorker",
    "UpdateCheckWorker",
    "WorkerCancelled",
    "add_trusted_download_host",
    "allow_ast_without_clamav_enabled",
    "auto_fix_enabled",
    "auto_refresh_enabled",
    "build_clamav_session",
    "clamav_allow_clamscan_fallback",
    "clamav_enabled",
    "format_install_summary",
    "format_uninstall_summary",
    "hide_discouraged_enabled",
    "load_app_icon",
    "plugin_column_sort_key",
    "plugin_included_in_select_all",
    "plugin_too_large",
    "preferred_engines_dir",
    "run_app",
    "safety_accepted",
    "set_allow_ast_without_clamav_enabled",
    "set_auto_fix_enabled",
    "set_auto_refresh_enabled",
    "set_clamav_allow_clamscan_fallback",
    "set_clamav_enabled",
    "set_hide_discouraged_enabled",
    "set_preferred_engines_dir",
    "set_safety_accepted",
    "show_plain_message",
    "trusted_download_hosts",
]
