"""Plugin tree columns, their sort keys and the disclaimer text."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QTreeWidgetItem,
)

from qbit_plugin_dl.catalog import (
    Plugin,
    parse_wiki_date,
    parse_wiki_version,
)
from qbit_plugin_dl.categories import (
    format_categories,
)

DISCLAIMER = (
    "Unofficial qBittorrent search plugins are community-provided Python scripts "
    "and are not inherently safe. Use them at your own risk. Prefer auditing a "
    "plugin before installing it.\n\n"
    "This app runs a static safety check before writing engines, and may use "
    "ClamAV when available. That reduces risk but is not a guarantee of safety.\n\n"
    "Plugins marked with warning symbols (✖ / ❗ / ❌) are strongly discouraged "
    "by the upstream wiki because they can slow down or break other plugins."
)

COLS = (
    "",
    "Name",
    "Version",
    "Visibility",
    "Categories",
    "Updated",
    "Author",
    "Source",
    "Comments",
    "Installed",
)

# Column indices for sort-key helpers / tests.
COL_CHECK = 0
COL_NAME = 1
COL_VERSION = 2
COL_VISIBILITY = 3
COL_CATEGORIES = 4
COL_UPDATED = 5
COL_AUTHOR = 6
COL_SOURCE = 7
COL_COMMENTS = 8
COL_INSTALLED = 9

SOURCE_LABELS = {
    "wiki": "Wiki",
    "official": "Official",
    "lightdestory": "LightDestory",
}


def plugin_column_sort_key(
    plugin: Plugin,
    column: int,
    *,
    checked: bool = False,
    installed: bool = False,
) -> tuple:
    """Return a comparable sort key for a plugin column."""
    if column == COL_CHECK:
        return (0 if checked else 1,)
    if column == COL_NAME:
        return (plugin.name.casefold(),)
    if column == COL_VISIBILITY:
        return (plugin.visibility.value,)
    if column == COL_CATEGORIES:
        return (format_categories(plugin.categories).casefold(),)
    if column == COL_VERSION:
        return (parse_wiki_version(plugin.version), plugin.version.casefold())
    if column == COL_UPDATED:
        return (parse_wiki_date(plugin.last_update), plugin.last_update.casefold())
    if column == COL_AUTHOR:
        return (plugin.author.casefold(),)
    if column == COL_SOURCE:
        return (SOURCE_LABELS.get(plugin.source_id, plugin.source_id).casefold(),)
    if column == COL_COMMENTS:
        return (plugin.comments.casefold(),)
    if column == COL_INSTALLED:
        return (0 if installed else 1,)
    return (plugin.name.casefold(),)


class PluginTreeItem(QTreeWidgetItem):
    """Tree row with type-aware column sorting (version/date/check/installed)."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:
        tree = self.treeWidget()
        column = tree.sortColumn() if tree is not None else 0
        left = self._sort_key(column)
        if isinstance(other, PluginTreeItem):
            right = other._sort_key(column)
        else:
            right = (other.text(column).casefold(),)
        return left < right

    def _sort_key(self, column: int) -> tuple:
        plugin = self.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(plugin, Plugin):
            return (self.text(column).casefold(),)
        return plugin_column_sort_key(
            plugin,
            column,
            checked=self.checkState(0) == Qt.CheckState.Checked,
            installed=self.text(COL_INSTALLED) == "Yes",
        )
