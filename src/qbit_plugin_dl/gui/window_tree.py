"""MainWindow behaviour: filling, sorting and checking the plugin tree."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QTreeWidgetItem,
)

from qbit_plugin_dl.catalog import (
    Plugin,
    group_plugins_for_display,
)
from qbit_plugin_dl.categories import (
    format_categories,
)
from qbit_plugin_dl.fix import FIX_INDICATOR
from qbit_plugin_dl.gui.columns import COL_NAME, COLS, SOURCE_LABELS, PluginTreeItem
from qbit_plugin_dl.gui.notes import _format_byte_size
from qbit_plugin_dl.gui.summary import plugin_included_in_select_all, plugin_too_large
from qbit_plugin_dl.install import (
    MAX_PLUGIN_BYTES,
)
from qbit_plugin_dl.provenance import fix_kinds_for_filename
from qbit_plugin_dl.updates import (
    UPDATE_INDICATOR,
)


class TreeMixin:
    """The plugin tree: rows, sorting, conflicts and selection."""

    def _plugin_key(self, plugin: Plugin) -> tuple[str, str]:
        return (plugin.name, plugin.download_url)

    def _plugin_from_item(self, item: QTreeWidgetItem) -> Plugin | None:
        value = item.data(0, Qt.ItemDataRole.UserRole)
        return value if isinstance(value, Plugin) else None

    def _fill_plugin_item(self, item: QTreeWidgetItem, plugin: Plugin) -> None:
        too_large = plugin_too_large(plugin)
        if too_large:
            # Listed but can never pass the download size limit: show it greyed
            # out and uncheckable instead of letting the install fail.
            item.setFlags(Qt.ItemFlag.ItemIsUserCheckable)
        else:
            item.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsUserCheckable
            )
        item.setData(0, Qt.ItemDataRole.UserRole, plugin)
        key = self._plugin_key(plugin)
        if too_large:
            self._checked.discard(key)
        item.setCheckState(
            0,
            Qt.CheckState.Checked if key in self._checked else Qt.CheckState.Unchecked,
        )
        has_update = plugin.filename in self._updates
        is_fixed = plugin.filename in self._fixed
        if has_update:
            display_name = f"{UPDATE_INDICATOR}{plugin.name}"
        elif is_fixed:
            display_name = f"{FIX_INDICATOR}{plugin.name}"
        else:
            display_name = plugin.name
        source_label = SOURCE_LABELS.get(plugin.source_id, plugin.source_id)
        version_text = plugin.version.strip() if plugin.version.strip() else "—"
        values = (
            display_name,
            version_text,
            plugin.visibility.value,
            format_categories(plugin.categories),
            plugin.last_update,
            plugin.author,
            source_label,
            (
                f"Unavailable: file too large ({_format_byte_size(plugin.size_bytes or 0)} "
                f"> {_format_byte_size(MAX_PLUGIN_BYTES)} limit). {plugin.comments}"
                if too_large
                else plugin.comments
            ),
            "Yes" if plugin.filename in self._installed else "No",
        )
        for col, value in enumerate(values, start=1):
            item.setText(col, value)
        if too_large:
            item.setToolTip(
                COL_NAME,
                f"Too large to install ({_format_byte_size(plugin.size_bytes or 0)} > "
                f"{_format_byte_size(MAX_PLUGIN_BYTES)} download limit)",
            )
        elif has_update:
            tip = "Update available — catalog source differs from what was installed"
            if is_fixed:
                kinds = fix_kinds_for_filename(plugin.filename)
                kind_txt = ", ".join(kinds) if kinds else "safe install-time fix"
                tip = f"{tip}. Also fixed previously: {kind_txt}"
            item.setToolTip(COL_NAME, tip)
        elif is_fixed:
            kinds = fix_kinds_for_filename(plugin.filename)
            kind_txt = ", ".join(kinds) if kinds else "safe install-time fix"
            item.setToolTip(
                COL_NAME,
                f"Installed with safe fix ({kind_txt}).",
            )
        elif plugin.warning:
            item.setToolTip(COL_NAME, "Discouraged by upstream wiki")
        elif item.parent() is not None:
            item.setToolTip(
                COL_NAME,
                f"Alternate fork by {plugin.author} (same install filename)",
            )

    def _on_header_section_clicked(self, section: int) -> None:
        """Toggle ascending/descending sort for the clicked column."""
        if section < 0 or section >= len(COLS):
            return
        if self._sort_column == section:
            self._sort_order = (
                Qt.SortOrder.DescendingOrder
                if self._sort_order == Qt.SortOrder.AscendingOrder
                else Qt.SortOrder.AscendingOrder
            )
        else:
            self._sort_column = section
            self._sort_order = Qt.SortOrder.AscendingOrder
        self._apply_tree_sort()

    def _apply_tree_sort(self) -> None:
        if self._sort_column is None:
            return
        header = self.tree.header()
        header.setSortIndicator(self._sort_column, self._sort_order)
        self.tree.sortItems(self._sort_column, self._sort_order)

    def _rebuild_tree(self) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()
        for group in group_plugins_for_display(self._visible_plugins):
            parent = PluginTreeItem(self.tree)
            self._fill_plugin_item(parent, group.primary)
            for alternate in group.alternates:
                child = PluginTreeItem(parent)
                self._fill_plugin_item(child, alternate)
            parent.setExpanded(False)
        self.tree.blockSignals(False)
        self._apply_tree_sort()

    def _uncheck_filename_conflicts(
        self,
        item: QTreeWidgetItem,
        plugin: Plugin,
    ) -> None:
        """Uncheck other checked plugins that would write the same .py basename.

        Works on the full selection, not just visible rows: a checked plugin
        hidden by filters would otherwise still be installed over this one.
        """
        target = plugin.filename
        keep = self._plugin_key(plugin)
        for other in self._all_plugins:
            if other.filename == target:
                other_key = self._plugin_key(other)
                if other_key != keep:
                    self._checked.discard(other_key)
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
