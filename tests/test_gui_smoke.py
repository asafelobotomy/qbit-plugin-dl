"""Smoke tests for GUI helpers, icon loading, and CLI version."""

import os
from dataclasses import replace
from pathlib import Path

import pytest
from PySide6.QtCore import Qt

from qbit_plugin_dl import __version__
from qbit_plugin_dl.audit import AuditFinding, AuditReport
from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.gui import (
    COL_INSTALLED,
    COL_NAME,
    COL_UPDATED,
    COL_VERSION,
    PluginTreeItem,
    format_install_summary,
    plugin_column_sort_key,
    plugin_included_in_select_all,
)
from qbit_plugin_dl.install import InstallResult
from qbit_plugin_dl.main import main


def _plugin(**kwargs) -> Plugin:
    base = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1",
        last_update="",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    return replace(base, **kwargs) if kwargs else base


def test_plugin_included_in_select_all():
    assert plugin_included_in_select_all(_plugin(warning=False))
    assert not plugin_included_in_select_all(_plugin(warning=True))


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out
    assert "qbit-plugin-dl" in out


def test_load_app_icon_offscreen():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from qbit_plugin_dl.gui import load_app_icon

    app = QApplication.instance() or QApplication([])
    icon = load_app_icon()
    assert not icon.isNull()
    assert app is not None


def test_format_install_summary_success(tmp_path: Path):
    plugin = _plugin()
    results = [
        InstallResult(
            plugin=plugin,
            ok=True,
            path=tmp_path / "demo.py",
            audit=AuditReport(
                findings=(),
                clamav_status="clean",
                clamav_backend="clamdscan",
            ),
        )
    ]
    title, msg, icon = format_install_summary(results, tmp_path)
    assert title == "Install complete"
    assert icon == "information"
    assert "Installed: 1 of 1" in msg
    assert "Failed: 0" in msg
    assert "Infections blocked: 0" in msg
    assert "ClamAV: clamd (clean)" in msg


def test_format_install_summary_infections_blocked(tmp_path: Path):
    plugin = _plugin(name="Bad", download_url="https://example.com/bad.py")
    report = AuditReport(
        findings=(
            AuditFinding(code="CLAM_HIT", severity="fail", message="Eicar found"),
        ),
        clamav_status="infected",
        clamav_backend="clamdscan",
    )
    results = [
        InstallResult(
            plugin=plugin,
            ok=False,
            path=None,
            error="Safety check blocked install — CLAM_HIT: Eicar found",
            audit=report,
        )
    ]
    title, msg, icon = format_install_summary(results, tmp_path)
    assert title == "Install complete — infections blocked"
    assert icon == "critical"
    assert "Infections blocked: 1" in msg
    assert "Infections blocked (not installed):" in msg
    assert "Bad:" in msg


def test_format_install_summary_mixed_failures(tmp_path: Path):
    ok_plugin = _plugin(name="Good", download_url="https://example.com/good.py")
    bad_plugin = _plugin(name="Exec", download_url="https://example.com/exec.py")
    results = [
        InstallResult(
            plugin=ok_plugin,
            ok=True,
            path=tmp_path / "good.py",
            audit=AuditReport(findings=()),
        ),
        InstallResult(
            plugin=bad_plugin,
            ok=False,
            path=None,
            error="Safety check blocked install — DYN_EXEC: exec()",
            audit=AuditReport(
                findings=(
                    AuditFinding(code="DYN_EXEC", severity="fail", message="exec()"),
                )
            ),
        ),
    ]
    title, msg, icon = format_install_summary(results, tmp_path)
    assert title == "Install complete — with failures"
    assert icon == "warning"
    assert "Installed: 1 of 2" in msg
    assert "Failed: 1" in msg
    assert "Safety check blocked: 1" in msg
    assert "Blocked by safety check:" in msg


def test_plugin_column_sort_key_version_and_date():
    older = _plugin(name="B", version="1.2", last_update="01 Jan 2020")
    newer = _plugin(name="A", version="1.10", last_update="15 Mar 2024")
    assert plugin_column_sort_key(older, COL_VERSION) < plugin_column_sort_key(
        newer, COL_VERSION
    )
    assert plugin_column_sort_key(older, COL_UPDATED) < plugin_column_sort_key(
        newer, COL_UPDATED
    )
    assert plugin_column_sort_key(newer, COL_NAME) < plugin_column_sort_key(
        older, COL_NAME
    )
    assert plugin_column_sort_key(
        older, COL_INSTALLED, installed=True
    ) < plugin_column_sort_key(newer, COL_INSTALLED, installed=False)


def test_plugin_tree_item_sort_toggle_offscreen():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QTreeWidget

    app = QApplication.instance() or QApplication([])
    tree = QTreeWidget()
    tree.setColumnCount(COL_NAME + 1)
    a = PluginTreeItem(tree)
    a.setData(0, Qt.ItemDataRole.UserRole, _plugin(name="Zed"))
    a.setText(COL_NAME, "Zed")
    b = PluginTreeItem(tree)
    b.setData(0, Qt.ItemDataRole.UserRole, _plugin(name="Ada"))
    b.setText(COL_NAME, "Ada")
    tree.sortItems(COL_NAME, Qt.SortOrder.AscendingOrder)
    assert tree.topLevelItem(0).text(COL_NAME) == "Ada"
    tree.sortItems(COL_NAME, Qt.SortOrder.DescendingOrder)
    assert tree.topLevelItem(0).text(COL_NAME) == "Zed"
    assert app is not None
