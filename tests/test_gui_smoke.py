"""Smoke tests for GUI helpers, icon loading, and CLI version."""

import os
from dataclasses import replace
from pathlib import Path

import pytest
from PySide6.QtCore import Qt

from qbit_plugin_dl import __version__
from qbit_plugin_dl.audit import AuditFinding, AuditReport
from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.fix import FIX_INDICATOR, FixKind, FixReport
from qbit_plugin_dl.gui import (
    COL_INSTALLED,
    COL_NAME,
    COL_UPDATED,
    COL_VERSION,
    PluginTreeItem,
    add_trusted_download_host,
    allow_ast_without_clamav_enabled,
    auto_fix_enabled,
    clamav_enabled,
    format_install_summary,
    hide_discouraged_enabled,
    plugin_column_sort_key,
    plugin_included_in_select_all,
    preferred_engines_dir,
    set_clamav_enabled,
    set_hide_discouraged_enabled,
    set_preferred_engines_dir,
    trusted_download_hosts,
)
from qbit_plugin_dl.install import InstallResult
from qbit_plugin_dl.main import main
from qbit_plugin_dl.updates import UPDATE_INDICATOR


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
    assert "clamd (clean)" in msg
    assert "Infections blocked" not in msg


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
    assert "Infections blocked (1)" in msg
    assert "• Bad" in msg


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
    assert "Blocked by safety check: 1" in msg
    assert "Dynamic code execution" in msg
    assert "Exec" in msg


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


def test_format_install_summary_groups_import_denies(tmp_path: Path):
    def blocked(name: str, module: str) -> InstallResult:
        return InstallResult(
            plugin=_plugin(name=name, download_url=f"https://example.com/{name}.py"),
            ok=False,
            path=None,
            error=f"Safety check blocked install — IMPORT_DENY: Denied import '{module}'",
            audit=AuditReport(
                findings=(
                    AuditFinding(
                        code="IMPORT_DENY",
                        severity="fail",
                        message=f"Denied import '{module}' at line 1",
                    ),
                )
            ),
        )

    results = [
        blocked("A", "socket"),
        blocked("B", "socket"),
        blocked("C", "HTMLParser"),
        InstallResult(
            plugin=_plugin(name="Net", download_url="https://example.com/net.py"),
            ok=False,
            path=None,
            error="Client error '404 Not Found' for url 'https://example.com/x.py'",
        ),
        InstallResult(
            plugin=_plugin(name="WarnOnly", download_url="https://example.com/w.py"),
            ok=True,
            path=tmp_path / "w.py",
            audit=AuditReport(
                findings=(
                    AuditFinding(
                        code="NOVA3_PRETTYPRINTER",
                        severity="warn",
                        message="search() does not call prettyPrinter",
                    ),
                )
            ),
        ),
        InstallResult(
            plugin=_plugin(name="BlockedWarn", download_url="https://example.com/bw.py"),
            ok=False,
            path=None,
            error="blocked",
            audit=AuditReport(
                findings=(
                    AuditFinding(
                        code="IMPORT_DENY",
                        severity="fail",
                        message="Denied import 'socket' at line 1",
                    ),
                    AuditFinding(
                        code="NOVA3_PRETTYPRINTER",
                        severity="warn",
                        message="search() does not call prettyPrinter",
                    ),
                )
            ),
        ),
    ]
    _, msg, _ = format_install_summary(results, tmp_path)
    assert "Uses raw sockets" in msg
    assert "A, B" in msg or ("A" in msg and "B" in msg)
    assert "Python 2 HTMLParser" in msg
    assert "Download / network errors" in msg
    assert "HTTP 404" in msg
    assert "Notes on installed plugins" in msg
    assert "prettyPrinter heuristic notes" in msg
    assert "Common (informational)" in msg
    # Collapsed — plugin name not listed for NOVA3_PRETTYPRINTER alone.
    assert "WarnOnly" not in msg.split("Notes on installed plugins")[-1].split(
        "Other notes"
    )[0]
    assert "BlockedWarn" not in msg.split("Notes on installed plugins")[-1]


def test_format_uninstall_summary(tmp_path: Path):
    from qbit_plugin_dl.gui import format_uninstall_summary
    from qbit_plugin_dl.install import UninstallResult

    results = [
        UninstallResult(
            filename="jackett.py",
            ok=True,
            removed=(tmp_path / "jackett.py", tmp_path / "jackett.json"),
            plugin=_plugin(name="Jackett", download_url="https://example.com/jackett.py"),
        ),
        UninstallResult(
            filename="gone.py",
            ok=False,
            error="Permission denied",
            plugin=_plugin(name="Gone", download_url="https://example.com/gone.py"),
        ),
    ]
    title, msg, icon = format_uninstall_summary(results, tmp_path)
    assert title == "Uninstall complete — with failures"
    assert icon == "warning"
    assert "Jackett" in msg
    assert "companion" in msg
    assert "Permission denied" in msg
    assert "provenance" in msg.lower()


def test_install_summary_dialog_bounded_offscreen():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from qbit_plugin_dl.gui import InstallSummaryDialog

    app = QApplication.instance() or QApplication([])
    body = "Installed: 1 of 1\n" + ("• plugin: " + ("x" * 200) + "\n") * 40
    dialog = InstallSummaryDialog("Install complete", body, "warning")
    assert dialog.maximumWidth() == 640
    assert dialog.width() <= 640
    dialog.close()
    assert app is not None


def test_header_sections_remain_clickable_after_init():
    """setSortingEnabled(False) must not leave column headers unclickable."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from qbit_plugin_dl.gui import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.tree.header().sectionsClickable() is True
    assert window.tree.isSortingEnabled() is False
    window.close()
    for worker in (
        window._catalog_worker,
        window._category_worker,
        window._install_worker,
        window._uninstall_worker,
        window._update_worker,
    ):
        if worker is not None and worker.isRunning():
            worker.wait(2000)
    assert app is not None
    assert window.uninstall_btn.text() == "Uninstall selected"

def test_auto_fix_setting_defaults_false():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName("qbit-plugin-dl-test-autofix")
    app.setApplicationName("qbit-plugin-dl-test-autofix")
    QSettings().remove("install/auto_fix")
    assert auto_fix_enabled() is False


def test_allow_ast_without_clamav_defaults_false():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName("qbit-plugin-dl-test-ast-clam")
    app.setApplicationName("qbit-plugin-dl-test-ast-clam")
    QSettings().remove("install/allow_ast_without_clamav")
    assert allow_ast_without_clamav_enabled() is False


def test_clamav_enabled_setting_round_trip():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName("qbit-plugin-dl-test-clamav-toggle")
    app.setApplicationName("qbit-plugin-dl-test-clamav-toggle")
    QSettings().remove("safety/clamav_enabled")
    assert clamav_enabled() is True
    set_clamav_enabled(False)
    assert clamav_enabled() is False
    set_clamav_enabled(True)
    assert clamav_enabled() is True
    assert app is not None


def test_trusted_download_hosts_persist_always_trust():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName("qbit-plugin-dl-test-trust-hosts")
    app.setApplicationName("qbit-plugin-dl-test-trust-hosts")
    QSettings().remove("security/trusted_download_hosts")
    assert trusted_download_hosts() == set()
    add_trusted_download_host("codeberg.org")
    add_trusted_download_host("Scare.ca")
    assert trusted_download_hosts() == {"codeberg.org", "scare.ca"}
    assert app is not None


def test_hide_discouraged_and_engines_dir_prefs(tmp_path: Path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName("qbit-plugin-dl-test-ui-prefs")
    app.setApplicationName("qbit-plugin-dl-test-ui-prefs")
    QSettings().remove("ui/hide_discouraged")
    QSettings().remove("install/engines_dir")
    assert hide_discouraged_enabled() is True
    set_hide_discouraged_enabled(False)
    assert hide_discouraged_enabled() is False
    target = tmp_path / "engines"
    set_preferred_engines_dir(target)
    assert preferred_engines_dir() == target
    set_preferred_engines_dir(None)
    assert preferred_engines_dir() is None
    assert app is not None


def test_main_window_clamav_checkbox_and_fix_tooltip(tmp_path: Path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from PySide6.QtWidgets import QApplication, QTreeWidgetItem

    from qbit_plugin_dl.gui import MainWindow
    from qbit_plugin_dl.provenance import record_install_provenance

    record_install_provenance(
        "demo.py",
        download_url="https://example.com/demo.py",
        sha="abc",
        fixed=True,
        rewritten=True,
        fix_kinds=["py2_imports"],
    )
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.clamav_cb.isChecked() is True
    window._fixed = {"demo.py"}
    window._installed = {"demo.py"}
    window._updates = set()
    item = QTreeWidgetItem()
    window._fill_plugin_item(item, _plugin())
    tip = item.toolTip(COL_NAME).lower()
    assert "safe fix" in tip
    assert "clamav ran" not in tip
    window.close()
    assert app is not None


def test_prompt_untrusted_hosts_session_and_decline(tmp_path: Path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication, QMessageBox

    from qbit_plugin_dl.gui import MainWindow

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName("qbit-plugin-dl-test-prompt-trust")
    app.setApplicationName("qbit-plugin-dl-test-prompt-trust")
    QSettings().remove("security/trusted_download_hosts")

    window = MainWindow()
    plugin = _plugin(download_url="https://codeberg.org/x/y/raw/branch/main/yts.py")
    chosen: dict[str, object] = {}

    def fake_exec(self):  # noqa: ANN001
        for btn in self.buttons():
            if btn.text() == "Trust once":
                chosen["btn"] = btn
                return 0
        chosen["btn"] = None
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(
        QMessageBox,
        "clickedButton",
        lambda self: chosen.get("btn"),
    )
    assert window._prompt_untrusted_hosts([plugin], purpose="install") is True
    assert "codeberg.org" in window._session_trusted_hosts
    assert "codeberg.org" not in trusted_download_hosts()

    # Declined hosts are not re-prompted (cancel path).
    other = _plugin(download_url="https://scare.ca/dl/qBittorrent/x.py")
    chosen.clear()

    def cancel_exec(self):  # noqa: ANN001
        for btn in self.buttons():
            if btn.text() == "Cancel":
                chosen["btn"] = btn
                return 0
        chosen["btn"] = self.buttons()[-1]
        return 0

    monkeypatch.setattr(QMessageBox, "exec", cancel_exec)
    assert (
        window._prompt_untrusted_hosts(
            [other], purpose="category resolve", required=False
        )
        is True
    )
    assert "scare.ca" in window._declined_download_hosts
    # Second call skips dialog because declined.
    calls = {"n": 0}

    def boom(self):  # noqa: ANN001
        calls["n"] += 1
        raise AssertionError("should not re-prompt declined host")

    monkeypatch.setattr(QMessageBox, "exec", boom)
    assert (
        window._prompt_untrusted_hosts(
            [other], purpose="category resolve", required=False
        )
        is True
    )
    assert calls["n"] == 0
    window.close()
    assert app is not None


def test_main_window_ast_checkbox_default_unchecked():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from qbit_plugin_dl.gui import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.ast_without_clam_cb.isChecked() is False
    window.close()
    for worker in (
        window._catalog_worker,
        window._category_worker,
        window._install_worker,
        window._uninstall_worker,
        window._update_worker,
    ):
        if worker is not None and worker.isRunning():
            worker.wait(2000)
    assert app is not None


def test_format_install_summary_fixed_engines(tmp_path: Path):
    plugin = _plugin()
    results = [
        InstallResult(
            plugin=plugin,
            ok=True,
            path=tmp_path / "demo.py",
            audit=AuditReport(findings=(), clamav_status="clean", clamav_backend="clamdscan"),
            fix=FixReport(
                kinds=(FixKind.PY2_IMPORTS,),
                rewritten=True,
                final_url=plugin.download_url,
            ),
        )
    ]
    title, msg, icon = format_install_summary(results, tmp_path)
    assert title == "Install complete"
    assert icon == "information"
    assert "Fixed during install: 1" in msg
    assert "py2_imports" in msg
    assert FIX_INDICATOR.strip() in msg


def test_format_install_summary_alternate_hint(tmp_path: Path):
    failed = _plugin(name="Scare", download_url="https://example.com/dead/scare.py")
    alt = _plugin(
        name="Scare",
        author="other",
        download_url="https://example.com/alive/scare.py",
    )
    results = [
        InstallResult(
            plugin=failed,
            ok=False,
            path=None,
            error="Client error '404 Not Found'",
        )
    ]
    _, msg, _ = format_install_summary(
        results,
        tmp_path,
        alternates_by_filename={"scare.py": (failed, alt)},
    )
    assert "Alternate available" in msg
    assert "other" in msg


def test_version_column_shows_placeholder_when_empty(tmp_path: Path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from PySide6.QtWidgets import QApplication, QTreeWidgetItem

    from qbit_plugin_dl.gui import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    item = QTreeWidgetItem()
    window._fill_plugin_item(item, _plugin(version=""))
    assert item.text(COL_VERSION) == "—"
    window._fill_plugin_item(item, _plugin(version="2.1"))
    assert item.text(COL_VERSION) == "2.1"
    window.close()
    assert app is not None
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    from PySide6.QtWidgets import QApplication, QTreeWidgetItem

    from qbit_plugin_dl.gui import MainWindow
    from qbit_plugin_dl.provenance import record_install_provenance

    record_install_provenance(
        "demo.py",
        download_url="https://example.com/demo.py",
        sha="abc",
        fixed=True,
        rewritten=True,
        fix_kinds=["py2_imports"],
    )

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window._fixed = {"demo.py"}
    window._installed = {"demo.py"}
    window._updates = set()
    plugin = _plugin()

    item = QTreeWidgetItem()
    window._fill_plugin_item(item, plugin)
    assert item.text(COL_NAME).startswith(FIX_INDICATOR)
    assert item.text(COL_VERSION) == "1"
    tip = item.toolTip(COL_NAME).lower()
    assert "fix" in tip or "py2" in tip

    # Update indicator wins over fix prefix; tooltip still mentions fixed.
    window._updates = {"demo.py"}
    window._fill_plugin_item(item, plugin)
    assert item.text(COL_NAME).startswith(UPDATE_INDICATOR)
    assert not item.text(COL_NAME).startswith(FIX_INDICATOR)
    tip2 = item.toolTip(COL_NAME).lower()
    assert "fixed" in tip2 or "py2" in tip2
    window.close()
    assert app is not None


def test_format_install_summary_failed_fix_attempts(tmp_path: Path):
    plugin = _plugin(name="Broken")
    results = [
        InstallResult(
            plugin=plugin,
            ok=False,
            path=None,
            error="Safety check blocked install",
            audit=AuditReport(
                findings=(
                    AuditFinding(
                        code="IMPORT_DENY",
                        severity="fail",
                        message="Denied import 'requests' at line 28",
                    ),
                )
            ),
            fix=FixReport(
                kinds=(FixKind.PY2_IMPORTS, FixKind.ALTERNATE),
                rewritten=True,
                alternate_used=True,
                final_url=plugin.download_url,
            ),
        )
    ]
    _, msg, _ = format_install_summary(results, tmp_path)
    assert "Fix attempts that did not install" in msg
    assert "Broken" in msg
    assert "py2_imports" in msg
    assert "still blocked: requests" in msg


def test_format_install_summary_collapses_common_warnings(tmp_path: Path):
    results = []
    for i, name in enumerate(["A", "B", "C"]):
        results.append(
            InstallResult(
                plugin=_plugin(name=name, download_url=f"https://example.com/{name}.py"),
                ok=True,
                path=tmp_path / f"{name}.py",
                audit=AuditReport(
                    findings=(
                        AuditFinding(
                            code="IMPORT_PY2_SHIM",
                            severity="warn",
                            message="Python 2 compatibility import 'HTMLParser'",
                        ),
                        AuditFinding(
                            code="NOVA3_PRETTYPRINTER",
                            severity="warn",
                            message="search() does not call prettyPrinter",
                        ),
                    )
                ),
            )
        )
    results.append(
        InstallResult(
            plugin=_plugin(name="Entropy", download_url="https://example.com/e.py"),
            ok=True,
            path=tmp_path / "e.py",
            audit=AuditReport(
                findings=(
                    AuditFinding(
                        code="HIGH_ENTROPY",
                        severity="warn",
                        message="High-entropy string literal at line 41",
                    ),
                )
            ),
        )
    )
    _, msg, _ = format_install_summary(results, tmp_path)
    assert "Notes on installed plugins (7)" in msg
    assert "Python 2 compatibility shims: 3 plugins" in msg
    assert "prettyPrinter heuristic notes: 3 plugins" in msg
    assert "Other notes (1)" in msg
    assert "Entropy — HIGH_ENTROPY" in msg
    # Not a per-plugin spam list for collapsed codes.
    assert "A — IMPORT_PY2_SHIM" not in msg


def test_format_install_summary_file_too_large(tmp_path: Path):
    results = [
        InstallResult(
            plugin=_plugin(name="Huge"),
            ok=False,
            path=None,
            error="Response too large (27037504 bytes > 2097152 bytes limit)",
        )
    ]
    _, msg, _ = format_install_summary(results, tmp_path)
    assert "File too large (25.8 MB > 2.0 MB limit)" in msg


def test_format_install_summary_provenance_error(tmp_path: Path):
    plugin = _plugin()
    results = [
        InstallResult(
            plugin=plugin,
            ok=True,
            path=tmp_path / "demo.py",
            provenance_error="Permission denied",
        )
    ]
    _, msg, _ = format_install_summary(results, tmp_path)
    assert "Provenance save failed" in msg
    assert "Permission denied" in msg


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
