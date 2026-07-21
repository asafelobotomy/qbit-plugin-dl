"""Smoke tests for GUI helpers, icon loading, and CLI version."""

import os
from dataclasses import replace

import pytest

from qbit_plugin_dl import __version__
from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.gui import plugin_included_in_select_all
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
