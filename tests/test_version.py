"""Keep package version aligned across release metadata."""

from pathlib import Path

import tomllib

from qbit_plugin_dl import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == data["project"]["version"]


def test_appstream_lists_current_version():
    text = (ROOT / "appimage" / "qbit-plugin-dl.appdata.xml").read_text(
        encoding="utf-8"
    )
    assert f'version="{__version__}"' in text
