"""Keep package version aligned with pyproject.toml."""

from pathlib import Path

import tomllib

from qbit_plugin_dl import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == "0.0.2"
    assert __version__ == data["project"]["version"]
