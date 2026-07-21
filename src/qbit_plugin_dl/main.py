"""Entry point for qbit-plugin-dl."""

from __future__ import annotations

import argparse
import sys

from qbit_plugin_dl import __version__


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="qbit-plugin-dl",
        description="Selective installer for unofficial qBittorrent search plugins",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"qbit-plugin-dl {__version__}",
    )
    parser.parse_args(argv)

    from qbit_plugin_dl.gui import run_app

    raise SystemExit(run_app())


if __name__ == "__main__":
    main()
