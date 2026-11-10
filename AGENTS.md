# Agent notes — qbit-plugin-dl

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
# or: uv sync
```

## Validate

```bash
QT_QPA_PLATFORM=offscreen pytest -q
qbit-plugin-dl --version
```

## Release

- Display name: **qbit - Torrent Plugin Manager**; CLI/package id stays `qbit-plugin-dl`.
- Version lives in `pyproject.toml`, `__init__.__version__`, `uv.lock` and the AppStream `<releases>` list — bump all four.
- Push a `vX.Y.Z` tag on a `main` commit to release (`.github/workflows/release.yml` verifies both).

## Trust / allowlist

- Catalog providers: wiki + `qbittorrent/search-plugins` + `LightDestory/qBittorrent-Search-Plugins` (`sources.default_providers`).
- Download auto-trust is **repo-scoped** in `fetch.ALLOWED_GITHUB_REPOS` (not CDN-wide).
- Other repos / hosts need user consent. Code-hosting hosts (`github.com`, raw, gist, `codeberg.org`, `gitlab.com`) are
  **project-scoped** (`github:owner/repo`, `gist:`, `codeberg:`, `gitlab:` keys); host-level trust never covers them.
  Other hosts use hostname keys.
- Fetch checks **each redirect hop** before requesting (`follow_redirects=False`).

## Safety audit

- Never import/exec plugin code. Policy lives in the `audit/` package: `policy.py` (allow/deny lists), `visitor*.py` (imports, calls, `getattr`/`__dict__`) and `structure.py` (nova3 structure).
- ClamAV is optional and soft-fails unless infected.

## Layout tips

- Shared download: `fetch.py` (+ `url_recover.py` for stale GitHub paths).
- GUI is the `gui/` package: `window.py` builds the main window and the `window_*` mixins hold its behaviour; workers, dialogs, settings and summaries have their own modules. Keep each under ~400 lines.
