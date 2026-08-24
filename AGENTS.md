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

## Trust / allowlist

- Catalog providers: wiki + `qbittorrent/search-plugins` + `LightDestory/qBittorrent-Search-Plugins` (`sources.default_providers`).
- Download auto-trust is **repo-scoped** in `fetch.ALLOWED_GITHUB_REPOS` (not CDN-wide).
- Other GitHub raw repos / hosts need user consent (`github:owner/repo` or hostname keys).
- Fetch checks **each redirect hop** before requesting (`follow_redirects=False`).

## Safety audit

- Never import/exec plugin code. Policy lives in `audit.py` (imports, calls, `getattr`/`__dict__`, nova3 structure).
- ClamAV is optional and soft-fails unless infected.

## Layout tips

- Shared download: `fetch.py` (+ `url_recover.py` for stale GitHub paths).
- GUI is large (`gui.py`); prefer small focused modules when splitting.
