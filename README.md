<p align="center">
  <img src="branding/qbit-plugin-dl-icon.png" alt="qbit-plugin-dl icon" width="168" />
</p>

<h1 align="center">qBittorrent Plugin Downloader</h1>

<p align="center">
  <strong>Selective installer</strong> for
  <a href="https://github.com/qbittorrent/search-plugins/wiki/Unofficial-search-plugins">unofficial qBittorrent search plugins</a>
</p>

<p align="center">
  Browse allowlisted catalogs · Filter by category · Install into <code>nova3/engines</code>
</p>

---

Fetches allowlisted catalogs (unofficial MediaWiki list, official `nova3/engines`, and LightDestory), merges duplicates by install filename, lists public and private engines with checkboxes, and downloads only the `.py` files you choose into qBittorrent’s search-plugin directory.

### Highlights

| | |
|---|---|
| **Multi-source catalogs** | Unofficial wiki + official nova3 + LightDestory, each with a 6-hour cache |
| **Category filters** | anime, books, games, movies, music, pictures, software, tv — plus Adult & Uncategorized |
| **Safer defaults** | Discouraged wiki entries stay unchecked; static safety check before install; optional ClamAV |
| **Path detection** | Flatpak and native Linux engine dirs are auto-detected |
| **One-file AppImage** | Ship a portable Qt GUI without installing Python deps |

## Naming

| Role | Value |
|------|--------|
| Display name | qBittorrent Plugin Downloader |
| CLI / desktop id | `qbit-plugin-dl` |
| Python package | `qbit_plugin_dl` |
| Branding asset | `branding/qbit-plugin-dl-icon.png` |
| Cache / config | `qbit-plugin-dl` under XDG dirs |

## Safety

Unofficial plugins are community Python scripts. **Use them at your own risk.** Prefer reviewing a script before installing.

Before writing an engine, this app runs a **static safety check** (format/encoding, AST import and call policy, nova3 structure heuristics). It never `import`s or `exec`s plugin code. When **ClamAV** is installed on the host, the app prefers a running `clamd` via `clamdscan --fdpass` (warm signature DB). If only one-shot `clamscan` is available, you are asked before each install (choice can be remembered). AppImage/Flatpak sandboxes may not see the host daemon — then only the static check runs.

This is a review aid, **not** a claim that plugins are malware-free or verified secure.

Plugins marked ✖ / ❗ / ❌ on the wiki are discouraged and can break other engines. This app never auto-selects them, and “Hide discouraged” leaves them out of the list by default.

On first launch you must **Accept** the safety notice (persisted via Qt settings). **Decline** (or Escape) exits the app.

## Threat model

- Catalog entries come from allowlisted HTTPS sources only (MediaWiki list + GitHub Contents API for known repos). Download URLs use `raw.githubusercontent.com` or the wiki’s listed HTTPS links.
- This app downloads selected `.py` files over **HTTPS only**, validates basenames, runs the static safety check (and optional ClamAV), and writes them under the chosen `nova3/engines` directory. It does **not** execute plugins.
- **qBittorrent** loads and runs installed engines later.
- Category resolution parses `supported_categories` with `ast.literal_eval` only (never `exec` / `import` of plugin modules).
- SHA hashes in the category cache identify source content for cache freshness — they are not a trust or integrity guarantee against malicious plugins.
- Static review + optional ClamAV + disclaimer + discouraged filters reduce risk but do not eliminate it. The app never starts `clamd` or elevates privileges for scanning.

## Quick start

### AppImage (recommended)

```bash
chmod +x qbit-plugin-dl-x86_64.AppImage
./qbit-plugin-dl-x86_64.AppImage
```

### From source

Requires **Python 3.11+**, Linux, and network access to GitHub.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
qbit-plugin-dl
# or: python -m qbit_plugin_dl
qbit-plugin-dl --version
```

## Usage

1. Accept the safety notice on first launch (Decline exits).
2. Wait for the catalog to load (or click **Refresh catalog**). Categories resolve in the background from each plugin’s `.py`. After that, installed engines are checked for updates; an upwards-arrow marker on the **Name** means the local file differs from the catalog copy.
3. Filter by name, public/private, **category**, and optionally hide discouraged plugins.
4. Check the plugins you want. When a **with categories** twin or another **author fork** installs to the same `.py` filename, the preferred engine is the main row (newest non-discouraged fork, then version / categories / qBittorrent 5 hint). Expand the row to pick an alternate instead — only one of the group can be selected.
5. Confirm the install path (labeled Flatpak / Native / Legacy when recognized).
6. Click **Install selected**, or **Update all** to reinstall every outdated engine from its catalog URL, then restart qBittorrent or refresh Search plugins.

## Categories

The **Category** filter uses qBittorrent’s native labels (`anime`, `books`, `games`, `movies`, `music`, `pictures`, `software`, `tv`), plus:

- **Adult** — inferred from name/URL for specialty adult indexers (plugins do not declare this)
- **Uncategorized** — no categories after parsing and fallback

Primary source: each plugin’s `supported_categories` dict in its `.py` file. If a plugin only declares `all`, a small name/URL heuristic fills the gap (e.g. FitGirl → games). Results are cached under `${XDG_CACHE_HOME:-~/.cache}/qbit-plugin-dl/categories.json`.

## Install directories (Linux)

The app prefers the first existing path, otherwise creates the modern native path:

1. `~/.var/app/org.qbittorrent.qBittorrent/data/qBittorrent/nova3/engines` (Flatpak)
2. `${XDG_DATA_HOME:-~/.local/share}/qBittorrent/nova3/engines` (Native)
3. `${XDG_DATA_HOME:-~/.local/share}/data/qBittorrent/nova3/engines` (Legacy)

## Build AppImage

Icon refresh requires **ImageMagick** (`magick`) or Pillow:

```bash
chmod +x scripts/sync-icons.sh scripts/build-appimage.sh
./scripts/sync-icons.sh   # branding → resources + AppImage PNG
./scripts/build-appimage.sh
```

Builds a wheel, syncs icons, generates `appimage/requirements.txt`, and runs [`python-appimage`](https://github.com/niess/python-appimage). Override the bundled Python with `PYTHON_VERSION=3.12` (default).

`APPIMAGE_EXTRACT_AND_RUN=1` is set so `appimagetool` works without FUSE. The result is `qbit-plugin-dl-x86_64.AppImage` (~200+ MB because of Qt).

## Tests

```bash
pytest
```

## Releases

GitHub Actions publishes a release when `pyproject.toml` / `__init__.py` version is bumped on `main` (and AppStream lists the same version). The workflow builds the AppImage, attaches `SHA256SUMS.txt`, and writes release notes from commits since the previous tag (plus GitHub’s generated changelog).

You can also run **Actions → Release → Run workflow** with **force** to publish the current version if its tag does not exist yet.

## Catalog sources

v1 merges three allowlisted providers (best-effort; one failure does not block the others):

| id | Source | Path |
|----|--------|------|
| `wiki` | [Unofficial-search-plugins.mediawiki](https://raw.githubusercontent.com/qbittorrent/search-plugins/master/wiki/Unofficial-search-plugins.mediawiki) | MediaWiki table |
| `official` | [`qbittorrent/search-plugins`](https://github.com/qbittorrent/search-plugins) | `nova3/engines/*.py` |
| `lightdestory` | [`LightDestory/qBittorrent-Search-Plugins`](https://github.com/LightDestory/qBittorrent-Search-Plugins) | `src/engines/*.py` |

GitHub providers use the public Contents API (≈60 unauthenticated requests/hour) and build HTTPS `raw.githubusercontent.com` download URLs only. `__init__.py` and `template.py` are skipped. Official `jackett.py` is included; it needs a **local Jackett** instance after install.

Results are concatenated, then grouped with the same with-categories / author-fork scoring as before (same install filename → one row with alternates).

Caches (6-hour TTL) under `${XDG_CACHE_HOME:-~/.cache}/qbit-plugin-dl/`:

- `catalog-wiki.mediawiki` (migrated from legacy `catalog.mediawiki` if present)
- `sources/{id}.json` for each GitHub listing
- `installed.json` — download URL + content hash recorded on successful installs (used for update checks)

Homepage: [github.com/asafelobotomy/qbit-plugin-dl](https://github.com/asafelobotomy/qbit-plugin-dl). AppStream still lists the upstream wiki as help.

## License

MIT — see [`LICENSE`](LICENSE).
