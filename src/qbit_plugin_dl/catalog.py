"""Fetch and parse the unofficial qBittorrent search plugins MediaWiki catalog."""

from __future__ import annotations

import re
import shutil
import time
import urllib.parse
from dataclasses import dataclass
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Iterable, Sequence

import httpx

from qbit_plugin_dl.paths import atomic_write_text, cache_dir

CATALOG_URL = (
    "https://raw.githubusercontent.com/qbittorrent/search-plugins/"
    "master/wiki/Unofficial-search-plugins.mediawiki"
)
CACHE_TTL_SECONDS = 6 * 60 * 60


def catalog_cache_file() -> Path:
    """Path to the cached MediaWiki catalog (XDG-aware)."""
    target = cache_dir() / "catalog-wiki.mediawiki"
    legacy = cache_dir() / "catalog.mediawiki"
    if not target.exists() and legacy.is_file():
        try:
            legacy.rename(target)
        except OSError:
            shutil.copy2(legacy, target)
    return target


def sources_cache_dir() -> Path:
    """Per-provider catalog cache directory."""
    path = cache_dir() / "sources"
    path.mkdir(parents=True, exist_ok=True)
    return path


_MW_LINK = re.compile(r"\[(https?://[^\s\]]+)\s+([^\]]+)\]")
_MW_BARE_URL = re.compile(r"(https?://[^\s\]|<]+)")
_BR_TAG = re.compile(r"<br\s*/?>", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")
_WARNING_MARKERS = ("✖", "❗", "❌")


class Visibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"


@dataclass(frozen=True, slots=True)
class Plugin:
    name: str
    site_url: str
    author: str
    author_url: str
    version: str
    last_update: str
    download_url: str
    comments: str
    visibility: Visibility
    warning: bool
    categories: frozenset[str] = frozenset()
    source_id: str = "wiki"

    @property
    def filename(self) -> str:
        path = urllib.parse.urlparse(self.download_url).path
        name = Path(urllib.parse.unquote(path)).name
        if not name.endswith(".py"):
            name = f"{name}.py" if name else "plugin.py"
        return name


WITH_CATEGORIES_SUFFIX = " with categories"


@dataclass(frozen=True, slots=True)
class PluginGroup:
    """Preferred plugin plus optional plain alternates collapsed under it."""

    primary: Plugin
    alternates: tuple[Plugin, ...] = ()


def is_with_categories(name: str) -> bool:
    return name.lower().endswith(WITH_CATEGORIES_SUFFIX)


def base_plugin_name(name: str) -> str | None:
    """Return the base name if ``name`` ends with ' with categories', else None."""
    if not is_with_categories(name):
        return None
    return name[: -len(WITH_CATEGORIES_SUFFIX)]


def group_category_variants(plugins: Iterable[Plugin]) -> list[PluginGroup]:
    """
    Nest plain engines under their ``with categories`` twins.

    Order follows the first-seen member of each pair. Unpaired plugins stay
    as single-primary groups. Duplicate names with different download URLs are
    kept as separate rows.
    """
    plugin_list = list(plugins)
    by_lower: dict[str, list[Plugin]] = {}
    for plugin in plugin_list:
        by_lower.setdefault(plugin.name.lower(), []).append(plugin)

    def identity(plugin: Plugin) -> tuple[str, str]:
        return (plugin.name, plugin.download_url)

    consumed: set[tuple[str, str]] = set()
    groups: list[PluginGroup] = []

    for plugin in plugin_list:
        key = identity(plugin)
        if key in consumed:
            continue

        if is_with_categories(plugin.name):
            base = base_plugin_name(plugin.name)
            alternate: Plugin | None = None
            if base:
                for candidate in by_lower.get(base.lower(), []):
                    cand_key = identity(candidate)
                    if cand_key not in consumed:
                        alternate = candidate
                        break
            if alternate is not None:
                groups.append(PluginGroup(primary=plugin, alternates=(alternate,)))
                consumed.add(key)
                consumed.add(identity(alternate))
            else:
                groups.append(PluginGroup(primary=plugin))
                consumed.add(key)
            continue

        twin_key = f"{plugin.name.lower()}{WITH_CATEGORIES_SUFFIX}"
        twin: Plugin | None = None
        for candidate in by_lower.get(twin_key, []):
            cand_key = identity(candidate)
            if cand_key not in consumed:
                twin = candidate
                break
        if twin is not None:
            groups.append(PluginGroup(primary=twin, alternates=(plugin,)))
            consumed.add(key)
            consumed.add(identity(twin))
            continue

        groups.append(PluginGroup(primary=plugin))
        consumed.add(key)

    return groups


_MONTHS = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}
_DATE_RE = re.compile(
    r"^\s*(\d{1,2})[/\-\s]+([A-Za-z]+)[/\-\s]+(\d{4})\s*$"
)
_VERSION_NUM_RE = re.compile(r"\d+")
_QBT5_RE = re.compile(r"qbt\s*5(?:\.\d+)?|(?<!\d)5\.[01](?:\.\d+)?x?", re.I)


def parse_wiki_date(value: str) -> date:
    """Parse wiki last_update strings; return date.min when unknown."""
    match = _DATE_RE.match(value or "")
    if not match:
        return date.min
    day_s, month_s, year_s = match.groups()
    month = _MONTHS.get(month_s.lower())
    if month is None:
        return date.min
    try:
        return date(int(year_s), month, int(day_s))
    except ValueError:
        return date.min


def parse_wiki_version(value: str) -> tuple[int, ...]:
    """Parse a wiki version into an int tuple for comparison."""
    parts = [int(p) for p in _VERSION_NUM_RE.findall(value or "")]
    return tuple(parts) if parts else (0,)


def mentions_qbt5(comments: str) -> bool:
    return bool(_QBT5_RE.search(comments or ""))


def source_preference_rank(source_id: str) -> int:
    """Higher rank prefers allowlisted GitHub engines over wiki forks."""
    if source_id == "official":
        return 2
    if source_id == "lightdestory":
        return 1
    return 0


def plugin_preference_score(plugin: Plugin) -> tuple:
    """
    Lexicographic preference for automatic fork selection (higher wins).

    Order: non-discouraged, source rank (official > LightDestory > wiki),
    newer wiki date, higher version, richer categories (excluding ``all``),
    qBittorrent 5.x hint in comments. Author and URL are applied as ascending
    tie-breaks in ``prefer_plugin`` / ``_rank_forks``.
    """
    return (
        0 if plugin.warning else 1,
        source_preference_rank(plugin.source_id),
        parse_wiki_date(plugin.last_update),
        parse_wiki_version(plugin.version),
        len(plugin.categories - {"all"}),
        1 if mentions_qbt5(plugin.comments) else 0,
    )


def prefer_plugin(left: Plugin, right: Plugin) -> Plugin:
    """Return the preferred plugin (newest non-discouraged fork wins)."""
    if plugin_preference_score(right) > plugin_preference_score(left):
        return right
    if plugin_preference_score(right) < plugin_preference_score(left):
        return left
    if (right.author, right.download_url) < (left.author, left.download_url):
        return right
    return left


def _rank_forks(members: Sequence[Plugin]) -> list[Plugin]:
    """Best fork first: higher preference score, then author/url ascending."""

    def sort_key(plugin: Plugin) -> tuple:
        score = plugin_preference_score(plugin)
        # Ascending key built so lower sorts first for preferred plugins:
        # invert numeric/date score components; keep author/url natural ASC.
        return (
            -score[0],
            -score[1],
            -score[2].toordinal(),
            tuple(-n for n in score[3]),
            -score[4],
            -score[5],
            plugin.author,
            plugin.download_url,
        )

    return sorted(members, key=sort_key)


def group_filename_forks(groups: Sequence[PluginGroup]) -> list[PluginGroup]:
    """
    Collapse author forks that install to the same ``.py`` basename.

    Runs after ``group_category_variants``. Preferred primary is chosen by
    ``plugin_preference_score`` (newest non-discouraged fork wins).
    """
    # Preserve first-seen order of each filename bucket.
    order: list[str] = []
    buckets: dict[str, list[Plugin]] = {}
    for group in groups:
        members = (group.primary, *group.alternates)
        for plugin in members:
            key = plugin.filename.lower()
            if key not in buckets:
                order.append(key)
                buckets[key] = []
            buckets[key].append(plugin)

    result: list[PluginGroup] = []
    for key in order:
        members = buckets[key]
        if len(members) == 1:
            result.append(PluginGroup(primary=members[0]))
            continue
        ranked = _rank_forks(members)
        result.append(PluginGroup(primary=ranked[0], alternates=tuple(ranked[1:])))
    return result


def group_plugins_for_display(plugins: Iterable[Plugin]) -> list[PluginGroup]:
    """With-categories nesting, then score-based same-filename fork grouping."""
    return group_filename_forks(group_category_variants(plugins))


def normalize_download_url(url: str) -> str:
    """Normalize blob/gist-style URLs and decode percent-escapes in the path."""
    url = url.strip()
    if "#" in url:
        url = url.split("#", 1)[0]

    parsed = urllib.parse.urlparse(url)
    path = urllib.parse.unquote(parsed.path)

    # github.com/owner/repo/blob/ref/path/file.py -> raw.githubusercontent.com/...
    blob_match = re.match(
        r"^/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$",
        path,
    )
    if parsed.netloc == "github.com" and blob_match:
        owner, repo, ref, rest = blob_match.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rest}"

    # Rebuild with decoded path segments that used %5F etc. in the host URL string.
    # Keep the URL usable: re-encode only characters that must be encoded.
    rebuilt = urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            "",
        )
    )
    # Prefer readable underscores in GitHub raw paths (wiki often uses %5F).
    return rebuilt.replace("%5F", "_").replace("%5f", "_")


def _clean_cell(text: str) -> str:
    text = _BR_TAG.sub(" ", text)
    text = _HTML_TAG.sub("", text)
    text = text.replace("'''", "").replace("''", "")
    return " ".join(text.split()).strip()


def _first_named_link(cell: str) -> tuple[str, str]:
    """Return (url, label) for the first [url label] link, else empty strings."""
    match = _MW_LINK.search(cell)
    if match:
        return match.group(1).strip(), _clean_cell(match.group(2))
    return "", _clean_cell(cell)


def _extract_py_url(cell: str) -> str:
    """Pick the first URL in the download cell that points at a .py file."""
    candidates: list[str] = []
    for match in _MW_LINK.finditer(cell):
        candidates.append(match.group(1))
    for match in _MW_BARE_URL.finditer(cell):
        candidates.append(match.group(1))

    seen: set[str] = set()
    for raw in candidates:
        url = raw.rstrip(".,;)")
        # Ignore nested image URLs used as link text.
        if "Download.gif" in url or "Help%20book" in url or "Help book" in url:
            continue
        lower = url.lower()
        if not lower.startswith("https://"):
            continue
        if ".py" in lower.split("?")[0].split("#")[0]:
            if url not in seen:
                seen.add(url)
                return normalize_download_url(url)
    return ""


def _split_table_rows(section: str) -> list[list[str]]:
    """Split a MediaWiki {| ... |} table into cell lists (data rows only)."""
    rows: list[list[str]] = []
    current: list[str] = []
    in_header = False

    for raw_line in section.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped.startswith("{|") or stripped == "|}":
            continue
        if stripped == "|-":
            if current and not in_header:
                rows.append(current)
            current = []
            in_header = False
            continue
        if stripped.startswith("!"):
            in_header = True
            current = []
            continue
        if in_header:
            continue
        if stripped.startswith("|"):
            # Cell may start with || on one line (rare) — split those.
            cell_text = stripped[1:]
            if cell_text.startswith("|"):
                cell_text = cell_text[1:]
            parts = re.split(r"\|\|", cell_text)
            if len(parts) > 1 and not current:
                current.extend(parts)
            else:
                current.append(cell_text)
    if current and not in_header:
        rows.append(current)
    return rows


def _parse_plugin_row(cells: list[str], visibility: Visibility) -> Plugin | None:
    if len(cells) < 6:
        return None

    site_url, name = _first_named_link(cells[0])
    author_url, author = _first_named_link(cells[1])
    version = _clean_cell(cells[2])
    last_update = _clean_cell(cells[3])
    download_url = _extract_py_url(cells[4])
    comments = _clean_cell(cells[5])

    if not name or not download_url:
        return None

    warning = any(marker in comments for marker in _WARNING_MARKERS)
    return Plugin(
        name=name,
        site_url=site_url,
        author=author,
        author_url=author_url,
        version=version,
        last_update=last_update,
        download_url=download_url,
        comments=comments,
        visibility=visibility,
        warning=warning,
        source_id="wiki",
    )


def _section_after(text: str, heading: str) -> str:
    pattern = re.compile(
        rf"^==\s*{re.escape(heading)}\s*==\s*$",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return ""
    start = match.end()
    next_heading = re.search(r"^==\s+.+\s+==\s*$", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(text)
    return text[start:end]


def parse_mediawiki(text: str) -> list[Plugin]:
    """Parse the unofficial plugins MediaWiki source into Plugin records."""
    plugins: list[Plugin] = []
    sections = (
        ("Plugins for Public Sites", Visibility.PUBLIC),
        ("Plugins for Private Sites", Visibility.PRIVATE),
    )
    for heading, visibility in sections:
        section = _section_after(text, heading)
        if not section:
            continue
        for cells in _split_table_rows(section):
            plugin = _parse_plugin_row(cells, visibility)
            if plugin is not None:
                plugins.append(plugin)
    return plugins


def _cache_is_fresh(path: Path | None = None, ttl: int = CACHE_TTL_SECONDS) -> bool:
    path = path or catalog_cache_file()
    if not path.is_file():
        return False
    age = time.time() - path.stat().st_mtime
    return age < ttl


def load_cached_catalog(path: Path | None = None) -> str | None:
    path = path or catalog_cache_file()
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return None


def save_catalog_cache(text: str, path: Path | None = None) -> None:
    path = path or catalog_cache_file()
    atomic_write_text(path, text)


def fetch_catalog(
    *,
    force_refresh: bool = False,
    client: httpx.Client | None = None,
) -> tuple[list[Plugin], str]:
    """
    Fetch and merge allowlisted catalog sources.

    Returns ``(plugins, status_summary)``. The summary encodes per-source counts
    (see ``sources.fetch_all_catalogs``).
    """
    # Lazy import: sources imports catalog helpers; avoid circular import at module load.
    from qbit_plugin_dl.sources import fetch_all_catalogs

    return fetch_all_catalogs(force_refresh=force_refresh, client=client)


def filter_plugins(
    plugins: Iterable[Plugin],
    *,
    query: str = "",
    visibility: Visibility | None = None,
    hide_discouraged: bool = False,
    category: str | None = None,
) -> list[Plugin]:
    query_l = query.strip().lower()
    result: list[Plugin] = []
    for plugin in plugins:
        if visibility is not None and plugin.visibility != visibility:
            continue
        if hide_discouraged and plugin.warning:
            continue
        if category is not None:
            if category == "uncategorized":
                if plugin.categories:
                    continue
            elif category not in plugin.categories:
                continue
        if query_l:
            haystack = " ".join(
                (
                    plugin.name,
                    plugin.author,
                    plugin.comments,
                    plugin.version,
                )
            ).lower()
            if query_l not in haystack:
                continue
        result.append(plugin)
    return result
