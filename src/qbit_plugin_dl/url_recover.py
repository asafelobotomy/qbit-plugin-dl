"""Recover moved/renamed GitHub raw plugin URLs via the Contents/Git Trees API."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import httpx

_RAW_HOST = "raw.githubusercontent.com"
_DEPRECATED_PREFIX = re.compile(
    r"^[\(\[]?deprecated[\)\]]?[\s_-]*$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class GitHubRawRef:
    """Parsed raw.githubusercontent.com URL parts."""

    owner: str
    repo: str
    ref: str
    path: str


def parse_github_raw_url(url: str) -> GitHubRawRef | None:
    """
    Parse ``raw.githubusercontent.com/{owner}/{repo}/{ref}/path…``.

    ``ref`` may be a branch, tag, commit, or ``refs/heads/…`` / ``refs/tags/…``.
    """
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() != "https":
        return None
    if (parsed.hostname or "").lower() != _RAW_HOST:
        return None
    parts = [unquote(p) for p in parsed.path.split("/") if p]
    if len(parts) < 4:
        return None
    owner, repo = parts[0], parts[1]
    if parts[2] == "refs" and len(parts) >= 5 and parts[3] in {"heads", "tags"}:
        ref = "/".join(parts[2:5])
        path = "/".join(parts[5:])
    else:
        ref = parts[2]
        path = "/".join(parts[3:])
    if not path:
        return None
    return GitHubRawRef(owner=owner, repo=repo, ref=ref, path=path)


def path_matches_basename(repo_path: str, basename: str) -> bool:
    """True when a repo path is the same engine file (including deprecated renames)."""
    name = Path(repo_path).name
    if name == basename:
        return True
    if not basename or not name.lower().endswith(basename.lower()):
        return False
    prefix = name[: -len(basename)].rstrip()
    return bool(_DEPRECATED_PREFIX.match(prefix))


def _deprecated_rank(repo_path: str) -> int:
    """Lower is better: live paths before deprecated/ folders or names."""
    lowered = repo_path.lower()
    name = Path(repo_path).name.lower()
    score = 0
    if "deprecated" in lowered.split("/"):
        score += 10
    if "deprecated" in name:
        score += 5
    return score


def rank_matching_paths(paths: list[str], basename: str) -> list[str]:
    """Filter and sort candidate tree paths for ``basename``."""
    matched = [p for p in paths if path_matches_basename(p, basename)]
    matched.sort(key=lambda p: (_deprecated_rank(p), len(p), p.lower()))
    return matched


def build_github_raw_url(owner: str, repo: str, ref: str, repo_path: str) -> str:
    """Build a raw.githubusercontent.com URL with encoded path segments."""
    # Keep refs/heads/foo as separate segments; encode each path piece.
    ref_parts = [quote(p, safe="") for p in ref.split("/") if p]
    path_parts = [quote(p, safe="") for p in repo_path.split("/") if p]
    return (
        f"https://{_RAW_HOST}/{quote(owner, safe='')}/"
        f"{quote(repo, safe='')}/{'/'.join(ref_parts)}/{'/'.join(path_parts)}"
    )


def tree_api_url(owner: str, repo: str, ref: str) -> str:
    """GitHub git trees API URL (recursive) for a ref."""
    # API wants the ref tip name; refs/heads/main → main
    api_ref = ref
    if ref.startswith("refs/heads/"):
        api_ref = ref[len("refs/heads/") :]
    elif ref.startswith("refs/tags/"):
        api_ref = ref[len("refs/tags/") :]
    return (
        f"https://api.github.com/repos/{quote(owner, safe='')}/"
        f"{quote(repo, safe='')}/git/trees/{quote(api_ref, safe='')}?recursive=1"
    )


def paths_from_tree_payload(payload: object) -> list[str]:
    """Extract blob paths from a GitHub git trees JSON payload."""
    if not isinstance(payload, dict):
        return []
    tree = payload.get("tree")
    if not isinstance(tree, list):
        return []
    paths: list[str] = []
    for entry in tree:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if isinstance(path, str) and path:
            paths.append(path)
    return paths


def recover_github_raw_url(
    client: httpx.Client,
    url: str,
    *,
    basename: str | None = None,
) -> str | None:
    """
    On a stale GitHub raw URL, find a same-basename blob elsewhere in the repo.

    Returns a new raw URL, or None when recovery is impossible (non-GitHub,
    API failure, rate limit, or no matching path).
    """
    parsed = parse_github_raw_url(url)
    if parsed is None:
        return None
    expected = basename or Path(parsed.path).name
    if not expected.endswith(".py"):
        return None

    api = tree_api_url(parsed.owner, parsed.repo, parsed.ref)
    try:
        response = client.get(
            api,
            headers={"Accept": "application/vnd.github+json"},
            timeout=30.0,
        )
    except httpx.HTTPError:
        return None
    if response.status_code == 403 or response.status_code == 429:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None

    ranked = rank_matching_paths(paths_from_tree_payload(payload), expected)
    # Skip the exact path we already tried (same string after normalize).
    for candidate in ranked:
        if candidate == parsed.path:
            continue
        return build_github_raw_url(
            parsed.owner, parsed.repo, parsed.ref, candidate
        )
    return None


async def recover_github_raw_url_async(
    client: httpx.AsyncClient,
    url: str,
    *,
    basename: str | None = None,
) -> str | None:
    """Async variant of :func:`recover_github_raw_url`."""
    parsed = parse_github_raw_url(url)
    if parsed is None:
        return None
    expected = basename or Path(parsed.path).name
    if not expected.endswith(".py"):
        return None

    api = tree_api_url(parsed.owner, parsed.repo, parsed.ref)
    try:
        response = await client.get(
            api,
            headers={"Accept": "application/vnd.github+json"},
            timeout=30.0,
        )
    except httpx.HTTPError:
        return None
    if response.status_code in {403, 429}:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None

    ranked = rank_matching_paths(paths_from_tree_payload(payload), expected)
    for candidate in ranked:
        if candidate == parsed.path:
            continue
        return build_github_raw_url(
            parsed.owner, parsed.repo, parsed.ref, candidate
        )
    return None


def is_http_not_found(error: object) -> bool:
    """True when a FetchError (or message) indicates HTTP 404."""
    code = getattr(error, "code", None)
    if code == "not_found":
        return True
    message = getattr(error, "message", None)
    if isinstance(message, str) and "404" in message:
        return True
    if isinstance(error, str) and "404" in error:
        return True
    return False
