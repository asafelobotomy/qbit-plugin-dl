"""requirements/*.lock.txt must stay an exact, hashed export of uv.lock.

Regenerate after changing dependencies:

    uv export --frozen --no-dev --no-emit-project -o requirements/runtime.lock.txt
    uv export --frozen --extra dev --no-emit-project -o requirements/dev.lock.txt
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)")
_HASH = re.compile(r"--hash=(sha256:[0-9a-f]{64})")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _uv_lock() -> dict[str, dict]:
    data = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {_norm(pkg["name"]): pkg for pkg in data["package"]}


def _lock_hashes(pkg: dict) -> set[str]:
    hashes = {w["hash"] for w in pkg.get("wheels", [])}
    if "sdist" in pkg:
        hashes.add(pkg["sdist"]["hash"])
    return hashes


def _closure(lock: dict[str, dict], roots: list[str]) -> set[str]:
    seen: set[str] = set()
    stack = [_norm(r) for r in roots]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(_norm(d["name"]) for d in lock[name].get("dependencies", []))
    return seen


def _parse_requirements(path: Path) -> dict[str, tuple[str, set[str]]]:
    pins: dict[str, tuple[str, set[str]]] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _PIN.match(line)
        if match:
            current = _norm(match.group(1))
            pins[current] = (match.group(2), set())
        if current is not None:
            pins[current][1].update(_HASH.findall(line))
    return pins


def _project_roots(lock: dict[str, dict], *, extras: tuple[str, ...]) -> list[str]:
    project = lock["qbit-plugin-dl"]
    roots = [d["name"] for d in project.get("dependencies", [])]
    for extra in extras:
        roots += [d["name"] for d in project.get("optional-dependencies", {})[extra]]
    return roots


@pytest.mark.parametrize(
    ("filename", "extras"),
    [("runtime.lock.txt", ()), ("dev.lock.txt", ("dev",))],
)
def test_requirements_lock_matches_uv_lock(filename: str, extras: tuple[str, ...]):
    lock = _uv_lock()
    pins = _parse_requirements(ROOT / "requirements" / filename)
    expected = _closure(lock, _project_roots(lock, extras=extras))
    assert set(pins) == expected, f"{filename} is stale; re-run uv export"
    for name, (version, hashes) in pins.items():
        assert version == lock[name]["version"], f"{name} version drift"
        assert hashes, f"{name} has no --hash pins"
        assert hashes <= _lock_hashes(lock[name]), f"{name} hash drift"


def test_build_lock_is_fully_hashed():
    pins = _parse_requirements(ROOT / "requirements" / "build.lock.txt")
    assert "python-appimage" in pins
    assert all(hashes for _version, hashes in pins.values())
