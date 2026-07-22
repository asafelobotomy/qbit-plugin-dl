"""Tests for optional ClamAV backend selection and scanning."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from qbit_plugin_dl.audit_clamav import ClamAvSession
from tests.fixtures.engine_stubs import CLEAN_ENGINE_BYTES


def _completed(code: int, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def test_prefers_clamdscan_fdpass():
    calls: list[list[str]] = []

    def which(name: str) -> str | None:
        if name in {"clamdscan", "clamscan"}:
            return f"/usr/bin/{name}"
        return None

    def run(argv, **kwargs):  # noqa: ANN001
        calls.append(list(argv))
        if "--ping" in argv:
            return _completed(0)
        return _completed(0)

    session = ClamAvSession(enabled=True, which=which, run=run)
    findings, status, backend = session.scan_bytes(CLEAN_ENGINE_BYTES, filename="demo.py")
    assert backend == "clamdscan"
    assert status == "clean"
    assert findings == [] or all(f.severity != "fail" for f in findings)
    ping_calls = [c for c in calls if "--ping" in c]
    assert ping_calls
    assert ping_calls[0][ping_calls[0].index("--ping") + 1] == "2"
    scan_calls = [c for c in calls if "--ping" not in c]
    assert scan_calls
    assert "--fdpass" in scan_calls[0]
    assert "--infected" in scan_calls[0]


def test_bare_ping_failure_does_not_select_clamdscan():
    """ClamAV 1.5 rejects bare --ping; we must pass an attempt count."""

    def which(name: str) -> str | None:
        if name in {"clamdscan", "clamscan"}:
            return f"/usr/bin/{name}"
        return None

    def run(argv, **kwargs):  # noqa: ANN001
        if "--ping" in argv:
            # Simulate old buggy call shape if somehow used without count.
            if argv[-1] == "--ping":
                return _completed(1, stderr="option `--ping' requires an argument")
            return _completed(0)
        return _completed(0)

    session = ClamAvSession(
        enabled=True,
        allow_clamscan_fallback=False,
        which=which,
        run=run,
    )
    assert session.backend == "clamdscan"


def test_scans_are_serialized():
    import threading
    import time

    active = 0
    max_active = 0
    lock = threading.Lock()

    def which(name: str) -> str | None:
        return "/usr/bin/clamscan" if name == "clamscan" else None

    def run(argv, **kwargs):  # noqa: ANN001
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return _completed(0)

    session = ClamAvSession(
        enabled=True,
        allow_clamscan_fallback=True,
        which=which,
        run=run,
    )
    threads = [
        threading.Thread(target=lambda: session.scan_bytes(CLEAN_ENGINE_BYTES))
        for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert max_active == 1


def test_exit_codes_mapping():
    def which(name: str) -> str | None:
        return "/usr/bin/clamdscan" if name == "clamdscan" else None

    def run_factory(code: int):
        def run(argv, **kwargs):  # noqa: ANN001
            if "--ping" in argv:
                return _completed(0)
            return _completed(code, stdout="demo.py: Eicar-Test-Signature FOUND")

        return run

    infected = ClamAvSession(enabled=True, which=which, run=run_factory(1))
    findings, status, backend = infected.scan_bytes(CLEAN_ENGINE_BYTES)
    assert backend == "clamdscan"
    assert status == "infected"
    assert any(f.code == "CLAM_HIT" for f in findings)

    errored = ClamAvSession(enabled=True, which=which, run=run_factory(2))
    findings, status, _ = errored.scan_bytes(CLEAN_ENGINE_BYTES)
    assert status == "error"
    assert any(f.severity == "warn" for f in findings)


def test_unavailable_when_no_binaries():
    session = ClamAvSession(enabled=True, which=lambda _n: None, run=lambda *a, **k: None)
    findings, status, backend = session.scan_bytes(CLEAN_ENGINE_BYTES)
    assert backend == "none"
    assert status == "unavailable"
    assert any(f.code == "CLAM_UNAVAILABLE" for f in findings)


def test_clamscan_without_consent_unused():
    calls: list[list[str]] = []

    def which(name: str) -> str | None:
        if name == "clamscan":
            return "/usr/bin/clamscan"
        return None

    def run(argv, **kwargs):  # noqa: ANN001
        calls.append(list(argv))
        return _completed(0)

    session = ClamAvSession(
        enabled=True,
        allow_clamscan_fallback=None,
        which=which,
        run=run,
    )
    assert session.needs_clamscan_consent()
    findings, status, backend = session.scan_bytes(CLEAN_ENGINE_BYTES)
    assert backend == "none"
    assert status == "skipped"
    assert calls == []  # never invoked clamscan
    assert any(f.code == "CLAM_SKIPPED" for f in findings)


def test_remembered_skip_does_not_prompt():
    def which(name: str) -> str | None:
        return "/usr/bin/clamscan" if name == "clamscan" else None

    session = ClamAvSession(
        enabled=True,
        allow_clamscan_fallback=False,
        which=which,
        run=lambda *a, **k: _completed(0),
    )
    assert not session.needs_clamscan_consent()
    _, status, backend = session.scan_bytes(CLEAN_ENGINE_BYTES)
    assert backend == "none"
    assert status == "skipped"


def test_clamscan_after_consent():
    calls: list[list[str]] = []

    def which(name: str) -> str | None:
        if name == "clamscan":
            return "/usr/bin/clamscan"
        return None

    def run(argv, **kwargs):  # noqa: ANN001
        calls.append(list(argv))
        return _completed(0)

    session = ClamAvSession(
        enabled=True,
        allow_clamscan_fallback=None,
        which=which,
        run=run,
    )
    session.grant_clamscan_fallback()
    findings, status, backend = session.scan_bytes(CLEAN_ENGINE_BYTES)
    assert backend == "clamscan"
    assert status == "clean"
    assert any(f.code == "CLAM_SLOW_FALLBACK" for f in findings)
    assert calls and "clamscan" in calls[0][0]
    assert "--fdpass" not in calls[0]


def test_timeout_is_error_not_block():
    def which(name: str) -> str | None:
        return "/usr/bin/clamdscan" if name == "clamdscan" else None

    def run(argv, **kwargs):  # noqa: ANN001
        if "--ping" in argv:
            return _completed(0)
        raise subprocess.TimeoutExpired(argv, 15)

    session = ClamAvSession(enabled=True, which=which, run=run)
    findings, status, backend = session.scan_bytes(CLEAN_ENGINE_BYTES)
    assert backend == "clamdscan"
    assert status == "error"
    assert any(f.code == "CLAM_TIMEOUT" for f in findings)
    assert all(f.severity != "fail" for f in findings)
