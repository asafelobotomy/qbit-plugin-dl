"""Optional ClamAV scanning via clamdscan/clamscan (no pip dependency).

Prefer a warm ``clamd`` with ``clamdscan --fdpass``. Never elevate privileges
or start/stop the daemon. One-shot ``clamscan`` requires explicit consent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qbit_plugin_dl.audit import (
    SEVERITY_FAIL,
    SEVERITY_INFO,
    SEVERITY_WARN,
    AuditFinding,
)

CLAMDSCAN_TIMEOUT_S = 15.0
CLAMSCAN_TIMEOUT_S = 90.0
PROBE_TIMEOUT_S = 2.0

BackendName = str  # "clamdscan" | "clamscan" | "none"


@dataclass
class ClamAvSession:
    """Per-install-batch ClamAV probe + consent state."""

    enabled: bool = True
    # None = ask GUI; True = allow clamscan; False = skip clamscan intentionally
    allow_clamscan_fallback: bool | None = False
    which: Callable[[str], str | None] = field(default=shutil.which)
    run: Callable[..., Any] = field(default=subprocess.run)
    _probed: bool = field(default=False, init=False, repr=False)
    _backend: BackendName = field(default="none", init=False, repr=False)
    _slow_fallback_noted: bool = field(default=False, init=False, repr=False)
    # clamscan reloads the full signature DB (~hundreds of MB–1GB+). Never run
    # more than one scan at a time across the install worker's to_thread pool.
    _scan_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def backend(self) -> BackendName:
        self._ensure_probed()
        return self._backend

    def _ensure_probed(self) -> None:
        if self._probed:
            return
        self._probed = True
        if not self.enabled:
            self._backend = "none"
            return

        clamdscan = self.which("clamdscan")
        if clamdscan and self._ping_clamd(clamdscan):
            self._backend = "clamdscan"
            return

        clamscan = self.which("clamscan")
        if clamscan and self.allow_clamscan_fallback is True:
            self._backend = "clamscan"
            return

        self._backend = "none"

    def _ping_clamd(self, clamdscan: str) -> bool:
        # ClamAV 1.0+ requires an attempt count: `clamdscan --ping [A[:I]]`.
        # A bare `--ping` fails to parse and made us falsely treat a live
        # clamd as down, falling back to memory-heavy one-shot clamscan.
        try:
            completed = self.run(
                [clamdscan, "--ping", "2"],
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def needs_clamscan_consent(self) -> bool:
        """True when only clamscan is available and consent has not been decided."""
        if not self.enabled:
            return False
        if self.allow_clamscan_fallback is not None:
            return False
        clamdscan = self.which("clamdscan")
        if clamdscan and self._ping_clamd(clamdscan):
            return False
        return self.which("clamscan") is not None

    def grant_clamscan_fallback(self) -> None:
        self.allow_clamscan_fallback = True
        # Re-probe so backend becomes clamscan if daemon still unavailable.
        self._probed = False
        self._ensure_probed()

    def deny_clamscan_fallback(self) -> None:
        self.allow_clamscan_fallback = False
        self._probed = False
        self._ensure_probed()

    def scan_bytes(
        self,
        content: bytes,
        *,
        filename: str = "plugin.py",
    ) -> tuple[list[AuditFinding], str, str]:
        """
        Scan *content*.

        Returns (findings, clamav_status, clamav_backend).
        Status: clean | infected | error | skipped | unavailable
        """
        self._ensure_probed()
        if not self.enabled:
            return [], "skipped", "none"

        if self._backend == "none":
            # Distinguish: clamscan present but no consent vs nothing installed.
            if self.which("clamscan") or self.which("clamdscan"):
                return (
                    [
                        AuditFinding(
                            code="CLAM_SKIPPED",
                            severity=SEVERITY_INFO,
                            message="ClamAV virus scan skipped for this install",
                        )
                    ],
                    "skipped",
                    "none",
                )
            return (
                [
                    AuditFinding(
                        code="CLAM_UNAVAILABLE",
                        severity=SEVERITY_INFO,
                        message="ClamAV not available on PATH",
                    )
                ],
                "unavailable",
                "none",
            )

        with self._scan_lock:
            return self._scan_bytes_locked(content, filename=filename)

    def _scan_bytes_locked(
        self,
        content: bytes,
        *,
        filename: str,
    ) -> tuple[list[AuditFinding], str, str]:
        findings: list[AuditFinding] = []
        if self._backend == "clamscan" and not self._slow_fallback_noted:
            self._slow_fallback_noted = True
            findings.append(
                AuditFinding(
                    code="CLAM_SLOW_FALLBACK",
                    severity=SEVERITY_INFO,
                    message="Using one-shot clamscan (virus DB reload; slower)",
                )
            )

        tmp_path: Path | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix="qbit-plugin-dl-", suffix=".py")
            tmp_path = Path(tmp_name)
            try:
                os.write(fd, content)
            finally:
                os.close(fd)
            os.chmod(tmp_path, 0o600)

            if self._backend == "clamdscan":
                argv = [
                    self.which("clamdscan") or "clamdscan",
                    "--fdpass",
                    "--no-summary",
                    "--infected",
                    str(tmp_path),
                ]
                timeout = CLAMDSCAN_TIMEOUT_S
            else:
                argv = [
                    self.which("clamscan") or "clamscan",
                    "--no-summary",
                    "--infected",
                    str(tmp_path),
                ]
                timeout = CLAMSCAN_TIMEOUT_S

            try:
                completed = self.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                findings.append(
                    AuditFinding(
                        code="CLAM_TIMEOUT",
                        severity=SEVERITY_WARN,
                        message=f"ClamAV scan timed out after {timeout:.0f}s",
                    )
                )
                return findings, "error", self._backend
            except OSError as exc:
                findings.append(
                    AuditFinding(
                        code="CLAM_ERROR",
                        severity=SEVERITY_WARN,
                        message=f"ClamAV failed to run: {exc}",
                    )
                )
                return findings, "error", self._backend

            code = completed.returncode
            if code == 0:
                return findings, "clean", self._backend
            if code == 1:
                detail = (completed.stdout or completed.stderr or "").strip()
                msg = "ClamAV reported an infection"
                if detail:
                    msg = f"{msg}: {detail.splitlines()[0][:200]}"
                findings.append(
                    AuditFinding(
                        code="CLAM_HIT",
                        severity=SEVERITY_FAIL,
                        message=msg,
                    )
                )
                return findings, "infected", self._backend

            detail = (completed.stderr or completed.stdout or "").strip()
            findings.append(
                AuditFinding(
                    code="CLAM_ERROR",
                    severity=SEVERITY_WARN,
                    message=(
                        f"ClamAV exited with code {code}"
                        + (f": {detail.splitlines()[0][:200]}" if detail else "")
                    ),
                )
            )
            return findings, "error", self._backend
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass


def format_clamav_backend_label(backend: str, status: str) -> str:
    """Human-readable ClamAV line for install summary / About."""
    if backend == "clamdscan":
        return f"ClamAV: clamd ({status})"
    if backend == "clamscan":
        return f"ClamAV: clamscan ({status})"
    if status == "skipped":
        return "ClamAV: skipped"
    if status == "unavailable":
        return "ClamAV: not installed"
    return f"ClamAV: {status}"
