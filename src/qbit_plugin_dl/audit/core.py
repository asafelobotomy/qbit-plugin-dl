"""Entry points: audit a plugin's source or downloaded bytes."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

from qbit_plugin_dl.audit.policy import SEVERITY_FAIL
from qbit_plugin_dl.audit.report import (
    AuditFinding,
    AuditReport,
    _check_format,
    _decode_source,
    _finding,
)
from qbit_plugin_dl.audit.structure import (
    _check_line_heuristics,
    _check_nova3_structure,
)
from qbit_plugin_dl.audit.visitor import _PolicyVisitor

if TYPE_CHECKING:
    from qbit_plugin_dl.audit_clamav import ClamAvSession

def audit_plugin_static(content: bytes, *, filename: str) -> AuditReport:
    """Run format/AST/import/structure/heuristic checks (no ClamAV)."""
    findings: list[AuditFinding] = []
    findings.extend(_check_format(content))
    if any(f.severity == SEVERITY_FAIL for f in findings):
        return AuditReport(findings=tuple(findings))

    text, enc_findings = _decode_source(content)
    findings.extend(enc_findings)
    if text is None:
        return AuditReport(findings=tuple(findings))

    findings.extend(_check_line_heuristics(text))

    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        findings.append(
            _finding(
                "SYNTAX",
                SEVERITY_FAIL,
                f"SyntaxError: {exc.msg} at line {exc.lineno}",
            )
        )
        return AuditReport(findings=tuple(findings))

    visitor = _PolicyVisitor()
    visitor.visit(tree)
    findings.extend(visitor.findings)

    if visitor.saw_decode_call and visitor.saw_dyn_exec:
        if not any(f.code == "DECODE_EXEC" for f in findings):
            findings.append(
                _finding(
                    "DECODE_EXEC",
                    SEVERITY_FAIL,
                    "Module contains both decode and dynamic exec/eval",
                )
            )

    stem = Path(filename).stem
    findings.extend(_check_nova3_structure(tree, stem))

    return AuditReport(findings=tuple(findings))


def audit_plugin_bytes(
    content: bytes,
    *,
    filename: str,
    clamav_session: ClamAvSession | None = None,
) -> AuditReport:
    """Full safety check: static review, then optional ClamAV when session provided."""
    report = audit_plugin_static(content, filename=filename)
    if report.blocked:
        return report

    if clamav_session is None:
        return report

    clam_findings, status, backend = clamav_session.scan_bytes(
        content, filename=filename
    )
    return AuditReport(
        findings=tuple([*report.findings, *clam_findings]),
        clamav_status=status,
        clamav_backend=backend,
    )
