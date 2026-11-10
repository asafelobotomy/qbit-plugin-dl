"""Static safety review of downloaded nova3 engine sources.

Never import or exec plugin bodies. ClamAV is optional via ``audit_clamav``.
The policy lives in ``policy``, the AST checks in ``visitor`` and its mixins, and the
engine-shape checks in ``structure``.
"""

from __future__ import annotations

from qbit_plugin_dl.audit.core import audit_plugin_bytes, audit_plugin_static
from qbit_plugin_dl.audit.policy import SEVERITY_FAIL, SEVERITY_INFO, SEVERITY_WARN
from qbit_plugin_dl.audit.report import AuditFinding, AuditReport

__all__ = [
    "SEVERITY_FAIL",
    "SEVERITY_INFO",
    "SEVERITY_WARN",
    "AuditFinding",
    "AuditReport",
    "audit_plugin_bytes",
    "audit_plugin_static",
]
