"""Tests for static plugin safety audit."""

from __future__ import annotations

import base64
import io
import secrets
import zipfile

from qbit_plugin_dl.audit import audit_plugin_bytes, audit_plugin_static
from tests.fixtures.engine_stubs import CLEAN_ENGINE_BYTES, engine_source


def test_clean_engine_not_blocked():
    report = audit_plugin_static(CLEAN_ENGINE_BYTES, filename="demo.py")
    assert not report.blocked
    assert report.fail_findings == ()


def test_exec_blocked():
    src = engine_source(body="exec('print(1)')")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "DYN_EXEC" for f in report.fail_findings)


def test_os_system_blocked():
    src = engine_source(extra_imports="import os\n", body="os.system('id')")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "OS_EXEC" for f in report.fail_findings)


def test_subprocess_import_blocked():
    src = engine_source(extra_imports="import subprocess\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "IMPORT_DENY" for f in report.fail_findings)


def test_marshal_loads_blocked():
    src = engine_source(
        extra_imports="import marshal\n",
        body="marshal.loads(b'')",
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code in {"IMPORT_DENY", "PICKLE_MARSHAL"} for f in report.fail_findings)


def test_decode_then_exec_blocked():
    src = engine_source(
        extra_imports="import base64\n",
        body="exec(base64.b64decode('cHJpbnQoMSk='))",
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code in {"DYN_EXEC", "DECODE_EXEC"} for f in report.fail_findings)


def test_non_allowlisted_import_blocked():
    src = engine_source(extra_imports="import requests\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "IMPORT_DENY" for f in report.fail_findings)


def test_missing_search_blocked():
    src = (
        "class demo:\n"
        '    url = "https://example.com"\n'
        '    name = "Demo"\n'
        '    supported_categories = {"all": ""}\n'
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "NOVA3_STRUCTURE" for f in report.fail_findings)


def test_high_entropy_warn_only():
    blob = base64.b64encode(secrets.token_bytes(90)).decode("ascii")
    src = engine_source(body=f"x = {blob!r}\n        prettyPrinter({{'name': what}})")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked
    assert any(f.code == "HIGH_ENTROPY" for f in report.warn_findings)


def test_zip_masquerading_blocked():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.py", "print('hi')")
    report = audit_plugin_static(buf.getvalue(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "FORMAT_ZIP" for f in report.fail_findings)


def test_nul_bytes_blocked():
    report = audit_plugin_static(b"pass\x00pass", filename="demo.py")
    assert report.blocked
    assert any(f.code == "FORMAT_NUL" for f in report.fail_findings)


def test_audit_plugin_bytes_without_clamav_session():
    report = audit_plugin_bytes(CLEAN_ENGINE_BYTES, filename="demo.py")
    assert not report.blocked
    assert report.clamav_backend == "none"
