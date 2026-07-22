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


def test_dangerous_builtin_reference_warned():
    src = engine_source(body="handler = eval\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked
    assert any(f.code == "BUILTIN_REF" for f in report.findings)
    assert any("eval" in f.message for f in report.findings)


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


def test_py2_shim_htmlparser_in_try_body_is_warn():
    src = engine_source(
        extra_imports=(
            "try:\n"
            "    from HTMLParser import HTMLParser\n"
            "except ImportError:\n"
            "    from html.parser import HTMLParser\n"
        )
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked
    assert any(f.code == "IMPORT_PY2_SHIM" for f in report.warn_findings)


def test_py2_shim_htmlparser_in_except_is_warn():
    src = engine_source(
        extra_imports=(
            "try:\n"
            "    from html.parser import HTMLParser\n"
            "except ImportError:\n"
            "    from HTMLParser import HTMLParser\n"
        )
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked
    assert any(f.code == "IMPORT_PY2_SHIM" for f in report.warn_findings)


def test_bare_htmlparser_still_blocked():
    src = engine_source(extra_imports="from HTMLParser import HTMLParser\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "IMPORT_DENY" for f in report.fail_findings)


def test_configparser_allowed():
    src = engine_source(extra_imports="import configparser\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked


def test_threading_allowed():
    src = engine_source(
        extra_imports="import threading\n",
        body=(
            "t = threading.Thread(target=lambda: None)\n"
            "        t.start()\n"
            "        t.join()\n"
            "        prettyPrinter({'name': what})"
        ),
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked


def test_thread_pool_executor_allowed():
    src = engine_source(
        extra_imports="from concurrent.futures import ThreadPoolExecutor\n",
        body=(
            "with ThreadPoolExecutor(max_workers=2) as ex:\n"
            "            ex.submit(lambda: None)\n"
            "        prettyPrinter({'name': what})"
        ),
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked


def test_multiprocessing_dummy_allowed():
    src = engine_source(
        extra_imports=(
            "from multiprocessing.dummy import Pool\n"
            "from threading import Lock\n"
        ),
        body=(
            "with Pool(2) as pool:\n"
            "            pool.map(lambda x: x, [1])\n"
            "        prettyPrinter({'name': what})"
        ),
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked


def test_multiprocessing_process_blocked():
    src = engine_source(extra_imports="from multiprocessing import Process\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(
        f.code in {"IMPORT_DENY", "PROCESS_EXEC"} for f in report.fail_findings
    )


def test_multiprocessing_module_blocked():
    src = engine_source(extra_imports="import multiprocessing\n")
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "IMPORT_DENY" for f in report.fail_findings)


def test_process_pool_executor_import_blocked():
    src = engine_source(
        extra_imports="from concurrent.futures import ProcessPoolExecutor\n"
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "PROCESS_EXEC" for f in report.fail_findings)


def test_process_pool_executor_call_blocked():
    src = engine_source(
        extra_imports="import concurrent.futures\n",
        body=(
            "with concurrent.futures.ProcessPoolExecutor() as ex:\n"
            "            pass\n"
            "        prettyPrinter({'name': what})"
        ),
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert report.blocked
    assert any(f.code == "PROCESS_EXEC" for f in report.fail_findings)


def test_jackett_style_concurrency_header_allowed():
    """Official Jackett uses multiprocessing.dummy.Pool + threading.Lock."""
    src = (
        "from multiprocessing.dummy import Pool\n"
        "from threading import Lock\n"
        "from novaprinter import prettyPrinter\n"
        "\n"
        "class demo:\n"
        '    url = "https://example.com"\n'
        '    name = "Demo"\n'
        '    supported_categories = {"all": ""}\n'
        "\n"
        "    def search(self, what, cat='all'):\n"
        "        with Pool(2) as pool:\n"
        "            pool.map(lambda x: x, [what])\n"
        "        prettyPrinter({'name': what})\n"
    )
    report = audit_plugin_static(src.encode(), filename="demo.py")
    assert not report.blocked
