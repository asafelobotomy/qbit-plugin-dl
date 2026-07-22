"""Tests for optional install-time safe fixes."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from qbit_plugin_dl.audit import audit_plugin_static
from qbit_plugin_dl.audit_clamav import ClamAvSession
from qbit_plugin_dl.catalog import Plugin, Visibility
from qbit_plugin_dl.fix import (
    FixKind,
    apply_safe_ast_fixes,
    audit_clamav_then_static,
    filename_alternates_map,
    ranked_alternates,
    try_ast_fix_after_clamav,
)
from qbit_plugin_dl.install import install_plugins_async
from qbit_plugin_dl.provenance import (
    fix_kinds_for_filename,
    list_fixed_filenames,
    load_installed_provenance,
    record_install_provenance,
)
from tests.fixtures.engine_stubs import CLEAN_ENGINE_BYTES, engine_source
from tests.http_fakes import TRUSTED_TEST_HOSTS, AsyncMapClient


def _plugin(**kwargs) -> Plugin:
    base = Plugin(
        name="Demo",
        site_url="https://example.com",
        author="a",
        author_url="",
        version="1",
        last_update="",
        download_url="https://example.com/demo.py",
        comments="",
        visibility=Visibility.PUBLIC,
        warning=False,
    )
    return replace(base, **kwargs) if kwargs else base


def test_apply_safe_ast_fixes_py2_imports_unblocks_audit():
    src = engine_source(extra_imports="from HTMLParser import HTMLParser\n")
    before = audit_plugin_static(src.encode(), filename="demo.py")
    assert before.blocked
    assert any(f.code == "IMPORT_DENY" for f in before.fail_findings)

    fixed, kinds = apply_safe_ast_fixes(src.encode(), filename="demo.py")
    assert FixKind.PY2_IMPORTS in kinds
    assert b"from html.parser import HTMLParser" in fixed
    after = audit_plugin_static(fixed, filename="demo.py")
    assert not after.blocked


def test_apply_safe_ast_fixes_process_pool_to_thread():
    src = engine_source(
        extra_imports="from concurrent.futures import ProcessPoolExecutor\n",
        body="ProcessPoolExecutor()",
    )
    before = audit_plugin_static(src.encode(), filename="demo.py")
    assert before.blocked
    assert any(f.code == "PROCESS_EXEC" for f in before.fail_findings)

    fixed, kinds = apply_safe_ast_fixes(src.encode(), filename="demo.py")
    assert FixKind.PROCESS_POOL in kinds
    assert b"ThreadPoolExecutor" in fixed
    assert b"ProcessPoolExecutor" not in fixed
    after = audit_plugin_static(fixed, filename="demo.py")
    assert not after.blocked


def test_apply_safe_ast_fixes_multiprocessing_pool_to_dummy():
    src = engine_source(
        extra_imports="from multiprocessing import Pool\n",
        body="Pool(2)",
    )
    before = audit_plugin_static(src.encode(), filename="demo.py")
    assert before.blocked

    fixed, kinds = apply_safe_ast_fixes(src.encode(), filename="demo.py")
    assert FixKind.MP_DUMMY in kinds
    assert b"multiprocessing.dummy" in fixed
    after = audit_plugin_static(fixed, filename="demo.py")
    assert not after.blocked


def test_apply_safe_ast_fixes_noop_when_clean():
    fixed, kinds = apply_safe_ast_fixes(CLEAN_ENGINE_BYTES, filename="demo.py")
    assert kinds == []
    assert fixed == CLEAN_ENGINE_BYTES


def test_infected_clamav_skips_ast_transform():
    src = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()

    def which(name: str) -> str | None:
        return "/usr/bin/clamdscan" if name == "clamdscan" else None

    def run(argv, **_kwargs):  # noqa: ANN001
        if "--ping" in argv:
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return type("R", (), {"returncode": 1, "stdout": "FOUND", "stderr": ""})()

    session = ClamAvSession(enabled=True, which=which, run=run)
    report = audit_clamav_then_static(
        src, filename="demo.py", clamav_session=session
    )
    assert report.clamav_status == "infected"

    with patch("qbit_plugin_dl.fix.apply_safe_ast_fixes") as mock_fix:
        out, out_report, kinds = try_ast_fix_after_clamav(
            src,
            filename="demo.py",
            clamav_session=session,
            prior_report=report,
        )
        mock_fix.assert_not_called()
    assert kinds == []
    assert out == src
    assert out_report.clamav_status == "infected"


def test_transform_then_clamav_infected_no_write(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()
    bad = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()

    scan_count = {"n": 0}

    def which(name: str) -> str | None:
        return "/usr/bin/clamdscan" if name == "clamdscan" else None

    def run(argv, **_kwargs):  # noqa: ANN001
        if "--ping" in argv:
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        scan_count["n"] += 1
        # First scan clean; second (post-rewrite) infected.
        code = 0 if scan_count["n"] == 1 else 1
        return type("R", (), {"returncode": code, "stdout": "FOUND", "stderr": ""})()

    session = ClamAvSession(enabled=True, which=which, run=run)
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncMapClient({plugin.download_url: bad}),  # type: ignore[arg-type]
            clamav_session=session,
            auto_fix=True,
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert not results[0].ok
    assert results[0].audit is not None
    assert results[0].audit.clamav_status == "infected"
    assert not (engines / "demo.py").exists()
    assert scan_count["n"] >= 2


def test_auto_fix_false_never_calls_fixer(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()
    bad = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()

    with patch("qbit_plugin_dl.fix.apply_safe_ast_fixes") as mock_fix:
        results = asyncio.run(
            install_plugins_async(
                [plugin],
                engines,
                client=AsyncMapClient({plugin.download_url: bad}),  # type: ignore[arg-type]
                auto_fix=False,
                trusted_hosts=TRUSTED_TEST_HOSTS,
            )
        )
        mock_fix.assert_not_called()
    assert not results[0].ok
    assert not (engines / "demo.py").exists()


def test_auto_fix_rewrites_and_writes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()
    bad = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()

    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncMapClient({plugin.download_url: bad}),  # type: ignore[arg-type]
            auto_fix=True,
            trusted_hosts=TRUSTED_TEST_HOSTS,
            allow_ast_without_clamav=True,
        )
    )
    assert results[0].ok
    assert results[0].fix is not None
    assert FixKind.PY2_IMPORTS in results[0].fix.kinds
    written = (engines / "demo.py").read_bytes()
    assert b"html.parser" in written
    prov = load_installed_provenance()
    assert prov["demo.py"]["fixed"] is True
    assert "py2_imports" in prov["demo.py"]["fix_kinds"]
    assert "demo.py" in list_fixed_filenames()


def test_alternate_used_on_404(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    # Same basename (scare.py) from different URL paths → same install filename.
    primary = _plugin(
        name="Scare",
        author="dead",
        download_url="https://example.com/dead/scare.py",
    )
    alt = _plugin(
        name="Scare",
        author="alive",
        download_url="https://example.com/alive/scare.py",
    )
    assert primary.filename == alt.filename == "scare.py"
    client = AsyncMapClient(
        {
            primary.download_url: (404, b""),
            alt.download_url: CLEAN_ENGINE_BYTES,
        }
    )
    results = asyncio.run(
        install_plugins_async(
            [primary],
            engines,
            client=client,  # type: ignore[arg-type]
            auto_fix=True,
            catalog=[primary, alt],
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert results[0].ok
    assert results[0].plugin.download_url == alt.download_url
    assert results[0].fix is not None
    assert FixKind.ALTERNATE in results[0].fix.kinds
    assert primary.download_url in client.gets
    assert alt.download_url in client.gets


def test_ranked_alternates_excludes_tried():
    a = _plugin(download_url="https://example.com/a/x.py", author="a")
    b = _plugin(download_url="https://example.com/b/x.py", author="b")
    assert a.filename == b.filename == "x.py"
    mapping = filename_alternates_map([a, b])
    alts = ranked_alternates(a, mapping, tried_urls={b.download_url})
    assert alts == []
    alts2 = ranked_alternates(a, mapping)
    assert [p.download_url for p in alts2] == [b.download_url]


def test_provenance_fixed_round_trip(tmp_path: Path):
    path = tmp_path / "installed.json"
    record_install_provenance(
        "demo.py",
        download_url="https://example.com/demo.py",
        sha="abc",
        path=path,
        fixed=True,
        rewritten=True,
        fix_kinds=["py2_imports", "alternate_fork"],
        source_sha="srcsha",
    )
    assert list_fixed_filenames(path) == {"demo.py"}
    assert fix_kinds_for_filename("demo.py", path=path) == [
        "py2_imports",
        "alternate_fork",
    ]
    data = load_installed_provenance(path)
    assert data["demo.py"]["rewritten"] is True
    assert data["demo.py"]["fixed"] is True
    assert data["demo.py"]["source_sha"] == "srcsha"


def test_ast_kinds_do_not_leak_across_alternate(tmp_path: Path, monkeypatch):
    """H1: failed AST on primary must not mark alternate write as rewritten."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    primary = _plugin(download_url="https://example.com/dead/demo.py")
    alt = _plugin(author="alive", download_url="https://example.com/alive/demo.py")
    # Primary: py2 rewrite applies but still blocked (requests).
    bad = engine_source(
        extra_imports="from HTMLParser import HTMLParser\nimport requests\n"
    ).encode()
    results = asyncio.run(
        install_plugins_async(
            [primary],
            engines,
            client=AsyncMapClient(
                {primary.download_url: bad, alt.download_url: CLEAN_ENGINE_BYTES}
            ),  # type: ignore[arg-type]
            auto_fix=True,
            catalog=[primary, alt],
            trusted_hosts=TRUSTED_TEST_HOSTS,
            allow_ast_without_clamav=True,
        )
    )
    assert results[0].ok
    assert results[0].fix is not None
    assert results[0].fix.kinds == (FixKind.ALTERNATE,)
    assert results[0].fix.rewritten is False
    written = (engines / "demo.py").read_bytes()
    assert written == CLEAN_ENGINE_BYTES
    assert b"html.parser" not in written
    prov = load_installed_provenance()["demo.py"]
    assert prov.get("rewritten") is not True
    assert "py2_imports" not in prov.get("fix_kinds", [])
    assert FixKind.ALTERNATE.value in prov["fix_kinds"]


def test_apply_safe_ast_fixes_bare_multiprocessing_import():
    src = engine_source(
        extra_imports="import multiprocessing\n",
        body="multiprocessing.Pool(2)",
    ).encode()
    before = audit_plugin_static(src, filename="demo.py")
    assert before.blocked
    fixed, kinds = apply_safe_ast_fixes(src, filename="demo.py")
    assert FixKind.MP_DUMMY in kinds
    assert b"import multiprocessing.dummy" in fixed
    assert b"multiprocessing.dummy.Pool" in fixed
    after = audit_plugin_static(fixed, filename="demo.py")
    assert not after.blocked


def test_clamav_allows_ast_statuses():
    from qbit_plugin_dl.fix import clamav_allows_ast

    assert clamav_allows_ast("clean") is True
    assert clamav_allows_ast("infected") is False
    assert clamav_allows_ast("skipped") is False
    assert clamav_allows_ast("unavailable") is False
    assert clamav_allows_ast("error") is False
    assert clamav_allows_ast("weird") is False
    assert clamav_allows_ast("skipped", allow_without_clamav=True) is True
    assert clamav_allows_ast("unavailable", allow_without_clamav=True) is True
    assert clamav_allows_ast("error", allow_without_clamav=True) is True
    assert clamav_allows_ast("infected", allow_without_clamav=True) is False


def test_ast_denied_when_clamav_unavailable_without_override():
    src = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()
    session = ClamAvSession(enabled=True, which=lambda _n: None, run=lambda *a, **k: None)
    report = audit_clamav_then_static(
        src, filename="demo.py", clamav_session=session
    )
    assert report.clamav_status == "unavailable"
    assert report.blocked
    _out, out_report, kinds = try_ast_fix_after_clamav(
        src,
        filename="demo.py",
        clamav_session=session,
        prior_report=report,
    )
    assert kinds == []
    assert out_report.blocked


def test_ast_allowed_when_clamav_unavailable_with_override():
    src = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()
    session = ClamAvSession(enabled=True, which=lambda _n: None, run=lambda *a, **k: None)
    report = audit_clamav_then_static(
        src, filename="demo.py", clamav_session=session
    )
    assert report.clamav_status == "unavailable"
    _out, out_report, kinds = try_ast_fix_after_clamav(
        src,
        filename="demo.py",
        clamav_session=session,
        prior_report=report,
        allow_ast_without_clamav=True,
    )
    assert FixKind.PY2_IMPORTS in kinds
    assert not out_report.blocked


def test_infected_refuses_alternate_walk(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    primary = _plugin(download_url="https://example.com/dead/demo.py")
    alt = _plugin(author="alive", download_url="https://example.com/alive/demo.py")

    def which(name: str) -> str | None:
        return "/usr/bin/clamdscan" if name == "clamdscan" else None

    def run(argv, **_kwargs):  # noqa: ANN001
        if "--ping" in argv:
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return type("R", (), {"returncode": 1, "stdout": "FOUND", "stderr": ""})()

    session = ClamAvSession(enabled=True, which=which, run=run)
    client = AsyncMapClient(
        {
            primary.download_url: CLEAN_ENGINE_BYTES,
            alt.download_url: CLEAN_ENGINE_BYTES,
        }
    )
    results = asyncio.run(
        install_plugins_async(
            [primary],
            engines,
            client=client,  # type: ignore[arg-type]
            clamav_session=session,
            auto_fix=True,
            catalog=[primary, alt],
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert not results[0].ok
    assert results[0].audit is not None
    assert results[0].audit.clamav_status == "infected"
    assert client.gets == [primary.download_url]
    assert not (engines / "demo.py").exists()


def test_alternate_after_static_fail(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    primary = _plugin(download_url="https://example.com/dead/demo.py")
    alt = _plugin(author="alive", download_url="https://example.com/alive/demo.py")
    # Non-rewritable static fail (socket).
    bad = engine_source(extra_imports="import socket\n").encode()
    results = asyncio.run(
        install_plugins_async(
            [primary],
            engines,
            client=AsyncMapClient(
                {primary.download_url: bad, alt.download_url: CLEAN_ENGINE_BYTES}
            ),  # type: ignore[arg-type]
            auto_fix=True,
            catalog=[primary, alt],
            trusted_hosts=TRUSTED_TEST_HOSTS,
        )
    )
    assert results[0].ok
    assert results[0].plugin.download_url == alt.download_url
    assert results[0].fix is not None
    assert FixKind.ALTERNATE in results[0].fix.kinds
    assert results[0].fix.rewritten is False


def test_rewrite_records_source_sha(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    engines = tmp_path / "engines"
    plugin = _plugin()
    bad = engine_source(extra_imports="from HTMLParser import HTMLParser\n").encode()
    results = asyncio.run(
        install_plugins_async(
            [plugin],
            engines,
            client=AsyncMapClient({plugin.download_url: bad}),  # type: ignore[arg-type]
            auto_fix=True,
            trusted_hosts=TRUSTED_TEST_HOSTS,
            allow_ast_without_clamav=True,
        )
    )
    assert results[0].ok
    from qbit_plugin_dl.provenance import content_sha

    prov = load_installed_provenance()["demo.py"]
    assert prov["rewritten"] is True
    assert prov["source_sha"] == content_sha(bad)
    assert prov["sha"] == content_sha((engines / "demo.py").read_bytes())
    assert prov["sha"] != prov["source_sha"]
