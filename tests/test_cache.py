"""Incremental SAST cache and offline database integrity."""

from __future__ import annotations

import json
import zipfile

import pytest

from argus.cli import EXIT_ERROR, EXIT_OK, main
from argus.sast.cache import SastCache, cache_key, default_directory
from argus.sast.scanner import SastOptions, scan_target
from argus.sca.osv import LocalOSVDB

VULNERABLE = """\
import javax.servlet.http.*;
public class Vulnerable extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("id");
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = '" + param + "'");
    }
}
"""


def test_cache_key_depends_on_content_and_properties():
    base = cache_key("A.java", b"class A {}", properties={"x": "1"})
    assert base == cache_key("A.java", b"class A {}", properties={"x": "1"})
    assert base != cache_key("A.java", b"class A {}", properties={"x": "2"})
    assert base != cache_key("A.java", b"class A { }")
    assert base != cache_key("B.java", b"class A {}")


def test_cache_roundtrip(tmp_path):
    from argus.models import Finding, Severity

    with SastCache(str(tmp_path)) as cache:
        assert cache.get("missing") is None
        finding = Finding(rule_id="r", title="t", severity=Severity.HIGH,
                          kind="sast", engine="argus-java", file="A.java",
                          start_line=4, message="m", cwe="CWE-89",
                          licenses=["MIT"])
        cache.put("key", [finding])
        loaded = cache.get("key")
        assert loaded is not None
        assert loaded[0].rule_id == "r"
        assert loaded[0].severity is Severity.HIGH
        assert loaded[0].start_line == 4
        assert loaded[0].licenses == ["MIT"]
        assert cache.stats() == {"hits": 1, "misses": 1, "stored": 1}


def test_cache_prune_and_clear(tmp_path):
    import time

    with SastCache(str(tmp_path)) as cache:
        cache.put("old", [])
        cache._connection.execute("UPDATE findings SET created = ?", (time.time() - 90 * 86400,))
        cache._connection.commit()
        assert cache.prune() == 1
        cache.put("new", [])
        assert cache.clear() == 1


def test_default_directory_honours_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_directory() == str(tmp_path / "argus" / "sast")


def _project(tmp_path):
    (tmp_path / "Vulnerable.java").write_text(VULNERABLE)
    return str(tmp_path)


def test_scan_uses_cache_on_second_run(tmp_path):
    root = _project(tmp_path)
    cache_dir = tmp_path / "cache"
    options = SastOptions(cache=True, cache_dir=str(cache_dir))
    first = scan_target(root, options)
    first_stats = first.stats["sast_cache"]
    assert first_stats["misses"] >= 1
    assert first_stats["stored"] >= 1
    second = scan_target(root, SastOptions(cache=True, cache_dir=str(cache_dir)))
    second_stats = second.stats["sast_cache"]
    assert second_stats["hits"] >= 1
    assert [finding.rule_id for finding in second.findings] == \
        [finding.rule_id for finding in first.findings]


def test_changed_file_misses_cache(tmp_path):
    root = _project(tmp_path)
    cache_dir = tmp_path / "cache"
    scan_target(root, SastOptions(cache=True, cache_dir=str(cache_dir)))
    (tmp_path / "Vulnerable.java").write_text(VULNERABLE + "\n// changed\n")
    result = scan_target(root, SastOptions(cache=True, cache_dir=str(cache_dir)))
    assert result.stats["sast_cache"]["misses"] >= 1
    assert result.stats["sast_cache"]["hits"] == 0


def test_cache_can_be_disabled(tmp_path):
    root = _project(tmp_path)
    result = scan_target(root, SastOptions(cache=False))
    assert "sast_cache" not in result.stats


def test_cli_no_sast_cache(tmp_path, capsys):
    root = _project(tmp_path)
    code = main(["sast", root, "--engine", "java", "-f", "json",
                 "--no-sast-cache", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code in (EXIT_OK, 1)
    assert "sast_cache" not in payload["stats"]


def test_cli_sast_cache_directory(tmp_path, capsys):
    root = _project(tmp_path)
    cache_dir = tmp_path / "mycache"
    code = main(["sast", root, "--engine", "java", "-f", "json",
                 "--sast-cache-dir", str(cache_dir), "-q"])
    json.loads(capsys.readouterr().out)
    assert code in (EXIT_OK, 1)
    assert (cache_dir / "findings.sqlite3").is_file()


# --------------------------------------------------------------------------- offline DB integrity

def _fake_archive(directory, ecosystem="Maven"):
    path = directory / ecosystem / "all.zip"
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("OSV-1.json", json.dumps({"id": "OSV-1"}))
    return path


def test_snapshot_and_verify(tmp_path):
    archive = _fake_archive(tmp_path)
    database = LocalOSVDB(str(tmp_path))
    database._write_metadata("Maven", str(archive), "https://example.invalid/all.zip")
    snapshot = database.snapshot("Maven")
    assert snapshot["size_bytes"] == archive.stat().st_size
    assert len(snapshot["sha256"]) == 64
    assert snapshot["downloaded_at"].endswith("Z")
    result = database.verify("Maven")
    assert result["ok"] is True

    archive.write_bytes(archive.read_bytes() + b"tampered")
    assert database.verify("Maven")["ok"] is False


def test_snapshot_without_sidecar(tmp_path):
    _fake_archive(tmp_path)
    database = LocalOSVDB(str(tmp_path))
    snapshot = database.snapshot("Maven")
    assert snapshot["sha256"] == ""
    assert snapshot["size_bytes"] > 0
    assert database.verify("Maven")["ok"] is False


def test_db_status_lists_snapshot_metadata(tmp_path, capsys):
    archive = _fake_archive(tmp_path)
    database = LocalOSVDB(str(tmp_path))
    database._write_metadata("Maven", str(archive), "https://example.invalid/all.zip")
    code = main(["db", "status", "--db-dir", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    maven = next(row for row in payload["ecosystems"] if row["ecosystem"] == "Maven")
    assert len(maven["sha256"]) == 64
    assert maven["downloaded_at"]


def test_db_status_verify_detects_tampering(tmp_path, capsys):
    archive = _fake_archive(tmp_path)
    database = LocalOSVDB(str(tmp_path))
    database._write_metadata("Maven", str(archive), "https://example.invalid/all.zip")
    assert main(["db", "status", "--db-dir", str(tmp_path), "--verify"]) == EXIT_OK
    capsys.readouterr()
    archive.write_bytes(b"broken")
    code = main(["db", "status", "--db-dir", str(tmp_path), "--verify"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_ERROR
    assert payload["failed"] == 1
