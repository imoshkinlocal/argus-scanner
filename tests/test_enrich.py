"""Finding enrichment: snippets, remediation, CWE names and overrides."""

from __future__ import annotations

from argus import enrich
from argus.models import Finding, Severity


def make_finding(rule="java-sqli-jdbc", cwe="CWE-89", kind="sast",
                 package="", version="", fixed="") -> Finding:
    return Finding(
        rule_id=rule, title="issue", severity=Severity.HIGH, kind=kind,
        engine="argus-java" if kind == "sast" else "osv",
        file="App.java" if kind == "sast" else "",
        start_line=3 if kind == "sast" else 0,
        message="unsafe query", cwe=cwe, package=package, version=version,
        fixed_version=fixed, purl=f"pkg:npm/{package}@{version}" if package else "")


def test_read_snippet(tmp_path):
    path = tmp_path / "App.java"
    path.write_text("line1\nline2\nline3\nline4\nline5\n")
    start, lines = enrich.read_snippet(str(path), 3, context=1)
    assert start == 2
    assert lines == ["line2", "line3", "line4"]


def test_read_snippet_bounds(tmp_path):
    path = tmp_path / "App.java"
    path.write_text("only\n")
    start, lines = enrich.read_snippet(str(path), 99, context=2)
    assert start == 1
    assert lines == ["only"]


def test_read_snippet_missing(tmp_path):
    assert enrich.read_snippet(str(tmp_path / "nope.java"), 1) is None
    assert enrich.read_snippet("", 1) is None


def test_read_snippet_skips_binary(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01\x02binary")
    assert enrich.read_snippet(str(path), 1) is None


def test_attach_snippets(tmp_path):
    path = tmp_path / "App.java"
    path.write_text("a\nb\nc\nd\ne\n")
    finding = make_finding()
    finding.file = "App.java"
    attached = enrich.attach_snippets([finding], root=str(tmp_path), context=1)
    assert attached == 1
    assert finding.snippet_start == 2
    assert finding.snippet == ["b", "c", "d"]


def test_attach_snippets_stops_at_truncation(tmp_path, monkeypatch):
    path = tmp_path / "App.java"
    path.write_text("x" * 100 + "\n")
    finding = make_finding()
    finding.file = "App.java"
    monkeypatch.setattr(enrich, "MAX_SNIPPET_LINE", 10)
    enrich.attach_snippets([finding], root=str(tmp_path), context=0)
    assert finding.snippet[0].endswith("...")


def test_upgrade_command_per_ecosystem():
    finding = make_finding("CVE-1", kind="sca", package="lodash",
                           version="4.0.0", fixed="4.17.21")
    finding.metadata["ecosystem"] = "npm"
    assert enrich.upgrade_command(finding) == "npm install lodash@4.17.21"
    finding.metadata["ecosystem"] = "PyPI"
    assert enrich.upgrade_command(finding) == "pip install 'lodash==4.17.21'"
    finding.metadata["ecosystem"] = "Unknown"
    assert enrich.upgrade_command(finding) == ""


def test_remediation_for_sca():
    finding = make_finding("CVE-1", kind="sca", package="lodash",
                           version="4.0.0", fixed="4.17.21")
    finding.metadata["ecosystem"] = "npm"
    hints = enrich.remediation_for(finding)
    assert "npm install lodash@4.17.21" in hints
    assert any("Upgrade lodash" in hint for hint in hints)


def test_remediation_for_sca_without_fix():
    finding = make_finding("CVE-1", kind="sca", package="foo", version="1.0")
    hints = enrich.remediation_for(finding)
    assert any("No fixed version" in hint for hint in hints)


def test_remediation_for_secret():
    finding = make_finding("secret-aws-access-key", cwe="CWE-798")
    finding.engine = "argus-secrets"
    hints = enrich.remediation_for(finding)
    assert hints[0].startswith("Rotate the exposed credential")


def test_remediation_capped():
    finding = make_finding()
    hints = enrich.remediation_for(finding)
    assert 1 <= len(hints) <= 4


def test_attach_cwe_names():
    finding = make_finding(cwe="CWE-89")
    assert enrich.attach_cwe_names([finding]) == 1
    assert "SQL" in finding.cwe_name
    assert finding.cwe_name_ru


def test_severity_overrides_by_rule_cwe_and_package():
    rule = make_finding(rule="java-sqli-jdbc")
    cwe = make_finding(rule="java-xss", cwe="CWE-79")
    pkg = make_finding(rule="CVE-1", kind="sca", package="log4j-core",
                       version="2.14.1")
    changed = enrich.apply_severity_overrides(
        [rule, cwe, pkg],
        {"java-sqli-*": "critical", "CWE-79": "low",
         "package:log4j-core": "medium"})
    assert changed == 3
    assert rule.severity is Severity.CRITICAL
    assert cwe.severity is Severity.LOW
    assert pkg.severity is Severity.MEDIUM
    assert rule.metadata["severity_original"] == "high"


def test_severity_override_invalid_severity_ignored():
    finding = make_finding()
    changed = enrich.apply_severity_overrides([finding], {"*": "nonsense"})
    assert changed == 0
    assert finding.severity is Severity.HIGH


def test_enrich_pipeline(tmp_path):
    path = tmp_path / "App.java"
    path.write_text("a\nb\nc\nd\ne\n")
    finding = make_finding()
    counts = enrich.enrich([finding], enrich.EnrichOptions(root=str(tmp_path)))
    assert counts["cwe"] == 1
    assert counts["remediation"] >= 1
    assert counts["snippets"] == 1


def test_format_snippet():
    finding = make_finding()
    finding.snippet = ["aaa", "bbb", "ccc"]
    finding.snippet_start = 2
    finding.start_line = 3
    rendered = enrich.format_snippet(finding)
    assert "> 3 | bbb" in rendered
    assert "  2 | aaa" in rendered


def test_format_snippet_empty():
    assert enrich.format_snippet(make_finding()) == ""
