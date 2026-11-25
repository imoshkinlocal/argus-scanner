"""Baselines and report comparison."""

from __future__ import annotations

import json

import pytest

from argus import baseline as baseline_module
from argus.models import Finding, ScanResult, Severity


def make_sast(line: int = 10, message: str = "unsafe query") -> Finding:
    return Finding(
        rule_id="java-sqli-jdbc", title="SQL injection", severity=Severity.HIGH,
        kind="sast", engine="argus-java", file="src/App.java",
        start_line=line, message=message, cwe="CWE-89")


def make_sca(version: str = "2.14.1") -> Finding:
    return Finding(
        rule_id="CVE-2021-44228", title="Log4Shell", severity=Severity.CRITICAL,
        kind="sca", engine="osv", package="log4j-core", version=version,
        fixed_version="2.17.0", purl="pkg:maven/org.apache/log4j-core@2.14.1")


def test_stable_key_ignores_line_numbers():
    first = make_sast(line=10)
    second = make_sast(line=250)
    assert baseline_module.stable_key(first) == baseline_module.stable_key(second)


def test_stable_key_changes_with_message():
    assert baseline_module.stable_key(make_sast(message="a")) != \
        baseline_module.stable_key(make_sast(message="b"))


def test_stable_key_sca_uses_version():
    assert baseline_module.stable_key(make_sca("2.14.1")) != \
        baseline_module.stable_key(make_sca("2.17.0"))


def test_build_and_write(tmp_path):
    path = tmp_path / "baseline.json"
    written = baseline_module.write(str(path), [make_sast(), make_sca()],
                                    target="/src")
    assert written.count == 2
    payload = json.loads(path.read_text())
    assert payload["version"] == baseline_module.BASELINE_VERSION
    assert payload["target"] == "/src"
    assert payload["count"] == 2


def test_build_deduplicates():
    baseline = baseline_module.build([make_sast(line=1), make_sast(line=2)])
    assert baseline.count == 1


def test_apply_marks_new_and_existing(tmp_path):
    path = tmp_path / "baseline.json"
    baseline_module.write(str(path), [make_sast()])
    loaded = baseline_module.load(str(path))

    existing = make_sast(line=99)
    new = make_sca()
    counts = baseline_module.apply([existing, new], loaded)
    assert counts == {"new": 1, "existing": 1}
    assert existing.baseline == "existing"
    assert new.baseline == "new"


def test_load_accepts_plain_keys(tmp_path):
    path = tmp_path / "baseline.json"
    key = baseline_module.stable_key(make_sast())
    path.write_text(json.dumps({"keys": [key]}))
    loaded = baseline_module.load(str(path))
    assert loaded.contains(make_sast(line=500))


def test_load_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        baseline_module.load(str(tmp_path / "absent.json"))


def test_load_invalid_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json")
    with pytest.raises(ValueError):
        baseline_module.load(str(path))


def _report(findings):
    return {"findings": [finding.to_dict() for finding in findings]}


def test_diff_reports():
    old = _report([make_sast(), make_sca("2.14.1")])
    fixed_removed = make_sca("2.17.0")
    new = _report([make_sast(line=42), fixed_removed])
    diff = baseline_module.diff_reports(old, new)
    assert diff.counts["unchanged"] == 1
    assert diff.counts["new"] == 1
    assert diff.counts["fixed"] == 1
    assert diff.new[0]["package"]["version"] == "2.17.0"


def test_diff_severity_change():
    old = _report([make_sast()])
    changed = make_sast()
    changed.severity = Severity.CRITICAL
    diff = baseline_module.diff_reports(old, _report([changed]))
    assert diff.counts["changed"] == 1
    previous, current = diff.changed[0]
    assert previous["severity"] == "high"
    assert current["severity"] == "critical"


def test_diff_regressions_threshold():
    old = _report([])
    high = make_sast()
    low = Finding(rule_id="low-rule", title="x", severity=Severity.LOW,
                  kind="sast", engine="argus-java", file="a.java", message="low")
    diff = baseline_module.diff_reports(old, _report([high, low]))
    assert len(diff.regressions("high")) == 1
    assert len(diff.regressions("low")) == 2
    assert diff.regressions("none") == []


def test_diff_skips_suppressed_by_default():
    old = _report([])
    suppressed = make_sast()
    suppressed.suppressed = True
    diff = baseline_module.diff_reports(old, _report([suppressed]))
    assert diff.counts["new"] == 0
    diff_all = baseline_module.diff_reports(old, _report([suppressed]),
                                            include_suppressed=True)
    assert diff_all.counts["new"] == 1


def test_diff_files(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(_report([make_sast()])))
    new_path.write_text(json.dumps(_report([make_sast(), make_sca()])))
    diff = baseline_module.diff_files(str(old_path), str(new_path))
    assert diff.counts["unchanged"] == 1
    assert diff.counts["new"] == 1


def test_render_diff_formats():
    diff = baseline_module.diff_reports(_report([make_sast()]),
                                        _report([make_sca()]))
    text = baseline_module.render_diff(diff, "text")
    assert "NEW (1)" in text and "FIXED (1)" in text
    markdown = baseline_module.render_diff(diff, "md")
    assert markdown.startswith("# argus report diff")
    payload = json.loads(baseline_module.render_diff(diff, "json"))
    assert payload["counts"]["new"] == 1
    assert len(payload["new_findings"]) == 1


def test_load_report_validation(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"findings": []}))
    assert baseline_module.load_report(str(path))["findings"] == []
    path.write_text(json.dumps({"nope": True}))
    with pytest.raises(ValueError):
        baseline_module.load_report(str(path))


def test_baseline_from_result():
    result = ScanResult(target="/src")
    result.findings = [make_sast(), make_sca()]
    baseline = baseline_module.baseline_from_result(result)
    assert baseline.count == 2
    assert baseline.target == "/src"
