"""End-to-end post-processing workflow: baseline -> suppress -> enrich -> gate."""

from __future__ import annotations

import json

import pytest

from argus import baseline as baseline_module
from argus import config as config_module
from argus import gates as gates_module
from argus import workflow
from argus.models import Finding, ScanResult, Severity


def make_sast(rule="java-sqli-jdbc", line=10, message="unsafe query") -> Finding:
    return Finding(
        rule_id=rule, title="SQL injection", severity=Severity.HIGH,
        kind="sast", engine="argus-java", file="App.java", start_line=line,
        message=message, cwe="CWE-89")


def make_sca() -> Finding:
    return Finding(
        rule_id="CVE-2021-44228", title="Log4Shell", severity=Severity.CRITICAL,
        kind="sca", engine="osv", package="log4j-core", version="2.14.1",
        fixed_version="2.17.0", purl="pkg:maven/org.apache/log4j-core@2.14.1",
        cwe="CWE-502")


def test_finalize_counts_and_stats():
    result = ScanResult(target="/src")
    result.findings = [make_sast(), make_sca()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", snippets=False, gate_policy=gates_module.GatePolicy(fail_on="none")))
    assert summary.snippets == 0
    assert summary.cwe_names == 2
    assert summary.remediation == 2
    assert result.stats["workflow"]["new"] == 0
    assert result.stats["gate"]["passed"] is True


def test_finalize_attaches_owasp_categories():
    result = ScanResult(target="/src")
    result.findings = [make_sast(), make_sca()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", snippets=False, owasp_version="2025",
        gate_policy=gates_module.GatePolicy(fail_on="none")))
    assert summary.owasp == 2
    assert summary.owasp_version == "2025"
    by_rule = {finding.rule_id: finding for finding in result.findings}
    assert [c.label for c in by_rule["java-sqli-jdbc"].owasp] == ["A05:2025"]
    assert [c.label for c in by_rule["CVE-2021-44228"].owasp] == ["A08:2025"]
    assert result.stats["owasp_version"] == "2025"
    assert result.stats["workflow"]["owasp"] == {"version": "2025", "mapped": 2}


def test_finalize_can_disable_owasp():
    result = ScanResult(target="/src")
    result.findings = [make_sast()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", snippets=False, owasp=False,
        gate_policy=gates_module.GatePolicy(fail_on="none")))
    assert summary.owasp == 0
    assert summary.owasp_version == ""
    assert result.findings[0].owasp == []
    assert "owasp_version" not in result.stats


def test_finalize_baseline(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_module.write(str(baseline_path), [make_sast()])
    result = ScanResult(target="/src")
    result.findings = [make_sast(line=200), make_sca()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", baseline=str(baseline_path), snippets=False,
        gate_policy=gates_module.GatePolicy(fail_on="none")))
    assert summary.existing == 1
    assert summary.new == 1
    assert result.findings[0].baseline in ("new", "existing")


def test_finalize_fail_on_new_requires_baseline():
    result = ScanResult(target="/src")
    result.findings = [make_sast()]
    with pytest.raises(ValueError):
        workflow.finalize(result, workflow.WorkflowOptions(
            fail_on_new=True, snippets=False))


def test_finalize_writes_baseline_out(tmp_path):
    out = tmp_path / "base.json"
    result = ScanResult(target="/src")
    result.findings = [make_sast(), make_sca()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", baseline_out=str(out), snippets=False,
        gate_policy=gates_module.GatePolicy(fail_on="none")))
    assert summary.baseline_out == str(out)
    assert json.loads(out.read_text())["count"] == 2


def test_finalize_suppression_and_expiry(tmp_path):
    result = ScanResult(target="/src")
    result.findings = [make_sast(), make_sca()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", snippets=False,
        suppression_entries=[{"rule": "java-sqli-*", "reason": "ok"},
                             {"rule": "other", "expires": "2000-01-01"}],
        gate_policy=gates_module.GatePolicy(fail_on="high")))
    assert summary.suppressed == 1
    assert summary.expired_suppressions == 1
    # only critical log4j remains -> gate fails
    assert summary.gate is not None and not summary.gate.passed


def test_finalize_severity_override_then_gate(tmp_path):
    result = ScanResult(target="/src")
    result.findings = [make_sast()]
    policy = gates_module.GatePolicy(fail_on="critical")
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", snippets=False,
        severity_overrides={"java-sqli-*": "critical"}, gate_policy=policy))
    assert summary.severity_overrides == 1
    assert not summary.gate.passed


def test_finalize_config_suppressions(tmp_path):
    config_path = tmp_path / "argus.toml"
    config_path.write_text('[[suppress]]\nrule = "java-*"\nreason = "config"\n')
    loaded = config_module.load(str(config_path))
    result = ScanResult(target="/src")
    result.findings = [make_sast()]
    summary = workflow.finalize(result, workflow.WorkflowOptions(
        root="/src", snippets=False, config=loaded,
        gate_policy=gates_module.GatePolicy(fail_on="high")))
    assert summary.suppressed == 1
    assert summary.gate.passed


def test_finalize_missing_baseline_raises(tmp_path):
    result = ScanResult(target="/src")
    with pytest.raises(FileNotFoundError):
        workflow.finalize(result, workflow.WorkflowOptions(
            root="/src", baseline=str(tmp_path / "absent.json"), snippets=False))
