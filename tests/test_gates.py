"""Quality gates and package policies."""

from __future__ import annotations

import pytest

from argus import gates
from argus.models import Finding, Severity


def make(severity=Severity.HIGH, rule="r", package="", version="", cwe="",
         metadata=None) -> Finding:
    return Finding(
        rule_id=rule, title="issue", severity=severity, kind="sca" if package else "sast",
        engine="osv" if package else "argus-java", file="App.java",
        start_line=1, message="issue", package=package, version=version,
        cwe=cwe, metadata=metadata or {})


def test_default_policy_fails_on_high():
    result = gates.evaluate([make(Severity.HIGH)])
    assert not result.passed
    assert "at or above high" in result.violations[0]


def test_fail_on_none_passes():
    result = gates.evaluate([make(Severity.CRITICAL)],
                            gates.GatePolicy(fail_on="none"))
    assert result.passed


def test_suppressed_findings_ignored():
    finding = make(Severity.CRITICAL)
    finding.suppressed = True
    result = gates.evaluate([finding])
    assert result.passed
    assert result.considered == 0


def test_fail_on_new_ignores_existing():
    existing = make(Severity.CRITICAL)
    existing.baseline = "existing"
    result = gates.evaluate([existing], gates.GatePolicy(fail_on="high",
                                                         fail_on_new=True))
    assert result.passed
    assert result.new == 0


def test_fail_on_new_catches_new():
    new = make(Severity.CRITICAL)
    new.baseline = "new"
    result = gates.evaluate([new], gates.GatePolicy(fail_on="high",
                                                    fail_on_new=True))
    assert not result.passed
    assert result.new == 1


def test_max_total():
    findings = [make(Severity.LOW) for _ in range(3)]
    result = gates.evaluate(findings, gates.GatePolicy(fail_on="none", max_total=2))
    assert not result.passed
    assert "max_total=2" in result.violations[0]


def test_max_by_severity():
    findings = [make(Severity.CRITICAL), make(Severity.CRITICAL)]
    result = gates.evaluate(findings, gates.GatePolicy(
        fail_on="none", max_by_severity={"critical": 1}))
    assert not result.passed
    assert "max_by_severity.critical=1" in result.violations[0]


def test_deny_packages_glob():
    result = gates.evaluate(
        [make(package="log4j-core", version="2.14.1")],
        gates.GatePolicy(fail_on="none", deny_packages=("log4j-*",)))
    assert not result.passed
    assert "denied package log4j-core" in result.violations[0]


def test_deny_cwes():
    result = gates.evaluate(
        [make(cwe="CWE-502")],
        gates.GatePolicy(fail_on="none", deny_cwes=("CWE-502",)))
    assert not result.passed
    assert "CWE-502" in result.violations[0]


def test_max_cvss():
    result = gates.evaluate(
        [make(Severity.HIGH, metadata={"cvss_score": 9.8})],
        gates.GatePolicy(fail_on="none", max_cvss=9.0))
    assert not result.passed
    assert "CVSS 9.8" in result.violations[0]


def test_violations_deduplicated():
    findings = [make(package="log4j-core", version="2.14.1"),
                make(package="log4j-core", version="2.14.1")]
    result = gates.evaluate(findings, gates.GatePolicy(
        fail_on="none", deny_packages=("log4j-*",)))
    assert len(result.violations) == 1
    assert len(result.violations) == len(set(result.violations))


def test_from_mapping():
    policy = gates.GatePolicy.from_mapping({
        "fail_on": "critical", "fail_on_new": True, "max_total": "10",
        "max_by_severity": {"high": 2}, "deny_packages": "x",
        "deny_cwes": ["CWE-1"], "max_cvss": "7.5", "deny_licenses": ["GPL-3.0"],
    })
    assert policy.fail_on == "critical"
    assert policy.fail_on_new is True
    assert policy.max_total == 10
    assert policy.max_by_severity == {"high": 2}
    assert policy.deny_packages == ("x",)
    assert policy.deny_cwes == ("CWE-1",)
    assert policy.max_cvss == 7.5
    assert policy.deny_licenses == ("GPL-3.0",)


def test_from_mapping_base():
    base = gates.GatePolicy(fail_on="low", max_total=3)
    policy = gates.GatePolicy.from_mapping({"fail_on": "high"}, base=base)
    assert policy.fail_on == "high"
    assert policy.max_total == 3


def test_to_dict_roundtrip():
    policy = gates.GatePolicy(max_total=1, deny_packages=("a",))
    payload = policy.to_dict()
    assert payload["max_total"] == 1
    assert payload["deny_packages"] == ["a"]


def test_format_gate():
    passed = gates.evaluate([], gates.GatePolicy(fail_on="high"))
    assert gates.format_gate(passed).startswith("quality gate passed")
    failed = gates.evaluate([make(Severity.CRITICAL)])
    assert gates.format_gate(failed).startswith("quality gate failed")


def test_deny_licenses_on_findings():
    finding = make(package="copyleft", version="1.0")
    finding.licenses = ["GPL-3.0-only"]
    result = gates.evaluate([finding], gates.GatePolicy(
        fail_on="none", deny_licenses=("GPL-*",)))
    assert not result.passed
    assert "denied licence GPL-3.0-only" in result.violations[0]


def test_deny_licenses_covers_packages_without_findings():
    result = gates.evaluate([], gates.GatePolicy(
        fail_on="none", deny_licenses=("AGPL-3.0",)),
        packages={"pkg:npm/x@1.0.0": ["AGPL-3.0"]})
    assert not result.passed
    assert "pkg:npm/x@1.0.0" in result.violations[0]


def test_deny_licenses_passes_when_clean():
    finding = make(package="mit", version="1.0")
    finding.licenses = ["MIT"]
    result = gates.evaluate([finding], gates.GatePolicy(
        fail_on="none", deny_licenses=("GPL-*",)))
    assert result.passed
