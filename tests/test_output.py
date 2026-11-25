"""Report writers and the shared finding model."""

from __future__ import annotations

import json

import pytest

from argus.models import (
    Finding,
    ScanError,
    ScanResult,
    Severity,
    dedupe,
    filter_findings,
    parse_severity,
    severity_from_cvss,
)
from argus.output import json_report, markdown_report, render, sarif_report, text_report


def sast_finding(**kwargs) -> Finding:
    base = dict(
        rule_id="java-sqli-jdbc",
        title="SQL injection",
        severity=Severity.HIGH,
        kind="sast",
        engine="argus-java",
        file="src/App.java",
        start_line=42,
        start_col=9,
        end_line=42,
        end_col=55,
        message="Untrusted input reaches executeQuery",
        cwe="CWE-89",
        confidence="high",
    )
    base.update(kwargs)
    return Finding(**base)


def sca_finding(**kwargs) -> Finding:
    base = dict(
        rule_id="CVE-2021-44228",
        title="Remote code execution in Log4j",
        severity=Severity.CRITICAL,
        kind="sca",
        engine="osv",
        package="org.apache.logging.log4j:log4j-core",
        version="2.14.1",
        fixed_version="2.15.0",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        aliases=["GHSA-jfh8-c2jp-5v3q"],
        confidence="high",
    )
    base.update(kwargs)
    return Finding(**base)


@pytest.fixture()
def sample_result():
    result = ScanResult(target="/tmp/project", engines=["argus-java", "osv"])
    result.findings = [sast_finding(), sca_finding()]
    result.errors = [ScanError(scanner="sca", message="manifest not found")]
    result.stats = {"files_total": 3}
    return result


# --------------------------------------------------------------------------- JSON

def test_json_report_shape(sample_result):
    payload = json_report(sample_result)
    assert payload["tool"]["name"] == "argus"
    assert payload["tool"]["engines"] == ["argus-java", "osv"]
    assert payload["target"] == "/tmp/project"
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["by_kind"] == {"sast": 1, "sca": 1}
    assert payload["summary"]["max_severity"] == "critical"
    assert payload["summary"]["errors"] == 1
    assert len(payload["findings"]) == 2
    assert payload["errors"][0]["scanner"] == "sca"
    assert payload["stats"] == {"files_total": 3}


def test_json_finding_contains_location_and_package(sample_result):
    payload = json_report(sample_result)
    sast, sca = payload["findings"]
    assert sast["location"]["file"] == "src/App.java"
    assert sast["location"]["start_line"] == 42
    assert "package" not in sast
    assert sca["package"]["name"].endswith("log4j-core")
    assert sca["package"]["fixed_version"] == "2.15.0"


def test_render_json_is_valid_json(sample_result):
    text = render(sample_result, "json")
    assert json.loads(text)["summary"]["total"] == 2


def test_render_unknown_format():
    with pytest.raises(ValueError):
        render(ScanResult(target="."), "html")


# --------------------------------------------------------------------------- SARIF

def test_sarif_report_structure(sample_result):
    sarif = sarif_report(sample_result, "/tmp/project")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "argus"
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file://")


def test_sarif_rules_are_deduplicated(sample_result):
    sample_result.findings.append(sast_finding(start_line=77))
    sarif = sarif_report(sample_result, "/tmp/project")
    run = sarif["runs"][0]
    ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert ids.count("java-sqli-jdbc") == 1
    indices = [result["ruleIndex"] for result in run["results"] if result["ruleId"] == "java-sqli-jdbc"]
    assert indices == [0, 0]


def test_sarif_regions_and_levels(sample_result):
    sarif = sarif_report(sample_result, "/tmp/project")
    results = sarif["runs"][0]["results"]
    sast = next(item for item in results if item["ruleId"] == "java-sqli-jdbc")
    region = sast["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42
    assert region["startColumn"] == 9
    assert sast["level"] == "error"
    assert sast["properties"]["cwe"] == "CWE-89"
    assert sast["partialFingerprints"]["argus/v1"] == sast_finding().fingerprint


def test_sarif_sca_properties(sample_result):
    sarif = sarif_report(sample_result, "/tmp/project")
    item = next(r for r in sarif["runs"][0]["results"] if r["properties"]["kind"] == "sca")
    assert item["properties"]["package"].endswith("log4j-core")
    assert item["properties"]["fixed_version"] == "2.15.0"
    assert item["properties"]["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]


def test_sarif_notifications_record_errors(sample_result):
    sarif = sarif_report(sample_result, "/tmp/project")
    notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notifications[0]["message"]["text"] == "sca: manifest not found"


def test_sarif_escapes_windows_paths_in_base_uri(sample_result):
    sarif = sarif_report(sample_result, "/tmp/project")
    assert sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"] == "file:///tmp/project/"


# --------------------------------------------------------------------------- text

def test_text_report_summary(sample_result):
    text = text_report(sample_result)
    assert "java-sqli-jdbc" in text
    assert "package: org.apache.logging.log4j:log4j-core 2.14.1 (fixed in 2.15.0)" in text
    assert "at: src/App.java:42" in text
    assert "total: 2" in text
    assert "warning [sca] manifest not found" in text


def test_text_report_truncates(sample_result):
    sample_result.findings = [sast_finding(start_line=line) for line in range(1, 6)]
    text = text_report(sample_result, max_items=2)
    assert "3 more findings" in text


def test_text_report_color_codes(sample_result):
    assert "\033[1;31m" in text_report(sample_result, color=True)
    assert "\033[" not in text_report(sample_result, color=False)


# --------------------------------------------------------------------------- markdown

def test_markdown_report_machine_fields_and_tables(sample_result):
    markdown = markdown_report(sample_result)
    assert markdown.startswith("# argus report")
    assert "* Status: **findings**" in markdown
    assert "| **total** | **2** |" in markdown
    assert "| SAST findings | 1 |" in markdown
    assert "| SCA findings | 1 |" in markdown
    # rules table and per-kind finding tables
    assert "| `java-sqli-jdbc` | sast | high | 1 |" in markdown
    assert "| `CVE-2021-44228` | sca | critical | 1 |" in markdown
    assert "`src/App.java:42`" in markdown
    assert "org.apache.logging.log4j:log4j-core" in markdown
    assert "**sca**: manifest not found" in markdown


def test_markdown_report_empty_result():
    markdown = markdown_report(ScanResult(target="."))
    assert "No findings." in markdown
    assert "* Status: **clean**" in markdown


def test_markdown_report_escapes_pipes():
    finding = sast_finding(message="match | pipe")
    result = ScanResult(target=".")
    result.findings = [finding]
    assert "match \\| pipe" in markdown_report(result)


def test_render_markdown_aliases(sample_result):
    assert render(sample_result, "md") == render(sample_result, "markdown")
    assert render(sample_result, "markdown").startswith("# argus report")


# --------------------------------------------------------------------------- summary helpers

def test_summary_status_and_top_rules(sample_result):
    summary = sample_result.summary()
    assert summary["status"] == "findings"
    assert summary["by_engine"] == {"argus-java": 1, "osv": 1}
    assert summary["top_rules"][0] == {
        "rule_id": "CVE-2021-44228", "kind": "sca", "severity": "critical", "count": 1,
    }
    assert {entry["rule_id"] for entry in summary["top_rules"]} == {
        "java-sqli-jdbc", "CVE-2021-44228",
    }


def test_summary_status_error_and_clean():
    error_only = ScanResult(target=".")
    error_only.errors = [ScanError(scanner="sca", message="boom")]
    assert error_only.summary()["status"] == "error"
    assert ScanResult(target=".").summary()["status"] == "clean"


def test_summary_top_rules_are_ranked_and_capped():
    result = ScanResult(target=".")
    result.findings = [sast_finding(rule_id=f"rule-{index}") for index in range(15)]
    result.findings.append(sast_finding(rule_id="rule-0", severity=Severity.MEDIUM))
    result.findings.append(sast_finding(rule_id="hot", severity=Severity.LOW))
    result.findings.append(sast_finding(rule_id="hot", severity=Severity.LOW))
    result.findings.append(sast_finding(rule_id="hot", severity=Severity.LOW))
    summary = result.summary()
    assert len(summary["top_rules"]) == 10
    assert summary["top_rules"][0]["rule_id"] == "hot"
    assert summary["top_rules"][0]["count"] == 3


# --------------------------------------------------------------------------- model helpers

def test_dedupe_keeps_highest_confidence():
    low = sast_finding(confidence="low")
    high = sast_finding(confidence="high")
    deduped = dedupe([low, high])
    assert len(deduped) == 1
    assert deduped[0].confidence == "high"


def test_dedupe_sca_key_includes_package_and_version():
    one = sca_finding()
    two = sca_finding(version="2.17.0", rule_id="CVE-2021-45046")
    assert len(dedupe([one, two])) == 2


def test_filter_findings_by_severity_and_kind(sample_result):
    high_only = filter_findings(sample_result.findings, Severity.HIGH)
    assert {f.kind for f in high_only} == {"sast", "sca"}
    critical_only = filter_findings(sample_result.findings, Severity.CRITICAL)
    assert [f.kind for f in critical_only] == ["sca"]
    sast_only = filter_findings(sample_result.findings, include_kinds=["sast"])
    assert [f.rule_id for f in sast_only] == ["java-sqli-jdbc"]


def test_severity_parsing_aliases():
    assert parse_severity("ERROR") is Severity.HIGH
    assert parse_severity("moderate") is Severity.MEDIUM
    assert parse_severity("") is Severity.UNKNOWN
    assert parse_severity(9.8) is Severity.CRITICAL
    assert severity_from_cvss(0.0) is Severity.INFO
    assert severity_from_cvss(5.5) is Severity.MEDIUM
    assert severity_from_cvss(None) is Severity.UNKNOWN


def test_finding_fingerprint_is_stable():
    assert sast_finding().fingerprint == sast_finding().fingerprint
    assert sast_finding().fingerprint != sast_finding(start_line=43).fingerprint
