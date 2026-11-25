"""OpenVEX export from scan reports."""

from __future__ import annotations

import json

import pytest

from argus import vex
from argus.cli import EXIT_OK, main


def sca(rule="CVE-2021-44228", version="2.14.1", fixed="2.17.0",
        suppressed=False, reason="") -> dict:
    finding = {
        "kind": "sca", "rule_id": rule, "severity": "critical",
        "package": {"name": "log4j-core", "version": version,
                    "fixed_version": fixed,
                    "purl": f"pkg:maven/org.apache/log4j-core@{version}"},
        "aliases": [rule],
    }
    if suppressed:
        finding["suppressed"] = True
        finding["suppression"] = {"reason": reason or "accepted risk"}
    return finding


def test_build_from_report_statuses():
    report = {"findings": [
        sca(),
        sca(rule="CVE-2", suppressed=True, reason="not reachable"),
        sca(rule="CVE-3", version="2.17.0"),
    ]}
    document = vex.build_from_report(report)
    assert document["@context"] == vex.OPENVEX_CONTEXT
    assert document["author"] == "argus"
    statuses = {statement["vulnerability"]["name"]: statement["status"]
                for statement in document["statements"]}
    assert statuses == {"CVE-2021-44228": "affected",
                        "CVE-2": "not_affected", "CVE-3": "fixed"}


def test_suppressed_statement_has_justification():
    document = vex.build_from_report({"findings": [
        sca(suppressed=True, reason="component not used")]})
    statement = document["statements"][0]
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert statement["impact_statement"] == "component not used"


def test_affected_statement_has_action():
    document = vex.build_from_report({"findings": [sca()]})
    statement = document["statements"][0]
    assert statement["action_statement"].startswith("Upgrade log4j-core")
    assert statement["vulnerability"]["aliases"] == ["CVE-2021-44228"]
    assert statement["products"][0]["identifiers"]["purl"].startswith("pkg:maven/")


def test_sast_findings_are_ignored():
    document = vex.build_from_report({"findings": [
        {"kind": "sast", "rule_id": "java-sqli"}]})
    assert document["statements"] == []


def test_counts():
    document = {"statements": [{"status": "affected"}, {"status": "affected"},
                               {"status": "fixed"}]}
    assert vex.counts(document) == {"affected": 2, "fixed": 1}


def test_render_is_json():
    payload = vex.render(vex.build_from_report({"findings": [sca()]}))
    parsed = json.loads(payload)
    assert parsed["version"] == 1


def test_cli_vex(tmp_path, capsys):
    report = tmp_path / "report.json"
    output = tmp_path / "vex.json"
    report.write_text(json.dumps({"findings": [sca(), sca(rule="CVE-2",
                                                         suppressed=True)]}))
    code = main(["vex", str(report), "-o", str(output), "-q"])
    assert code == EXIT_OK
    document = json.loads(output.read_text())
    assert len(document["statements"]) == 2
    assert {statement["status"] for statement in document["statements"]} == {
        "affected", "not_affected"}


def test_cli_vex_stdout(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [sca()]}))
    assert main(["vex", str(report), "-q"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["statements"]
