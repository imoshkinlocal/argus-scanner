"""Suppression matching, expiry and file loading."""

from __future__ import annotations

import datetime
import json

import pytest

from argus import suppress
from argus.models import Finding, Severity


def make_finding(rule="java-sqli-jdbc", file="src/App.java", cwe="CWE-89",
                 package="", version="", message="unsafe query") -> Finding:
    return Finding(
        rule_id=rule, title=message, severity=Severity.HIGH, kind="sast",
        engine="argus-java", file=file, start_line=10, message=message,
        cwe=cwe, package=package, version=version)


def test_matches_by_rule_glob():
    entry = suppress.Suppression(rule="java-sqli-*")
    assert entry.matches(make_finding().to_dict())
    assert not entry.matches(make_finding(rule="java-xss").to_dict())


def test_matches_by_file_glob():
    entry = suppress.Suppression(file="src/legacy/*")
    assert entry.matches(make_finding(file="src/legacy/Old.java").to_dict())
    assert not entry.matches(make_finding(file="src/new/New.java").to_dict())


def test_matches_requires_all_criteria():
    entry = suppress.Suppression(rule="java-sqli-*", file="src/legacy/*")
    assert not entry.matches(make_finding(file="src/App.java").to_dict())


def test_matches_by_cwe():
    entry = suppress.Suppression(cwe="CWE-89")
    assert entry.matches(make_finding().to_dict())
    assert not entry.matches(make_finding(cwe="CWE-79").to_dict())


def test_matches_by_package():
    entry = suppress.Suppression(package="log4j-core@2.14.1")
    finding = make_finding(rule="CVE-2021-44228", package="log4j-core",
                           version="2.14.1")
    assert entry.matches(finding.to_dict())
    assert not entry.matches(make_finding(package="log4j-core",
                                          version="2.17.0").to_dict())


def test_empty_entry_never_matches():
    entry = suppress.Suppression()
    assert not entry.has_criteria()
    assert not entry.matches(make_finding().to_dict())


def test_expiry():
    expired = suppress.Suppression(rule="*", expires="2000-01-01")
    future = suppress.Suppression(rule="*", expires="2099-01-01")
    finding = make_finding().to_dict()
    assert expired.is_expired()
    assert not expired.matches(finding)
    assert not future.is_expired()
    assert future.matches(finding)


def test_parse_date_variants():
    assert suppress.parse_date("2024-05-01") == datetime.date(2024, 5, 1)
    assert suppress.parse_date("2024-05-01T10:00:00Z") == datetime.date(2024, 5, 1)
    assert suppress.parse_date("") is None
    assert suppress.parse_date("nonsense") is None


def test_from_line_forms():
    assert suppress.Suppression.from_line("rule:java-*").rule == "java-*"
    assert suppress.Suppression.from_line("file:src/*").file == "src/*"
    assert suppress.Suppression.from_line("cwe:CWE-79").cwe == "CWE-79"
    assert suppress.Suppression.from_line("package:lodash@*").package == "lodash@*"
    assert suppress.Suppression.from_line("CWE-89").cwe == "CWE-89"
    assert suppress.Suppression.from_line("java-sqli-*").rule == "java-sqli-*"
    line = suppress.Suppression.from_line("rule:x  # accepted risk")
    assert line.reason == "accepted risk"
    assert suppress.Suppression.from_line("# comment") is None


def test_load_argusignore(tmp_path):
    path = tmp_path / ".argusignore"
    path.write_text("# comment\nrule:java-sqli-*\nfile:legacy/*\n")
    entries = suppress.load_file(str(path))
    assert len(entries) == 2
    assert entries[0].rule == "java-sqli-*"


def test_load_json(tmp_path):
    path = tmp_path / "suppress.json"
    path.write_text(json.dumps({"suppress": [
        {"rule": "x", "reason": "ok", "expires": "2099-01-01"}]}))
    entries = suppress.load_file(str(path))
    assert entries[0].reason == "ok"


def test_load_toml(tmp_path):
    path = tmp_path / "suppress.toml"
    path.write_text('[[suppress]]\nrule = "java-*"\nreason = "ok"\n')
    entries = suppress.load_file(str(path))
    assert entries[0].rule == "java-*"


def test_load_merges_and_deduplicates(tmp_path):
    path = tmp_path / ".argusignore"
    path.write_text("rule:java-sqli-*\n")
    entries = suppress.load([str(path)], entries=[{"rule": "java-sqli-*"},
                                                  {"rule": "java-xss"}])
    assert [entry.rule for entry in entries] == ["java-sqli-*", "java-xss"]


def test_apply_marks_and_counts():
    findings = [make_finding(), make_finding(rule="java-xss", cwe="CWE-79")]
    entries = [suppress.Suppression(rule="java-sqli-*", reason="accepted")]
    result = suppress.apply(findings, entries)
    assert result.applied == 1
    assert findings[0].suppressed is True
    assert findings[0].suppression["reason"] == "accepted"
    assert findings[1].suppressed is False
    assert result.to_dict()["suppressed"] == 1


def test_apply_reports_expired():
    findings = [make_finding()]
    entries = [suppress.Suppression(rule="java-sqli-*", expires="2000-01-01")]
    result = suppress.apply(findings, entries)
    assert result.applied == 0
    assert len(result.expired) == 1
    assert findings[0].suppressed is False
