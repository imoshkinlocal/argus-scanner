"""Semgrep fix suggestions: captured, rendered, never applied.

A rule's ``fix`` is treated as a proposal.  These tests pin both halves of that
contract: the engine and the reports surface the replacement, while the source
file and the finding's severity stay exactly as they were.
"""

from __future__ import annotations

import os

import pytest

from argus.models import Finding, ScanResult, Severity
from argus.output import json_report, markdown_report, sarif_report, text_report
from argus.sast import semgrep_engine

BUNDLE = semgrep_engine.bundle_root()
SEMGREP = semgrep_engine.find_semgrep()
requires_semgrep = pytest.mark.skipif(SEMGREP is None, reason="semgrep is not installed")


def suggestion_finding(**kwargs) -> Finding:
    base = dict(
        rule_id="python-flask-debug",
        title="The Flask debugger must not be enabled in production",
        severity=Severity.MEDIUM,
        kind="sast",
        engine="semgrep",
        file="app.py",
        start_line=2,
        start_col=5,
        end_line=2,
        end_col=34,
        message="The Flask debugger exposes an interactive console.",
        cwe="CWE-489",
        confidence="medium",
        suggested_fix="app.run(debug=False)",
    )
    base.update(kwargs)
    return Finding(**base)


def result_with(finding: Finding) -> ScanResult:
    return ScanResult(target="/tmp/project", findings=[finding], engines=["semgrep"])


def test_json_report_exposes_the_suggestion():
    payload = json_report(result_with(suggestion_finding()))
    finding = payload["findings"][0]
    assert finding["suggested_fix"] == "app.run(debug=False)"
    assert finding["severity"] == "medium"


def test_sarif_fix_is_a_replacement_proposal():
    payload = sarif_report(result_with(suggestion_finding()), "/tmp/project")
    result = payload["runs"][0]["results"][0]
    assert result["level"] == "warning"
    replacement = result["fixes"][0]["artifactChanges"][0]["replacements"][0]
    assert replacement["insertedContent"]["text"] == "app.run(debug=False)"
    assert replacement["deletedRegion"] == {
        "startLine": 2, "startColumn": 5, "endLine": 2, "endColumn": 34,
    }
    assert "review" in result["fixes"][0]["description"]["text"].lower()


def test_text_and_markdown_mark_the_fix_as_a_suggestion():
    result = result_with(suggestion_finding())
    text = text_report(result)
    assert "suggested fix (not applied)" in text
    assert "app.run(debug=False)" in text

    markdown = markdown_report(result)
    assert "## Suggested fixes" in markdown
    assert "never modifies the scanned sources" in markdown
    assert "app.run(debug=False)" in markdown


def test_suggestion_does_not_change_severity():
    high = suggestion_finding(severity=Severity.HIGH)
    assert high.to_dict()["severity"] == "high"
    assert high.to_dict()["suggested_fix"] == "app.run(debug=False)"


@requires_semgrep
def test_engine_captures_the_fix_and_keeps_the_source(tmp_path):
    path = tmp_path / "app.py"
    source = "def f(app):\n    app.run(debug=True)\n"
    path.write_text(source)

    findings, errors = semgrep_engine.run_semgrep(
        str(path), rules=os.path.join(BUNDLE, "python"), jobs=1, root=str(tmp_path))

    assert not errors
    finding = next(f for f in findings if f.rule_id == "python-flask-debug")
    assert finding.suggested_fix == "app.run(debug=False)"
    # WARNING on the Semgrep side must still map to MEDIUM in argus.
    assert finding.severity is Severity.MEDIUM
    # The suggestion is never written: the scan is read-only.
    assert path.read_text() == source


@requires_semgrep
def test_error_rule_keeps_high_severity_and_offers_a_fix(tmp_path):
    path = tmp_path / "app.go"
    path.write_text(
        'package main\n\nimport "crypto/tls"\n\n'
        "func f() {\n"
        "\tc := tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}\n"
        "\t_ = c\n"
        "}\n"
    )

    findings, errors = semgrep_engine.run_semgrep(
        str(path), rules=os.path.join(BUNDLE, "go"), jobs=1, root=str(tmp_path))

    assert not errors
    finding = next(f for f in findings
                   if f.rule_id == "go-tls-insecure-skip-verify")
    assert finding.severity is Severity.HIGH
    assert "InsecureSkipVerify: false" in finding.suggested_fix
    assert "InsecureSkipVerify: true" not in finding.suggested_fix
