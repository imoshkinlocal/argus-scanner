"""CLI surface: exit codes, formats and subcommand wiring."""

from __future__ import annotations

import json

import pytest

from argus.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

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

CLEAN = """\
import javax.servlet.http.*;

public class Clean extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = 1");
    }
}
"""


@pytest.fixture()
def vulnerable_file(tmp_path):
    path = tmp_path / "Vulnerable.java"
    path.write_text(VULNERABLE)
    return str(path)


@pytest.fixture()
def clean_file(tmp_path):
    path = tmp_path / "Clean.java"
    path.write_text(CLEAN)
    return str(path)


# --------------------------------------------------------------------------- sast

def test_sast_json_and_fail_on(vulnerable_file, capsys):
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert payload["summary"]["total"] >= 1
    assert payload["findings"][0]["rule_id"] == "java-sqli-jdbc"
    assert payload["findings"][0]["location"]["file"] == "Vulnerable.java"


def test_fail_on_none_suppresses_exit_code(vulnerable_file, capsys):
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "text",
                 "--fail-on", "none", "-q"])
    output = capsys.readouterr().out
    assert code == EXIT_OK
    assert "java-sqli-jdbc" in output


def test_clean_file_exits_zero(clean_file, capsys):
    code = main(["sast", clean_file, "--engine", "java", "-f", "json",
                 "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["summary"]["total"] == 0


def test_min_severity_filters_findings(vulnerable_file, capsys):
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--min-severity", "critical", "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total"] == 0
    assert code == EXIT_OK


def test_sast_sarif_output(vulnerable_file, capsys):
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "sarif",
                 "--fail-on", "none", "-q"])
    sarif = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "argus"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "java-sqli-jdbc"


def test_sast_writes_report_to_file(vulnerable_file, tmp_path):
    output = tmp_path / "nested" / "report.json"
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "-o", str(output), "--fail-on", "none", "-q"])
    assert code == EXIT_OK
    assert json.loads(output.read_text())["summary"]["total"] >= 1


def test_sast_writes_markdown_summary_alongside_json(vulnerable_file, tmp_path):
    output = tmp_path / "report.json"
    summary = tmp_path / "report.md"
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "-o", str(output), "--summary", str(summary), "--fail-on", "none", "-q"])
    assert code == EXIT_OK
    payload = json.loads(output.read_text())
    assert payload["summary"]["status"] == "findings"
    assert payload["summary"]["by_engine"] == {"argus-java": 1}
    assert payload["summary"]["top_rules"][0]["rule_id"] == "java-sqli-jdbc"
    markdown = summary.read_text()
    assert markdown.startswith("# argus report")
    assert "* Status: **findings**" in markdown
    assert "`java-sqli-jdbc`" in markdown


def test_sast_markdown_format(vulnerable_file, capsys):
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "md",
                 "--fail-on", "none", "-q"])
    output = capsys.readouterr().out
    assert code == EXIT_OK
    assert output.startswith("# argus report")
    assert "## SAST findings" in output


def test_missing_target_is_exit_2(tmp_path, capsys):
    code = main(["sast", str(tmp_path / "nope"), "--engine", "java", "-q"])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "does not exist" in captured.err


def test_scan_with_no_sast_still_runs(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    code = main(["scan", str(tmp_path / "empty"), "--no-sast", "--no-sca",
                 "-f", "json", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["findings"] == []


# --------------------------------------------------------------------------- informational subcommands

def test_version_command(capsys):
    assert main(["version"]) == EXIT_OK
    assert "argus " in capsys.readouterr().out


def test_version_matches_pyproject():
    """The runtime constant and the packaged version must not drift apart."""
    import re
    from pathlib import Path

    from argus import __version__

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    match = re.search(r'^version = "([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
    assert match is not None
    assert match.group(1) == __version__


def test_rules_list_json(capsys):
    code = main(["rules", "list", "-f", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["semgrep"], "bundled Semgrep rules must be discoverable"
    assert payload["java"], "Java engine catalog must be discoverable"
    assert all(rule["id"] for rule in payload["semgrep"])


def test_rules_list_text(capsys):
    assert main(["rules", "list"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "# Semgrep rules" in output
    assert "# Java engine rules" in output


def test_db_status_json(capsys):
    code = main(["db", "status"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["ecosystems"]
    assert {"ecosystem", "archive", "size_bytes", "modified"} <= set(payload["ecosystems"][0])


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    assert "usage: argus" in capsys.readouterr().out


# --------------------------------------------------------------------------- workflow: config, baseline, suppressions, gates

def test_config_defaults_applied(vulnerable_file, tmp_path, capsys):
    config = tmp_path / "argus.toml"
    config.write_text('[scan]\nmin_severity = "critical"\n')
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--config", str(config), "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["summary"]["total"] == 0


def test_cli_flag_overrides_config(vulnerable_file, tmp_path, capsys):
    config = tmp_path / "argus.toml"
    config.write_text('[scan]\nmin_severity = "critical"\n')
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--config", str(config), "--min-severity", "low",
                 "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert payload["summary"]["total"] >= 1


def test_invalid_config_is_exit_2(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    config = tmp_path / "argus.json"
    config.write_text("{broken")
    code = main(["scan", str(tmp_path / "empty"), "--config", str(config),
                 "--no-sast", "--no-sca", "-q"])
    assert code == EXIT_ERROR
    assert "invalid JSON" in capsys.readouterr().err


def test_suppression_hides_finding_from_exit_code(vulnerable_file, tmp_path, capsys):
    ignore = tmp_path / ".argusignore"
    ignore.write_text("rule:java-sqli-*  # accepted risk\n")
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--ignore", str(ignore), "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["summary"]["suppressed"] == 1
    assert payload["summary"]["total"] == 0
    finding = payload["findings"][0]
    assert finding["suppressed"] is True
    assert finding["suppression"]["reason"] == "accepted risk"


def test_expired_suppression_warns_and_still_fails(vulnerable_file, tmp_path, capsys):
    ignore = tmp_path / "suppress.json"
    ignore.write_text(json.dumps({"suppress": [
        {"rule": "java-sqli-*", "reason": "old", "expires": "2000-01-01"}]}))
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--ignore", str(ignore), "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["suppressed"] == 0
    assert payload["stats"]["workflow"]["expired_suppressions"] == 1


def test_baseline_out_then_fail_on_new(vulnerable_file, tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    first = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                  "--baseline-out", str(baseline), "--fail-on", "high", "-q"])
    capsys.readouterr()
    assert first == EXIT_FINDINGS
    assert json.loads(baseline.read_text())["count"] >= 1

    second = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                   "--baseline", str(baseline), "--fail-on-new",
                   "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert second == EXIT_OK
    assert payload["summary"]["new"] == 0
    assert payload["findings"][0]["baseline"] == "existing"


def test_fail_on_new_without_baseline_is_exit_2(vulnerable_file, capsys):
    code = main(["sast", vulnerable_file, "--engine", "java", "--fail-on-new", "-q"])
    assert code == EXIT_ERROR
    assert "requires a baseline" in capsys.readouterr().err


def test_quality_gate_max_total(vulnerable_file, tmp_path, capsys):
    config = tmp_path / "argus.toml"
    config.write_text("[gates]\nmax_total = 0\nfail_on = \"none\"\n")
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--config", str(config), "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert any("max_total=0" in violation
               for violation in payload["stats"]["gate"]["violations"])


def test_quality_gate_deny_cwes(vulnerable_file, tmp_path, capsys):
    config = tmp_path / "argus.toml"
    config.write_text('[gates]\ndeny_cwes = ["CWE-89"]\nfail_on = "none"\n')
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--config", str(config), "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert any("CWE-89" in violation
               for violation in payload["stats"]["gate"]["violations"])


def test_severity_override_from_config(vulnerable_file, tmp_path, capsys):
    config = tmp_path / "argus.toml"
    config.write_text('[severity]\n"java-sqli-*" = "low"\n')
    code = main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
                 "--config", str(config), "--fail-on", "high", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["findings"][0]["severity"] == "low"


def test_diff_command(vulnerable_file, clean_file, tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
          "-o", str(old), "--fail-on", "none", "-q"])
    main(["sast", clean_file, "--engine", "java", "-f", "json",
          "-o", str(new), "--fail-on", "none", "-q"])
    capsys.readouterr()
    code = main(["diff", str(old), str(new), "-q"])
    output = capsys.readouterr().out
    assert code == EXIT_OK
    assert "FIXED (1)" in output


def test_diff_command_reports_regressions(clean_file, vulnerable_file, tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    main(["sast", clean_file, "--engine", "java", "-f", "json",
          "-o", str(old), "--fail-on", "none", "-q"])
    main(["sast", vulnerable_file, "--engine", "java", "-f", "json",
          "-o", str(new), "--fail-on", "none", "-q"])
    capsys.readouterr()
    code = main(["diff", str(old), str(new), "--fail-on", "high", "-q"])
    assert code == EXIT_FINDINGS


def test_diff_command_json(tmp_path, capsys):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"findings": []}))
    new.write_text(json.dumps({"findings": []}))
    code = main(["diff", str(old), str(new), "-f", "json", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["counts"]["new"] == 0
