"""GUI helpers that work without opening a display."""

from __future__ import annotations

import sys

import pytest

pytest.importorskip("tkinter")

from argus import gui  # noqa: E402


def test_scan_command_defaults():
    command = gui.build_scan_command("/src", "/tmp/report.json")
    assert command[:4] == [sys.executable, "-m", "argus.cli", "scan"]
    assert "/src" in command
    assert command[command.index("-f") + 1] == "json"
    assert command[command.index("-o") + 1] == "/tmp/report.json"
    assert "--no-sast" not in command and "--no-sca" not in command
    assert "--include-dev" not in command and "--offline" not in command


def test_scan_command_flags_and_summary():
    command = gui.build_scan_command(
        "/src", "/tmp/r.json", "/tmp/r.md", sast=False, sca=True,
        include_dev=True, offline=True, fail_on="critical", range_policy="skip",
        excludes=("tests", "*/vendor/*"))
    assert command[command.index("--fail-on") + 1] == "critical"
    assert command[command.index("--range-policy") + 1] == "skip"
    assert command[command.index("--summary") + 1] == "/tmp/r.md"
    assert "--no-sast" in command and "--no-sca" not in command
    assert "--include-dev" in command and "--offline" in command
    assert command.count("--exclude") == 2
    assert command[command.index("--exclude") + 1] == "tests"


def test_format_summary_lists_key_numbers():
    report = {"summary": {
        "status": "findings", "total": 3, "max_severity": "critical",
        "by_severity": {"critical": 1, "high": 2}, "by_kind": {"sast": 1, "sca": 2},
        "by_engine": {"argus-java": 1, "osv": 2}, "by_ecosystem": {"Maven": 2},
        "packages": 7, "errors": 1,
        "top_rules": [{"rule_id": "java-sqli-jdbc", "count": 2}],
    }}
    text = gui.format_summary(report)
    assert "Статус: findings" in text
    assert "Находок: 3" in text
    assert "critical 1, high 2" in text
    assert "SAST 1, SCA 2" in text
    assert "Пакетов в инвентаре: 7" in text
    assert "java-sqli-jdbc ×2" in text


def test_format_summary_empty_report():
    text = gui.format_summary({})
    assert "Статус: неизвестно" in text
    assert "Находок: 0" in text


def test_finding_row_for_sast_and_sca():
    sast = {"severity": "high", "kind": "sast", "rule_id": "java-sqli-jdbc",
            "engine": "argus-java", "message": "unsafe query",
            "location": {"file": "src/App.java", "start_line": 42}}
    assert gui.finding_row(sast) == ("high", "sast", "java-sqli-jdbc", "",
                                     "src/App.java:42", "argus-java", "",
                                     "unsafe query")
    sca = {"severity": "critical", "kind": "sca", "rule_id": "CVE-2021-44228",
           "engine": "osv", "title": "RCE in Log4j", "cwe": "CWE-502",
           "package": {"name": "log4j-core", "version": "2.14.1",
                       "direct": False, "depth": 2}}
    assert gui.finding_row(sca)[4] == "log4j-core 2.14.1"
    assert gui.finding_row(sca)[6] == "transitive · d2"
    assert gui.finding_row(sca)[7] == "RCE in Log4j"
    assert gui.finding_row(sca)[3] == "CWE-502"


def test_dependency_label_for_sca_and_sast():
    assert gui.dependency_label({"kind": "sca", "package": {"direct": True,
                                                            "depth": 0}}) == "direct · d0"
    assert gui.dependency_label({"kind": "sca", "package": {"direct": False,
                                                            "depth": 3}}) == "transitive · d3"
    assert gui.dependency_label({"kind": "sca", "package": {}}) == "unknown"
    assert gui.dependency_label({"kind": "sast"}) == ""


def test_format_finding_shows_dependency_path_and_json():
    finding = {
        "severity": "high", "kind": "sca", "rule_id": "CVE-2024-0001",
        "title": "bad b", "message": "b is affected", "cwe": "CWE-79",
        "package": {"name": "b", "version": "2.0.0", "fixed_version": "2.0.1",
                    "direct": False, "depth": 1, "purl": "pkg:npm/b@2.0.0"},
    }
    text = gui.format_finding(finding, "a 1.0.0 → b 2.0.0")
    assert "HIGH  ·  CVE-2024-0001" in text
    assert "Пакет: b 2.0.0" in text
    assert "transitive" in text and "глубина 1" in text
    assert "Путь: a 1.0.0 → b 2.0.0" in text
    assert "CWE-79 — Межсайтовый скриптинг (XSS)" in text
    assert "cwe.mitre.org/data/definitions/79.html" in text
    assert "JSON:" in text


def test_format_finding_for_sast_includes_location():
    finding = {
        "severity": "medium", "kind": "sast", "rule_id": "java-xss",
        "message": "unsafe writer", "location": {"file": "src/App.java",
                                                  "start_line": 7},
    }
    text = gui.format_finding(finding)
    assert "Место: src/App.java:7" in text
    assert "unsafe writer" in text



def test_help_mentions_core_sections():
    for heading in ("ЧТО ПРОВЕРЯЕТ", "КАК ПОЛЬЗОВАТЬСЯ", "ОПЦИИ",
                    "ВЫХОДНЫЕ ДАННЫЕ", "ОГРАНИЧЕНИЯ", "ВКЛАДКА «CWE»"):
        assert heading in gui.HELP_TEXT


def test_format_cwe_entry_lists_mitigations_and_link():
    entry = gui.cwe_catalog.lookup("CWE-89")
    text = gui.format_cwe_entry(entry, count=3)
    assert "CWE-89  ·  Инъекции" in text
    assert "Инъекция SQL" in text
    assert "Последствия:" in text and "Меры защиты:" in text
    assert "В текущем отчёте: 3" in text
    assert "https://cwe.mitre.org/data/definitions/89.html" in text


def _graph_report(resolved=True):
    nodes = [
        {"ref": "pkg:npm/a@1.0.0", "name": "a", "version": "1.0.0",
         "ecosystem": "npm", "direct": True, "depth": 0},
        {"ref": "pkg:npm/b@2.0.0", "name": "b", "version": "2.0.0",
         "ecosystem": "npm", "direct": False if resolved else None,
         "depth": 1 if resolved else None},
    ]
    return {
        "stats": {"dependency_graph": {
            "resolved": resolved,
            "roots": ["pkg:npm/a@1.0.0"] if resolved else [],
            "nodes": nodes,
            "dependencies": ([{"ref": "pkg:npm/a@1.0.0",
                               "dependsOn": ["pkg:npm/b@2.0.0"]}]
                             if resolved else []),
        }},
        "findings": [{"severity": "high", "package": {"purl": "pkg:npm/b@2.0.0"}}],
    }


def test_dependency_rows_builds_hierarchy_with_severity():
    rows = gui.dependency_rows(_graph_report())
    assert [row["name"] for row in rows] == ["a", "b"]
    assert rows[0]["parent"] == "" and rows[1]["parent"] == "pkg:npm/a@1.0.0"
    assert rows[1]["depth"] == 1
    assert rows[1]["severity"] == "high"
    assert rows[0]["cycle"] is False


def test_dependency_rows_falls_back_to_flat_list_when_unresolved():
    rows = gui.dependency_rows(_graph_report(resolved=False))
    assert [row["name"] for row in rows] == ["a", "b"]
    assert all(row["parent"] == "" for row in rows)
    assert rows[1]["direct"] is None
    assert rows[1]["depth"] is None


def test_dependency_rows_empty_report():
    assert gui.dependency_rows({}) == []
    assert gui.dependency_rows({"stats": {}}) == []


def _sort_report():
    nodes = [
        {"ref": "pkg:npm/a@1.0.0", "name": "a", "version": "1.0.0",
         "ecosystem": "npm", "direct": True, "depth": 0},
        {"ref": "pkg:npm/b@2.0.0", "name": "b", "version": "2.0.0",
         "ecosystem": "npm", "direct": False, "depth": 1},
        {"ref": "pkg:npm/c@3.0.0", "name": "c", "version": "3.0.0",
         "ecosystem": "npm", "direct": False, "depth": 1},
        {"ref": "pkg:npm/z@9.0.0", "name": "z", "version": "9.0.0",
         "ecosystem": "npm", "direct": True, "depth": 0},
    ]
    return {
        "stats": {"dependency_graph": {
            "resolved": True,
            "roots": ["pkg:npm/a@1.0.0", "pkg:npm/z@9.0.0"],
            "nodes": nodes,
            "dependencies": [{"ref": "pkg:npm/a@1.0.0",
                              "dependsOn": ["pkg:npm/c@3.0.0", "pkg:npm/b@2.0.0"]}],
        }},
        "findings": [
            {"severity": "medium", "package": {"purl": "pkg:npm/a@1.0.0"}},
            {"severity": "high", "package": {"purl": "pkg:npm/b@2.0.0"}},
            {"severity": "low", "package": {"purl": "pkg:npm/c@3.0.0"}},
            {"severity": "critical", "package": {"purl": "pkg:npm/z@9.0.0"}},
        ],
    }


def test_dependency_rows_default_order_keeps_graph_roots_and_sorted_siblings():
    rows = gui.dependency_rows(_sort_report())
    assert [row["name"] for row in rows] == ["a", "b", "c", "z"]


def test_dependency_rows_sorts_roots_and_siblings_by_severity_desc():
    rows = gui.dependency_rows(_sort_report(), "severity", descending=True)
    assert [row["name"] for row in rows] == ["z", "a", "b", "c"]
    assert rows[1]["parent"] == "" and rows[2]["parent"] == "pkg:npm/a@1.0.0"
    assert rows[3]["parent"] == "pkg:npm/a@1.0.0"


def test_dependency_rows_sorts_roots_and_siblings_by_severity_asc():
    rows = gui.dependency_rows(_sort_report(), "severity", descending=False)
    assert [row["name"] for row in rows] == ["a", "c", "b", "z"]


def test_dependency_rows_sort_keeps_names_on_unresolved_list():
    report = _sort_report()
    graph = report["stats"]["dependency_graph"]
    graph["resolved"] = False
    graph["roots"] = []
    graph["dependencies"] = []
    rows = gui.dependency_rows(report, "#0", descending=True)
    assert [row["name"] for row in rows] == ["z", "c", "b", "a"]
    assert all(row["parent"] == "" for row in rows)


def test_sort_finding_indices_by_severity_and_relation():
    findings = [
        {"severity": "low", "kind": "sca", "rule_id": "CVE-3",
         "package": {"direct": False, "depth": 2}},
        {"severity": "critical", "kind": "sca", "rule_id": "CVE-1",
         "package": {"direct": True, "depth": 0}},
        {"severity": "high", "kind": "sca", "rule_id": "CVE-2",
         "package": {"direct": True, "depth": 0}},
    ]
    assert gui.sort_finding_indices(findings, "severity", True) == [1, 2, 0]
    assert gui.sort_finding_indices(findings, "severity", False) == [0, 2, 1]
    assert gui.sort_finding_indices(findings, "relation", False) == [0, 1, 2]
    assert gui.sort_finding_indices(findings, "relation", True) == [2, 1, 0]
    assert gui.sort_finding_indices(findings, "", True) == [0, 1, 2]


def test_default_sort_direction_is_descending_only_for_severity():
    assert gui.default_sort_desc("severity") is True
    assert gui.default_sort_desc("where") is False
    assert gui.default_sort_desc("#0") is False



def test_scan_command_workflow_flags():
    command = gui.build_scan_command(
        "/src", "/tmp/r.json", config="/src/argus.toml",
        baseline="/src/base.json", fail_on_new=True,
        secrets=False, iac=False, include_suppressed=True, context_lines=5)
    assert command[command.index("--config") + 1] == "/src/argus.toml"
    assert command[command.index("--baseline") + 1] == "/src/base.json"
    assert "--fail-on-new" in command
    assert "--no-secrets" in command and "--no-iac" in command
    assert "--include-suppressed" in command
    assert command[command.index("--context-lines") + 1] == "5"


def test_scan_command_no_context_when_zero():
    command = gui.build_scan_command("/src", "/tmp/r.json", context_lines=0)
    assert "--no-context" in command
    assert "--context-lines" not in command


def test_format_finding_shows_suppression_status():
    finding = {
        "severity": "high", "kind": "sast", "rule_id": "java-sqli",
        "message": "unsafe", "suppressed": True,
        "suppression": {"reason": "accepted", "expires": "2099-01-01"},
    }
    text = gui.format_finding(finding)
    assert "SUPPRESSED — accepted, до 2099-01-01" in text


def test_format_finding_shows_baseline_state():
    finding = {"severity": "high", "kind": "sast", "rule_id": "r",
               "message": "m", "baseline": "new"}
    assert "Baseline: NEW" in gui.format_finding(finding)
    finding["baseline"] = "existing"
    assert "Baseline: existing" in gui.format_finding(finding)


def test_format_finding_renders_snippet_and_remediation():
    finding = {
        "severity": "high", "kind": "sast", "rule_id": "java-sqli",
        "message": "unsafe", "location": {"file": "App.java", "start_line": 3},
        "snippet": {"start_line": 2, "lines": ["a", "b", "c"]},
        "remediation": ["Use a prepared statement."],
    }
    text = gui.format_finding(finding)
    assert "Код:" in text
    assert "> 3 | b" in text
    assert "Как исправить:" in text
    assert "Use a prepared statement." in text
