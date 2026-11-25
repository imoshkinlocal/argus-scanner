"""OWASP Benchmark harness: parsing, scoring and reporting."""

from __future__ import annotations

import json
import os

import pytest

from argus.bench import owasp


def write_benchmark(root, cases):
    """Create a minimal BenchmarkJava-shaped tree.

    ``cases`` maps a test case name to ``(category, real, cwe)``.
    """
    testcode = root / owasp.TESTCODE_REL
    testcode.mkdir(parents=True)
    rows = ["# test name, category, real vulnerability, cwe, ..."]
    for name, (category, real, cwe) in cases.items():
        rows.append(f"{name},{category},{str(real).lower()},{cwe},,,")
        (testcode / f"{name}.java").write_text("class X {}\n")
    (root / owasp.EXPECTED_REL).write_text("\n".join(rows) + "\n")
    return str(root)


SERVLET_HEAD = """\
import javax.servlet.http.*;

public class {klass} extends HttpServlet {{
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {{
"""

SERVLET_TAIL = """
    }
}
"""


def write_java(testcode_dir, name, body):
    source = SERVLET_HEAD.format(klass=name) + body + SERVLET_TAIL
    (testcode_dir / f"{name}.java").write_text(source)


# --------------------------------------------------------------------------- parsing

def test_load_expected_parses_csv(tmp_path):
    directory = write_benchmark(tmp_path / "bm", {
        "BenchmarkTest00001": ("sqli", True, 89),
        "BenchmarkTest00002": ("xss", False, 79),
    })
    cases = owasp.load_expected(directory)
    assert set(cases) == {"BenchmarkTest00001", "BenchmarkTest00002"}
    assert cases["BenchmarkTest00001"]["real"] is True
    assert cases["BenchmarkTest00001"]["cwe"] == "CWE-89"
    assert cases["BenchmarkTest00002"]["category"] == "xss"
    assert cases["BenchmarkTest00002"]["real"] is False


def test_list_testcases_sorted(tmp_path):
    directory = write_benchmark(tmp_path / "bm", {
        "BenchmarkTest00002": ("sqli", True, 89),
        "BenchmarkTest00001": ("sqli", True, 89),
    })
    assert owasp.list_testcases(directory) == ["BenchmarkTest00001", "BenchmarkTest00002"]


# --------------------------------------------------------------------------- scoring

def outcome(name, category, real, findings):
    return owasp.CaseOutcome(name=name, category=category, real=real, cwe="CWE-89",
                             findings=findings)


def test_compute_metrics_confusion_matrix():
    outcomes = [
        outcome("a", "sqli", True, [{"rule_id": "r"}]),
        outcome("b", "sqli", True, [{"rule_id": "r"}]),
        outcome("c", "sqli", True, []),
        outcome("d", "sqli", False, [{"rule_id": "r"}]),
        outcome("e", "sqli", False, []),
    ]
    summary = owasp.compute_metrics(outcomes)["summary"]
    assert (summary["tp"], summary["fp"], summary["fn"], summary["tn"]) == (2, 1, 1, 1)
    assert summary["tpr"] == pytest.approx(2 / 3, abs=1e-4)
    assert summary["fpr"] == pytest.approx(1 / 2, abs=1e-4)
    assert summary["score"] == pytest.approx(2 / 3 - 1 / 2, abs=1e-4)
    assert summary["cases"] == 5


def test_engine_errors_are_not_reported():
    assert outcome("a", "sqli", True, [{"rule_id": "engine-error"}]).reported is False
    assert outcome("b", "sqli", True, [{"rule_id": "error", "line": 0}]).reported is False
    assert outcome("c", "sqli", True, [{"rule_id": "java-sqli"}]).reported is True


def test_metrics_break_down_by_category_and_rule():
    outcomes = [
        outcome("a", "sqli", True, [{"rule_id": "java-sqli"}]),
        outcome("b", "xss", False, [{"rule_id": "java-sqli"}, {"rule_id": "java-xss"}]),
        outcome("c", "xss", True, [{"rule_id": "java-xss"}]),
    ]
    metrics = owasp.compute_metrics(outcomes)
    assert metrics["by_category"]["sqli"]["score"] == 1.0
    assert metrics["by_category"]["xss"]["tp"] == 1
    assert metrics["by_category"]["xss"]["fp"] == 1
    rules = metrics["by_rule"]
    assert rules["java-sqli"]["fired"] == 2
    assert rules["java-sqli"]["true_cases"] == 1
    assert rules["java-sqli"]["false_cases"] == 1
    assert rules["java-sqli"]["precision"] == 0.5
    assert rules["java-xss"]["precision"] == 0.5


def test_evaluate_marks_unreported_real_cases():
    expected = {
        "BenchmarkTest00001": {"name": "BenchmarkTest00001", "category": "sqli",
                               "real": True, "cwe": "CWE-89"},
        "BenchmarkTest00002": {"name": "BenchmarkTest00002", "category": "sqli",
                               "real": True, "cwe": "CWE-89"},
    }
    metrics = owasp.evaluate(expected, {"BenchmarkTest00001": [{"rule_id": "r"}]}, ["argus-java"])
    assert metrics["summary"]["tp"] == 1
    assert metrics["summary"]["fn"] == 1
    assert metrics["engines"] == ["argus-java"]
    cases = {case["name"]: case for case in metrics["cases"]}
    assert cases["BenchmarkTest00001"]["reported"] is True
    assert cases["BenchmarkTest00002"]["reported"] is False
    assert cases["BenchmarkTest00001"]["rules"] == ["r"]


# --------------------------------------------------------------------------- SARIF input

def test_load_sarif_report_groups_java_files(tmp_path):
    payload = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "other", "rules": []}},
            "results": [
                {"ruleId": "r1", "level": "error",
                 "message": {"text": "boom"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "org/owasp/benchmark/testcode/BenchmarkTest00001.java"},
                     "region": {"startLine": 12}}}]},
                {"ruleId": "r2", "level": "note",
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "BenchmarkTest00002.java"}}}]},
                {"ruleId": "ignored", "message": {"text": "no location"}},
            ],
        }],
    }
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps(payload))
    grouped = owasp.load_sarif_report(str(path))
    assert [item["rule_id"] for item in grouped["BenchmarkTest00001"]] == ["r1"]
    assert grouped["BenchmarkTest00001"][0]["severity"] == "high"
    assert grouped["BenchmarkTest00001"][0]["line"] == 12
    assert grouped["BenchmarkTest00002"][0]["severity"] == "low"
    assert "ignored" not in json.dumps(grouped)


# --------------------------------------------------------------------------- reporting

def metrics_for_report():
    outcomes = [
        outcome("a", "sqli", True, [{"rule_id": "java-sqli"}]),
        outcome("b", "cmdi", False, [{"rule_id": "java-cmdi"}]),
    ]
    metrics = owasp.compute_metrics(outcomes)
    metrics["engines"] = ["argus-java"]
    return metrics


def test_markdown_report_has_scorecard_sections():
    report = owasp.markdown_report(metrics_for_report())
    assert "# OWASP Benchmark scorecard" in report
    assert "Benchmark score (TPR - FPR)" in report
    assert "SQL injection" in report
    assert "`java-cmdi`" in report


def test_write_outputs_creates_json_and_markdown(tmp_path):
    json_path, md_path = owasp.write_outputs(metrics_for_report(), str(tmp_path / "out"), prefix="demo")
    assert os.path.isfile(json_path) and os.path.isfile(md_path)
    payload = json.loads(open(json_path, encoding="utf-8").read())
    assert payload["summary"]["tp"] == 1
    assert "# OWASP Benchmark scorecard" in open(md_path, encoding="utf-8").read()


# --------------------------------------------------------------------------- end to end

def test_run_benchmark_with_java_engine(tmp_path):
    root = tmp_path / "bm"
    directory = write_benchmark(root, {
        "BenchmarkTest00001": ("sqli", True, 89),
        "BenchmarkTest00002": ("sqli", False, 89),
    })
    testcode = root / owasp.TESTCODE_REL
    write_java(testcode, "BenchmarkTest00001", """
        String param = request.getParameter("id");
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = '" + param + "'");
""")
    write_java(testcode, "BenchmarkTest00002", """
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = 1");
""")
    metrics = owasp.run_benchmark(
        directory, engines=["java"], jobs=1,
        cache_path=str(tmp_path / "cache.json"), verbose=False,
    )
    summary = metrics["summary"]
    assert summary["tp"] == 1
    assert summary["fn"] == 0
    assert summary["fp"] == 0
    assert summary["score_pct"] == 100.0
    assert metrics["engines"] == ["argus-java"]
    assert os.path.isfile(tmp_path / "cache.json")


def test_run_benchmark_rejects_unknown_engine(tmp_path):
    directory = write_benchmark(tmp_path / "bm", {"BenchmarkTest00001": ("sqli", True, 89)})
    with pytest.raises(ValueError):
        owasp.run_benchmark(directory, engines=["codeql"], verbose=False)
