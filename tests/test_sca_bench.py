"""SCA benchmark harness: fixture discovery, scoring and reporting."""

from __future__ import annotations

import json

import pytest

from argus.bench import sca_bench
from argus.models import Finding, Severity


def make_fixture(root, name, manifests, expected):
    directory = root / name
    directory.mkdir(parents=True)
    for filename, content in manifests.items():
        (directory / filename).write_text(content)
    (directory / sca_bench.EXPECTED_FILE).write_text(json.dumps(expected))
    return directory


def sca(rule_id, package, version, aliases=None):
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.HIGH,
        kind="sca",
        engine="osv",
        package=package,
        version=version,
        aliases=aliases or [],
    )


# --------------------------------------------------------------------------- discovery

def test_discover_fixtures_requires_expected_json(tmp_path):
    make_fixture(tmp_path, "b-fixture", {"requirements.txt": "flask==1.0\n"},
                 {"findings": [{"package": "flask", "vulns": ["CVE-2019-1010083"]}]})
    make_fixture(tmp_path, "a-fixture", {"requirements.txt": "flask==1.0\n"}, {"findings": []})
    (tmp_path / "not-a-fixture").mkdir()
    (tmp_path / "not-a-fixture" / "requirements.txt").write_text("flask==1.0\n")
    names = [directory.rsplit("/", 1)[-1] for directory in sca_bench.discover_fixtures(str(tmp_path))]
    assert names == ["a-fixture", "b-fixture"]
    assert sca_bench.discover_fixtures(str(tmp_path / "missing")) == []


def test_load_expected_defaults(tmp_path):
    directory = make_fixture(tmp_path, "f", {}, {"description": "empty"})
    payload = sca_bench.load_expected(str(directory))
    assert payload["findings"] == []
    assert payload["clean"] == []


# --------------------------------------------------------------------------- scoring

def test_evaluate_fixture_true_positive_and_negative(tmp_path):
    directory = make_fixture(
        tmp_path, "mixed",
        {"requirements.txt": "flask==1.0\nsix==1.17.0\n"},
        {
            "findings": [{"package": "flask", "version": "1.0", "vulns": ["CVE-2019-1010083"]}],
            "clean": ["six"],
        },
    )
    findings = [sca("GHSA-m8g4-6h6g-6h4v", "flask", "1.0", aliases=["CVE-2019-1010083"])]
    case = sca_bench.evaluate_fixture(str(directory), findings)
    assert case["expected"] == 1
    assert case["tp"] == 1
    assert case["fn"] == 0
    assert case["fp"] == 0
    assert case["score_pct"] == 100.0
    assert case["true_positives"][0]["matched"] == ["CVE-2019-1010083"]


def test_evaluate_fixture_alias_mismatch_is_false_negative(tmp_path):
    directory = make_fixture(
        tmp_path, "miss",
        {"requirements.txt": "flask==1.0\n"},
        {"findings": [{"package": "flask", "version": "1.0", "vulns": ["CVE-2019-1010083"]}]},
    )
    findings = [sca("CVE-2023-0001", "flask", "1.0")]
    case = sca_bench.evaluate_fixture(str(directory), findings)
    assert case["tp"] == 0
    assert case["fn"] == 1
    assert case["false_negatives"][0]["reported"] == ["CVE-2023-0001"]


def test_evaluate_fixture_unexpected_package_is_false_positive(tmp_path):
    directory = make_fixture(
        tmp_path, "fp",
        {"requirements.txt": "requests==2.0\n"},
        {"findings": [], "clean": ["requests"]},
    )
    case = sca_bench.evaluate_fixture(str(directory), [sca("CVE-2023-32681", "requests", "2.0")])
    assert case["fp"] == 1
    assert case["fpr"] == 1.0
    assert case["score_pct"] == 0.0  # recall defaults to 1.0 with no expected packages
    assert case["false_positives"][0]["clean"] is True


def test_evaluate_fixture_ignores_sast_findings(tmp_path):
    directory = make_fixture(tmp_path, "sast", {}, {"findings": [], "clean": []})
    sast = Finding(rule_id="java-sqli", title="sqli", severity=Severity.HIGH,
                   kind="sast", engine="argus-java", file="A.java", start_line=1)
    case = sca_bench.evaluate_fixture(str(directory), [sast])
    assert case["tp"] == case["fp"] == 0


# --------------------------------------------------------------------------- reporting

def test_run_sca_benchmark_requires_fixtures(tmp_path):
    with pytest.raises(FileNotFoundError):
        sca_bench.run_sca_benchmark(str(tmp_path), verbose=False)


def test_markdown_report_lists_misses_and_false_positives():
    metrics = {
        "summary": {"fixtures": 2, "expected": 2, "tp": 1, "fn": 1, "fp": 1,
                    "recall": 0.5, "fpr": 1.0, "precision": 0.5, "score_pct": -50.0},
        "fixtures": [
            {"fixture": "miss", "expected": 1, "tp": 0, "fn": 1, "fp": 0,
             "tpr": 0.0, "fpr": 0.0, "score_pct": 0.0,
             "false_negatives": [{"package": "flask", "version": "1.0",
                                  "expected": ["CVE-2019-1010083"], "reported": []}],
             "false_positives": []},
            {"fixture": "fp", "expected": 1, "tp": 1, "fn": 0, "fp": 1,
             "tpr": 1.0, "fpr": 1.0, "score_pct": 0.0,
             "false_negatives": [],
             "false_positives": [{"package": "requests", "reported": ["CVE-2023-32681"],
                                  "clean": True}]},
        ],
    }
    report = sca_bench.markdown_report(metrics)
    assert "Score (recall - FPR): **-50.0**" in report
    assert "## Missed packages" in report
    assert "`flask` 1.0: expected CVE-2019-1010083" in report
    assert "## False positives" in report
    assert "`requests`: CVE-2023-32681" in report


def test_finding_ids_include_aliases_and_metadata():
    finding = sca("GHSA-1", "pkg", "1.0", aliases=["CVE-2020-1"])
    finding.metadata["vuln_ids"] = ["cve-2020-2"]
    assert set(sca_bench.finding_ids(finding)) == {"CVE-2020-1", "CVE-2020-2", "GHSA-1"}
