"""SCA benchmark harness.

Each fixture is a directory with one or more dependency manifests plus an
``expected.json`` file:

.. code-block:: json

    {
      "description": "why this fixture exists",
      "findings": [
        {"package": "lodash", "version": "4.17.15", "vulns": ["CVE-2020-8203"]}
      ],
      "clean": ["left-pad"]
    }

Scoring is deliberately simple and dependency-level, because that is what an
SCA tool actually decides:

* **TP** — an expected package is reported with at least one of its listed
  vulnerability identifiers (primary id or alias);
* **FN** — an expected package is not reported at all;
* **FP** — a package is reported although the fixture does not expect it to be
  vulnerable (``clean`` entries and unlisted packages).

``Score = recall - false_positive_rate`` mirrors the SAST harness.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..sca.scanner import SCAOptions, scan as sca_scan

EXPECTED_FILE = "expected.json"


def discover_fixtures(root: str) -> List[str]:
    if not os.path.isdir(root):
        return []
    fixtures = []
    for entry in sorted(os.listdir(root)):
        directory = os.path.join(root, entry)
        if os.path.isfile(os.path.join(directory, EXPECTED_FILE)):
            fixtures.append(directory)
    return fixtures


def load_expected(fixture: str) -> dict:
    with open(os.path.join(fixture, EXPECTED_FILE), "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload.setdefault("findings", [])
    payload.setdefault("clean", [])
    return payload


def _normalise_package(name: str) -> str:
    return name.strip().lower()


def finding_ids(finding) -> List[str]:
    identifiers = set(finding.aliases or [])
    identifiers.add(finding.rule_id)
    metadata_ids = (finding.metadata or {}).get("vuln_ids") or []
    identifiers.update(str(item) for item in metadata_ids)
    return [item.strip().upper() for item in identifiers if item]


def evaluate_fixture(fixture: str, findings: Sequence) -> dict:
    expected = load_expected(fixture)
    by_package: Dict[str, List] = {}
    for finding in findings:
        if finding.kind != "sca":
            continue
        by_package.setdefault(_normalise_package(finding.package), []).append(finding)

    expected_packages = {_normalise_package(item["package"]): item for item in expected["findings"]}
    clean_packages = {_normalise_package(item) for item in expected["clean"]}

    true_positives: List[dict] = []
    false_negatives: List[dict] = []
    for package, item in expected_packages.items():
        reported = by_package.get(package, [])
        wanted = {str(v).strip().upper() for v in item.get("vulns", [])}
        matched_ids: List[str] = []
        for finding in reported:
            overlap = wanted.intersection(finding_ids(finding)) if wanted else set()
            if overlap or not wanted:
                matched_ids.extend(sorted(overlap))
        if matched_ids or (reported and not wanted):
            true_positives.append({"package": package, "version": item.get("version", ""),
                                   "matched": sorted(set(matched_ids))})
        else:
            false_negatives.append({"package": package, "version": item.get("version", ""),
                                    "expected": sorted(wanted),
                                    "reported": sorted({rid for f in reported for rid in finding_ids(f)})})

    false_positives: List[dict] = []
    for package, reported in by_package.items():
        if package in expected_packages:
            continue
        false_positives.append({
            "package": package,
            "reported": sorted({rid for f in reported for rid in finding_ids(f)}),
            "clean": package in clean_packages,
        })

    expected_count = len(expected_packages)
    positives = expected_count + len(clean_packages)
    tpr = len(true_positives) / expected_count if expected_count else 1.0
    fpr = len(false_positives) / len(clean_packages) if clean_packages else (
        1.0 if false_positives else 0.0)
    return {
        "fixture": os.path.basename(fixture.rstrip(os.sep)),
        "description": expected.get("description", ""),
        "expected": expected_count,
        "tp": len(true_positives),
        "fn": len(false_negatives),
        "fp": len(false_positives),
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "score_pct": round((tpr - fpr) * 100, 1),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "total_findings": len(findings),
        "packages": positives,
    }


def run_sca_benchmark(fixtures: str, jobs: int = 1, verbose: bool = True,
                      cache_path: Optional[str] = None,
                      offline: bool = False) -> Dict[str, object]:
    started = time.time()
    directories = discover_fixtures(fixtures)
    if not directories:
        raise FileNotFoundError(f"no SCA fixtures with {EXPECTED_FILE} under {fixtures}")

    options = SCAOptions(offline=offline, no_cache=False, verbose=verbose)
    cases: List[dict] = []
    for index, directory in enumerate(directories, 1):
        if verbose:
            print(f"[bench-sca] {index}/{len(directories)} {os.path.basename(directory)}",
                  file=__import__("sys").stderr)
        findings, _stats, errors = sca_scan(directory, options)
        case = evaluate_fixture(directory, findings)
        if errors:
            case["errors"] = list(errors)[:5]
        cases.append(case)

    expected_total = sum(case["expected"] for case in cases)
    tp = sum(case["tp"] for case in cases)
    fn = sum(case["fn"] for case in cases)
    fp = sum(case["fp"] for case in cases)
    clean_total = sum(case["packages"] for case in cases) - expected_total
    recall = tp / expected_total if expected_total else 1.0
    fpr = fp / clean_total if clean_total else (1.0 if fp else 0.0)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    summary = {
        "fixtures": len(cases),
        "expected": expected_total,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "score_pct": round((recall - fpr) * 100, 1),
    }
    return {
        "summary": summary,
        "fixtures": cases,
        "elapsed_seconds": round(time.time() - started, 2),
        "fixtures_dir": os.path.abspath(fixtures),
    }


def markdown_report(metrics: Dict[str, object]) -> str:
    summary = metrics["summary"]
    lines = [
        "# SCA benchmark",
        "",
        f"* Fixtures: **{summary['fixtures']}**",
        f"* Expected vulnerable packages: **{summary['expected']}**",
        f"* Detected: **{summary['tp']}** (recall {summary['recall'] * 100:.1f}%)",
        f"* Missed: **{summary['fn']}**, false positives: **{summary['fp']}** "
        f"(FPR {summary['fpr'] * 100:.1f}%)",
        f"* Score (recall - FPR): **{summary['score_pct']}**",
        "",
        "| Fixture | Expected | TP | FN | FP | Recall | FPR | Score |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for case in metrics["fixtures"]:
        lines.append(
            f"| {case['fixture']} | {case['expected']} | {case['tp']} | {case['fn']} | "
            f"{case['fp']} | {case['tpr'] * 100:.1f}% | {case['fpr'] * 100:.1f}% | "
            f"{case['score_pct']} |"
        )
    misses = [case for case in metrics["fixtures"] if case["false_negatives"]]
    if misses:
        lines.extend(["", "## Missed packages", ""])
        for case in misses:
            for miss in case["false_negatives"]:
                lines.append(f"* `{miss['package']}` {miss['version']}: "
                             f"expected {', '.join(miss['expected']) or 'any advisory'}")
    false_positives = [case for case in metrics["fixtures"] if case["false_positives"]]
    if false_positives:
        lines.extend(["", "## False positives", ""])
        for case in false_positives:
            for item in case["false_positives"]:
                lines.append(f"* `{item['package']}`: {', '.join(item['reported']) or 'reported'}")
    lines.append("")
    return "\n".join(lines)
