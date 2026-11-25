"""OWASP Benchmark harness.

Scores any SAST engine against `OWASP Benchmark <https://owasp.org/www-project-benchmark/>`_
using the project's own methodology: a test case counts as *reported* when the
tool produces at least one finding inside that test case file, then

    TPR = TP / (TP + FN)          FPR = FP / (FP + TN)
    Score = TPR - FPR             (Youden index, as used by the OWASP scorecards)

The harness can score the built-in Java engine, Semgrep with the bundled
ruleset, or any external SARIF report (``--sarif``).
"""

from __future__ import annotations

import concurrent.futures
import csv
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import Finding, severity_from_cvss
from ..sca.osv import cache_root

OWASP_REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
TESTCODE_REL = "src/main/java/org/owasp/benchmark/testcode"
EXPECTED_REL = "expectedresults-1.2.csv"

CATEGORY_CWE = {
    "cmdi": "CWE-78",
    "crypto": "CWE-327",
    "hash": "CWE-328",
    "ldapi": "CWE-90",
    "pathtraver": "CWE-22",
    "securecookie": "CWE-614",
    "sqli": "CWE-89",
    "trustbound": "CWE-501",
    "weakrand": "CWE-330",
    "xpathi": "CWE-643",
    "xss": "CWE-79",
    "xxe": "CWE-611",
}

CATEGORY_TITLES = {
    "cmdi": "Command injection",
    "crypto": "Weak cryptography",
    "hash": "Weak hashing",
    "ldapi": "LDAP injection",
    "pathtraver": "Path traversal",
    "securecookie": "Insecure cookie",
    "sqli": "SQL injection",
    "trustbound": "Trust boundary violation",
    "weakrand": "Insecure randomness",
    "xpathi": "XPath injection",
    "xss": "Cross-site scripting",
    "xxe": "XML external entity",
}


def ensure_benchmark(directory: str, verbose: bool = True) -> str:
    """Clone OWASP Benchmark when the target directory does not exist yet."""
    testcode = os.path.join(directory, TESTCODE_REL)
    if os.path.isdir(testcode):
        return directory
    parent = os.path.dirname(os.path.abspath(directory)) or "."
    os.makedirs(parent, exist_ok=True)
    if verbose:
        print(f"[bench] cloning {OWASP_REPO} -> {directory}", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", OWASP_REPO, directory],
        check=True,
    )
    return directory


def load_expected(directory: str) -> Dict[str, Dict[str, object]]:
    path = os.path.join(directory, EXPECTED_REL)
    cases: Dict[str, Dict[str, object]] = {}
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        next(reader)
        for row in reader:
            if len(row) < 4:
                continue
            name = row[0].strip()
            category = row[1].strip()
            real = row[2].strip().lower() == "true"
            cwe = row[3].strip()
            cases[name] = {
                "name": name,
                "category": category,
                "real": real,
                "cwe": f"CWE-{cwe}" if cwe and not cwe.startswith("CWE") else cwe,
            }
    return cases


def list_testcases(directory: str) -> List[str]:
    testcode = os.path.join(directory, TESTCODE_REL)
    return sorted(
        filename[:-5]
        for filename in os.listdir(testcode)
        if filename.startswith("BenchmarkTest") and filename.endswith(".java")
    )


# --------------------------------------------------------------------------- engine runners

def _scan_java_worker(payload: Tuple[str, str, Dict[str, str]]) -> Tuple[str, List[dict]]:
    path, root, properties = payload
    from ..sast.java.engine import analyze_file

    name = os.path.basename(path)[: -len(".java")] if path.endswith(".java") else os.path.basename(path)
    try:
        findings = analyze_file(path, root, properties=properties)
    except Exception as exc:  # noqa: BLE001 - a single broken file must not stop the run
        return name, [{"error": str(exc), "rule_id": "engine-error", "line": 0}]
    return name, [
        {"rule_id": finding.rule_id, "line": finding.start_line, "severity": finding.severity.value}
        for finding in findings
    ]


def _load_cache(path: Optional[str]) -> Dict[str, dict]:
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(path: Optional[str], cache: Dict[str, dict]) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(cache, handle)
    os.replace(temporary, path)


def _engine_fingerprint() -> str:
    """Fingerprint of the analyzer sources so a code change invalidates the cache."""
    import hashlib

    digest = hashlib.sha256()
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in ("sast/java/engine.py", "sast/java/catalog.py"):
        path = os.path.join(base, relative)
        try:
            with open(path, "rb") as handle:
                digest.update(handle.read())
        except OSError:
            digest.update(relative.encode())
    return digest.hexdigest()[:16]


def run_java_engine(directory: str, jobs: int = 1, cache_path: Optional[str] = None,
                    properties: Optional[Dict[str, str]] = None,
                    verbose: bool = True) -> Dict[str, List[dict]]:
    from ..sast.java.engine import load_properties

    testcode = os.path.join(directory, TESTCODE_REL)
    names = list_testcases(directory)
    properties = properties if properties is not None else load_properties(directory)

    cache = _load_cache(cache_path)
    version = _engine_fingerprint()
    results: Dict[str, List[dict]] = {}
    pending: List[Tuple[str, str, Dict[str, str]]] = []
    for name in names:
        path = os.path.join(testcode, name + ".java")
        try:
            stat = os.stat(path)
        except OSError:
            continue
        key = path
        cached = cache.get(key)
        if cached and cached.get("version") == version \
                and cached.get("mtime") == stat.st_mtime and cached.get("size") == stat.st_size:
            results[name] = cached.get("findings", [])
        else:
            pending.append((path, directory, properties))

    if verbose:
        print(f"[bench] java engine: {len(results)} cached, {len(pending)} to scan", file=sys.stderr)
    started = time.time()
    if pending:
        if jobs > 1:
            with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
                for index, (name, findings) in enumerate(pool.map(_scan_java_worker, pending, chunksize=16), 1):
                    results[name] = findings
                    if verbose and index % 500 == 0:
                        print(f"[bench]   {index}/{len(pending)} files", file=sys.stderr)
        else:
            for index, payload in enumerate(pending, 1):
                name, findings = _scan_java_worker(payload)
                results[name] = findings
                if verbose and index % 500 == 0:
                    print(f"[bench]   {index}/{len(pending)} files", file=sys.stderr)
        for path, root, _props in pending:
            try:
                stat = os.stat(path)
            except OSError:
                continue
            name = os.path.basename(path)[: -len(".java")]
            cache[path] = {"version": version, "mtime": stat.st_mtime, "size": stat.st_size,
                           "findings": results.get(name, [])}
        _save_cache(cache_path, cache)
    if verbose and pending:
        print(f"[bench] java engine finished in {time.time() - started:.1f}s", file=sys.stderr)
    return results


def run_semgrep_engine(directory: str, jobs: int = 1, verbose: bool = True) -> Dict[str, List[dict]]:
    from ..sast.semgrep_engine import SemgrepError, find_semgrep, run_semgrep

    binary = find_semgrep()
    if not binary:
        raise SemgrepError("semgrep is not installed (pip install semgrep)")
    rules = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sast", "rules", "java")
    testcode = os.path.join(directory, TESTCODE_REL)
    if verbose:
        print(f"[bench] semgrep: scanning {testcode}", file=sys.stderr)
    findings, errors = run_semgrep(testcode, rules, jobs=jobs, binary=binary, verbose=verbose)
    if errors and verbose:
        for error in errors[:5]:
            print(f"[bench] semgrep: {error}", file=sys.stderr)
    grouped: Dict[str, List[dict]] = {}
    for finding in findings:
        name = os.path.basename(finding.file)[: -len(".java")] if finding.file.endswith(".java") else finding.file
        grouped.setdefault(name, []).append(
            {"rule_id": finding.rule_id, "line": finding.start_line, "severity": finding.severity.value}
        )
    return grouped


def load_sarif_report(path: str) -> Dict[str, List[dict]]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    grouped: Dict[str, List[dict]] = {}
    runs = payload.get("runs") if isinstance(payload, dict) else None
    for run in runs or []:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or ""
            message = ((result.get("message") or {}).get("text") or "")
            level = result.get("level") or "warning"
            severity = {"error": "high", "warning": "medium", "note": "low"}.get(level, "unknown")
            locations = result.get("locations") or []
            if not locations:
                continue
            physical = locations[0].get("physicalLocation") or {}
            uri = ((physical.get("artifactLocation") or {}).get("uri") or "").replace("\\", "/")
            name = os.path.basename(uri)
            if name.endswith(".java"):
                name = name[: -len(".java")]
            line = (physical.get("region") or {}).get("startLine", 0)
            grouped.setdefault(name, []).append(
                {"rule_id": rule_id, "line": line, "severity": severity, "message": message}
            )
    return grouped


# --------------------------------------------------------------------------- scoring

@dataclass
class CaseOutcome:
    name: str
    category: str
    real: bool
    cwe: str
    findings: List[dict] = field(default_factory=list)

    @property
    def reported(self) -> bool:
        return bool([f for f in self.findings if f.get("rule_id") not in ("engine-error", "error")])


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_metrics(outcomes: Sequence[CaseOutcome]) -> Dict[str, object]:
    def block(rows: Sequence[CaseOutcome]) -> Dict[str, object]:
        tp = sum(1 for row in rows if row.real and row.reported)
        fp = sum(1 for row in rows if not row.real and row.reported)
        fn = sum(1 for row in rows if row.real and not row.reported)
        tn = sum(1 for row in rows if not row.real and not row.reported)
        tpr = _safe_div(tp, tp + fn)
        fpr = _safe_div(fp, fp + tn)
        precision = _safe_div(tp, tp + fp)
        recall = tpr
        return {
            "cases": len(rows),
            "real": tp + fn,
            "reported": tp + fp,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "score": round(tpr - fpr, 4),
            "score_pct": round((tpr - fpr) * 100, 1),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(_safe_div(2 * precision * recall, precision + recall), 4),
        }

    by_category: Dict[str, Dict[str, object]] = {}
    for category in sorted({row.category for row in outcomes}):
        by_category[category] = block([row for row in outcomes if row.category == category])

    rules: Dict[str, Dict[str, object]] = {}
    for row in outcomes:
        for finding in row.findings:
            rule_id = finding.get("rule_id") or "unknown"
            entry = rules.setdefault(rule_id, {"fired": 0, "true_cases": 0, "false_cases": 0})
            entry["fired"] += 1
            if row.real:
                entry["true_cases"] += 1
            else:
                entry["false_cases"] += 1
    for entry in rules.values():
        fired = entry["fired"]
        entry["precision"] = round(_safe_div(entry["true_cases"], fired), 4)

    summary = block(outcomes)
    return {
        "summary": summary,
        "by_category": by_category,
        "by_rule": dict(sorted(rules.items(), key=lambda item: -item[1]["fired"])),
    }


def evaluate(expected: Dict[str, Dict[str, object]],
             reported: Dict[str, List[dict]],
             engines: Sequence[str]) -> Dict[str, object]:
    outcomes: List[CaseOutcome] = []
    for name, meta in expected.items():
        outcomes.append(
            CaseOutcome(
                name=name,
                category=str(meta["category"]),
                real=bool(meta["real"]),
                cwe=str(meta["cwe"]),
                findings=reported.get(name, []),
            )
        )
    metrics = compute_metrics(outcomes)
    metrics["engines"] = list(engines)
    metrics["cases"] = [
        {
            "name": outcome.name,
            "category": outcome.category,
            "real": outcome.real,
            "reported": outcome.reported,
            "rules": sorted({finding.get("rule_id", "") for finding in outcome.findings}),
        }
        for outcome in outcomes
    ]
    return metrics


# --------------------------------------------------------------------------- reporting

def markdown_report(metrics: Dict[str, object], title: str = "OWASP Benchmark scorecard") -> str:
    summary = metrics["summary"]
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"Engines: **{', '.join(metrics.get('engines', []))}**")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Test cases | {summary['cases']} |")
    lines.append(f"| True positives | {summary['tp']} |")
    lines.append(f"| False positives | {summary['fp']} |")
    lines.append(f"| False negatives | {summary['fn']} |")
    lines.append(f"| True negatives | {summary['tn']} |")
    lines.append(f"| TPR (recall) | {summary['tpr'] * 100:.1f}% |")
    lines.append(f"| FPR | {summary['fpr'] * 100:.1f}% |")
    lines.append(f"| Precision | {summary['precision'] * 100:.1f}% |")
    lines.append(f"| F1 | {summary['f1'] * 100:.1f}% |")
    lines.append(f"| **Benchmark score (TPR - FPR)** | **{summary['score_pct']:.1f}** |")
    lines.append("")
    lines.append("## Per category")
    lines.append("")
    lines.append("| Category | CWE | Cases | TP | FP | FN | TPR | FPR | Score |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for category, block in metrics["by_category"].items():
        lines.append(
            "| {cat} | {cwe} | {cases} | {tp} | {fp} | {fn} | {tpr:.1f}% | {fpr:.1f}% | {score:.1f} |".format(
                cat=CATEGORY_TITLES.get(category, category),
                cwe=CATEGORY_CWE.get(category, ""),
                cases=block["cases"],
                tp=block["tp"],
                fp=block["fp"],
                fn=block["fn"],
                tpr=block["tpr"] * 100,
                fpr=block["fpr"] * 100,
                score=block["score_pct"],
            )
        )
    lines.append("")
    lines.append("## Rules that fired")
    lines.append("")
    lines.append("| Rule | Findings | On vulnerable cases | On clean cases | Precision |")
    lines.append("| --- | --- | --- | --- | --- |")
    for rule_id, entry in metrics["by_rule"].items():
        lines.append(
            f"| `{rule_id}` | {entry['fired']} | {entry['true_cases']} | {entry['false_cases']} | "
            f"{entry['precision'] * 100:.0f}% |"
        )
    lines.append("")
    return "\n".join(lines)


def run_benchmark(directory: str, engines: Sequence[str] = ("java",), jobs: int = 1,
                  cache_path: Optional[str] = None, sarif_path: Optional[str] = None,
                  verbose: bool = True) -> Dict[str, object]:
    directory = ensure_benchmark(directory, verbose=verbose)
    expected = load_expected(directory)
    reported: Dict[str, List[dict]] = {}
    used_engines: List[str] = []
    if sarif_path:
        reported = load_sarif_report(sarif_path)
        used_engines = [f"sarif:{os.path.basename(sarif_path)}"]
    else:
        for engine in engines:
            if engine == "java":
                reported.update(run_java_engine(directory, jobs=jobs, cache_path=cache_path, verbose=verbose))
                used_engines.append("argus-java")
            elif engine == "semgrep":
                reported.update(run_semgrep_engine(directory, jobs=jobs, verbose=verbose))
                used_engines.append("semgrep")
            else:
                raise ValueError(f"unknown engine: {engine}")
    started = time.time()
    metrics = evaluate(expected, reported, used_engines)
    metrics["elapsed_seconds"] = round(time.time() - started, 2)
    metrics["benchmark_dir"] = os.path.abspath(directory)
    return metrics


def write_outputs(metrics: Dict[str, object], output_dir: str, prefix: str = "owasp-benchmark") -> Tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{prefix}.json")
    md_path = os.path.join(output_dir, f"{prefix}.md")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(markdown_report(metrics))
    return json_path, md_path
