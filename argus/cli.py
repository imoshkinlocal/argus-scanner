"""``argus`` command line interface.

Commands
--------
scan          SAST + SCA in one pass
sast          static analysis only
sca           dependency / vulnerability analysis only
sbom          export dependencies as CycloneDX 1.5, SPDX 2.3 or Markdown
bench owasp   score an engine against OWASP Benchmark
bench sca     score the SCA engine against pinned fixtures
db update     download the offline OSV archives
db status     show the content of the local caches
Rules list    list bundled Semgrep rules
cwe           browse the built-in CWE reference
diff          compare two JSON reports (new / fixed / unchanged)
vex           export SCA findings from a report as OpenVEX
version       print the tool version

Reports are emitted as JSON or SARIF for machines and as Markdown or text for
humans; ``--summary`` writes the Markdown view next to the machine report.

Exit codes: ``0`` no findings at/above ``--fail-on``, ``1`` findings found,
``2`` a scan error occurred (missing manifest, network failure, missing Semgrep).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from . import config as config_module
from .gates import GatePolicy
from .models import Finding, ScanError, ScanResult, Severity, dedupe, filter_findings, parse_severity
from .output import render
from .sca.osv import cache_root
from .sca.scanner import SCAOptions, collect_inventory, scan as sca_scan
from .sast.scanner import SastOptions, scan_target as sast_scan
from .workflow import WorkflowOptions, finalize

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_FAIL_ON_CHOICES = ("none", "info", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------- helpers

def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-f", "--format", default="json",
                        choices=("json", "sarif", "text", "md", "markdown"),
                        help="machine report: json/sarif; human report: text/md "
                             "(default: json)")
    parser.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    parser.add_argument("--summary", metavar="PATH",
                        help="also write a human-readable Markdown report to PATH")
    parser.add_argument("--fail-on", default="high", choices=_FAIL_ON_CHOICES,
                        help="exit with status 1 when a finding at/above this severity exists")
    parser.add_argument("--min-severity", default="unknown",
                        choices=("unknown", "info", "low", "medium", "high", "critical"),
                        help="drop findings below this severity")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages")
    parser.add_argument("--config", metavar="PATH",
                        help="project configuration (argus.toml / argus.json); "
                             "auto-discovered when omitted")
    parser.add_argument("--baseline", metavar="PATH",
                        help="mark findings present in this baseline as existing")
    parser.add_argument("--baseline-out", metavar="PATH",
                        help="write the current findings as a new baseline")
    parser.add_argument("--fail-on-new", action="store_true",
                        help="only fail on findings missing from --baseline")
    parser.add_argument("--ignore", action="append", default=[], metavar="PATH",
                        help="suppression file (JSON/TOML/.argusignore), repeatable")
    parser.add_argument("--include-suppressed", action="store_true",
                        help="show suppressed findings in human/SARIF reports")
    parser.add_argument("--context-lines", type=int, default=2, metavar="N",
                        help="source lines around a finding for snippets (default: 2)")
    parser.add_argument("--no-context", action="store_true",
                        help="do not attach source snippets to findings")


def _add_sast_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engine", default="auto", choices=("auto", "java", "semgrep"),
                        help="SAST backend (default: auto — Java engine + Semgrep)")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="parallel workers / Semgrep jobs")
    parser.add_argument("--language", action="append", default=[], metavar="LANG",
                        help="restrict to a language (repeatable): java, python, javascript, "
                             "typescript, go, php, c, cpp")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATH",
                        help="skip paths containing this fragment (repeatable)")
    parser.add_argument("--rules", metavar="DIR", help="use an external Semgrep rule directory")
    parser.add_argument("--java-properties", metavar="DIR",
                        help="directory with *.properties files used to resolve constants")
    parser.add_argument("--no-secrets", action="store_true",
                        help="disable the built-in secret scanner")
    parser.add_argument("--no-iac", action="store_true",
                        help="disable Dockerfile/Kubernetes/Terraform checks")
    parser.add_argument("--no-sast-cache", action="store_true",
                        help="re-analyse every Java file instead of reusing cached findings")
    parser.add_argument("--sast-cache-dir", metavar="DIR",
                        help="directory for the incremental SAST cache")


def _add_debian_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--deb-root", action="append", default=[], metavar="DIR",
                        help="read installed packages from DIR/var/lib/dpkg/status "
                             "(repeatable; use / for the running system)")
    parser.add_argument("--deb-status", action="append", default=[], metavar="FILE",
                        help="read a dpkg status file (repeatable)")
    parser.add_argument("--deb", action="append", default=[], metavar="FILE",
                        help="inspect a binary .deb package (repeatable)")
    parser.add_argument("--deb-suite", default="", metavar="SUITE",
                        help="Debian suite/codename (for example bookworm or 12) for "
                             "--deb/--deb-status and debian/control; "
                             "default: detect from the rootfs or the host")


def _add_sca_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include-dev", action="store_true", help="include dev/test dependencies")
    parser.add_argument("--range-policy", default="min", choices=("min", "skip"),
                        help="how to treat version ranges: resolve the lower bound or skip")
    parser.add_argument("--offline", action="store_true",
                        help="use the offline OSV archives only (see `argus db update`)")
    parser.add_argument("--no-cache", action="store_true", help="bypass the OSV query cache")
    parser.add_argument("--db-dir", metavar="DIR", help="offline OSV archive directory")
    parser.add_argument("--ecosystem", action="append", default=[], metavar="NAME",
                        help="restrict to an ecosystem (repeatable)")
    _add_debian_arguments(parser)
    parser.add_argument("--threat-intel", action="store_true",
                        help="annotate SCA findings with EPSS scores and CISA KEV status")
    parser.add_argument("--epss-file", metavar="FILE",
                        help="read EPSS data from a local JSON file instead of the API")
    parser.add_argument("--kev-file", metavar="FILE",
                        help="read the CISA KEV catalogue from a local JSON file")
    parser.add_argument("--no-threat-cache", action="store_true",
                        help="ignore the cached EPSS/KEV snapshots")
    parser.add_argument("--threat-cache-dir", metavar="DIR",
                        help="directory for cached EPSS/KEV snapshots")
    parser.add_argument("--threat-ttl", type=float, metavar="HOURS",
                        help="how long a cached EPSS/KEV snapshot stays fresh")


def _write_report(path: str, payload: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(payload if payload.endswith("\n") else payload + "\n")


def _gate_policy(args: argparse.Namespace) -> GatePolicy:
    config = getattr(args, "config_obj", None)
    values: Dict[str, Any] = {}
    if config is not None:
        values.update(config.gate_options())
    values["fail_on"] = args.fail_on
    values["fail_on_new"] = bool(getattr(args, "fail_on_new", False))
    return GatePolicy.from_mapping(values)


def _workflow_options(args: argparse.Namespace) -> WorkflowOptions:
    config = getattr(args, "config_obj", None)
    context = max(0, int(getattr(args, "context_lines", 2)))
    if getattr(args, "no_context", False):
        context = 0
    return WorkflowOptions(
        root=os.path.abspath(args.target),
        baseline=getattr(args, "baseline", None),
        baseline_out=getattr(args, "baseline_out", None),
        fail_on_new=bool(getattr(args, "fail_on_new", False)),
        ignore_files=tuple(getattr(args, "ignore", ()) or ()),
        config=config,
        severity_overrides=config.severity_overrides() if config is not None else {},
        gate_policy=_gate_policy(args),
        context_lines=context,
        snippets=context > 0,
        include_suppressed=bool(getattr(args, "include_suppressed", False)),
    )


def _finalize(result: ScanResult, args: argparse.Namespace) -> None:
    summary = finalize(result, _workflow_options(args))
    gate = summary.gate
    if gate is not None and not gate.passed and not args.quiet:
        for violation in gate.violations:
            print(f"gate: {violation}", file=sys.stderr)
    if summary.expired_suppressions and not args.quiet:
        print(f"warning: {summary.expired_suppressions} suppression(s) have expired and were "
              "ignored", file=sys.stderr)


def _emit(result: ScanResult, args: argparse.Namespace) -> int:
    from .output import markdown_report

    _finalize(result, args)
    payload = render(result, args.format)
    if args.output:
        _write_report(args.output, payload)
        if not args.quiet:
            summary = result.summary()
            print(f"{summary['total']} findings "
                  f"(max severity: {summary['max_severity']}) -> {args.output}", file=sys.stderr)
    else:
        print(payload)

    summary_path = getattr(args, "summary", None)
    if summary_path:
        markdown = markdown_report(result)
        if summary_path != args.output:
            _write_report(summary_path, markdown)
            if not args.quiet:
                print(f"human-readable summary -> {summary_path}", file=sys.stderr)
    return _exit_code(result, args.fail_on, bool(result.errors))


def _exit_code(result: ScanResult, fail_on: str, had_errors: bool) -> int:
    gate = result.stats.get("gate")
    if isinstance(gate, dict):
        if not gate.get("passed", True):
            return EXIT_FINDINGS
        if had_errors:
            return EXIT_ERROR
        return EXIT_OK
    if fail_on != "none":
        threshold = parse_severity(fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.findings
               if not f.suppressed):
            return EXIT_FINDINGS
    if had_errors:
        return EXIT_ERROR
    return EXIT_OK


def _merge_results(target: str, parts: Sequence[ScanResult]) -> ScanResult:
    merged = ScanResult(target=target)
    for part in parts:
        merged.findings.extend(part.findings)
        merged.errors.extend(part.errors)
        for engine in part.engines:
            if engine not in merged.engines:
                merged.engines.append(engine)
        for key, value in part.stats.items():
            merged.stats.setdefault(key, value)
    merged.findings = dedupe(merged.findings)
    merged.sort()
    return merged


def _sast_options(args: argparse.Namespace) -> SastOptions:
    properties = None
    if getattr(args, "java_properties", None):
        from .sast.java import load_properties
        properties = load_properties(args.java_properties)
    return SastOptions(
        engine=args.engine,
        jobs=max(1, args.jobs),
        min_severity=parse_severity(args.min_severity),
        languages=tuple(args.language),
        exclude=tuple(args.exclude),
        rules_dir=args.rules,
        properties=properties,
        verbose=not args.quiet,
        secrets=not getattr(args, "no_secrets", False),
        iac=not getattr(args, "no_iac", False),
        cache=not getattr(args, "no_sast_cache", False),
        cache_dir=getattr(args, "sast_cache_dir", None),
    )


def _sca_options(args: argparse.Namespace) -> SCAOptions:
    return SCAOptions(
        include_dev=args.include_dev,
        range_policy=args.range_policy,
        offline=args.offline,
        no_cache=args.no_cache,
        db_dir=args.db_dir,
        ecosystems=tuple(args.ecosystem),
        exclude=tuple(getattr(args, "exclude", ())),
        verbose=not args.quiet,
        deb_roots=tuple(getattr(args, "deb_root", ()) or ()),
        deb_status=tuple(getattr(args, "deb_status", ()) or ()),
        deb_files=tuple(getattr(args, "deb", ()) or ()),
        deb_suite=getattr(args, "deb_suite", "") or "",
    )


def _run_sca(target: str, args: argparse.Namespace) -> ScanResult:
    findings, stats, errors = sca_scan(target, _sca_options(args))
    result = ScanResult(target=os.path.abspath(target))
    result.findings = findings
    result.stats.update(stats)
    result.engines.append("osv")
    for message in errors:
        result.errors.append(ScanError(scanner="sca", message=message))
    result.findings = filter_findings(result.findings, parse_severity(args.min_severity))
    if (getattr(args, "threat_intel", False) or getattr(args, "epss_file", None)
            or getattr(args, "kev_file", None)):
        from . import threat

        ttl = getattr(args, "threat_ttl", None)
        threat_stats = threat.apply(result.findings, threat.ThreatOptions(
            epss_file=getattr(args, "epss_file", None),
            kev_file=getattr(args, "kev_file", None),
            cache=not getattr(args, "no_threat_cache", False),
            cache_dir=getattr(args, "threat_cache_dir", None),
            ttl_hours=float(ttl) if ttl is not None else threat.DEFAULT_TTL_HOURS,
            timeout=float(getattr(args, "threat_timeout", threat.DEFAULT_TIMEOUT)),
            verbose=not args.quiet,
        ))
        result.stats["threat_intel"] = threat_stats
        if not args.quiet:
            for message in threat_stats.get("errors", ()):
                print(f"warning: threat intel: {message}", file=sys.stderr)
    result.sort()
    return result


# --------------------------------------------------------------------------- commands

def command_scan(args: argparse.Namespace) -> int:
    parts: List[ScanResult] = []
    if not args.no_sast:
        parts.append(sast_scan(args.target, _sast_options(args)))
    if not args.no_sca:
        parts.append(_run_sca(args.target, args))
    result = _merge_results(os.path.abspath(args.target), parts)
    return _emit(result, args)


def command_sast(args: argparse.Namespace) -> int:
    result = sast_scan(args.target, _sast_options(args))
    return _emit(result, args)


def command_sca(args: argparse.Namespace) -> int:
    result = _run_sca(args.target, args)
    return _emit(result, args)


def command_sbom(args: argparse.Namespace) -> int:
    from .sbom import (SBOMOptions, cyclonedx_document, dumps, markdown_inventory,
                       spdx_document, verify_document)

    sign_key = getattr(args, "sign_key", None) or os.environ.get("ARGUS_SBOM_KEY", "")
    if getattr(args, "verify", None):
        path = args.verify
        try:
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read SBOM {path}: {exc}") from exc
        valid = verify_document(document, sign_key)
        signature = document.get("signature") or {}
        if not args.quiet:
            print(f"{'valid' if valid else 'INVALID'} signature: "
                  f"algorithm={signature.get('algorithm', 'none')} "
                  f"sha256={signature.get('sha256', '-')}"
                  + (f" keyId={signature['keyId']}" if signature.get("keyId") else ""),
                  file=sys.stderr)
        return EXIT_OK if valid else EXIT_ERROR

    target = args.target
    if not target:
        raise ValueError("sbom needs a target directory or --verify FILE")
    if not os.path.exists(target):
        raise FileNotFoundError(f"target does not exist: {target}")
    root = (os.path.dirname(os.path.abspath(target))
            if os.path.isfile(target) else os.path.abspath(target))
    options = SCAOptions(
        include_dev=args.include_dev,
        range_policy=args.range_policy,
        exclude=tuple(args.exclude),
        ecosystems=tuple(args.ecosystem),
        verbose=False,
        deb_roots=tuple(args.deb_root or ()),
        deb_status=tuple(args.deb_status or ()),
        deb_files=tuple(args.deb or ()),
        deb_suite=getattr(args, "deb_suite", "") or "",
    )
    inventory = collect_inventory(root, options)
    metadata = SBOMOptions(
        name=args.name or "", component_version=args.component_version or "",
        sign_key=sign_key, sign_key_id=getattr(args, "sign_key_id", "") or "")
    fmt = args.format.lower()
    human = markdown_inventory(root, inventory, metadata) + "\n"
    if fmt == "cyclonedx":
        payload = dumps(cyclonedx_document(root, inventory, metadata))
    elif fmt == "spdx":
        payload = dumps(spdx_document(root, inventory, metadata))
    else:
        payload = human

    if args.output:
        _write_report(args.output, payload)
        if not args.quiet:
            print(f"{len(inventory.unique)} components -> {args.output}", file=sys.stderr)
    else:
        print(payload)
    if args.summary and args.summary != args.output:
        _write_report(args.summary, human)
        if not args.quiet:
            print(f"human-readable inventory -> {args.summary}", file=sys.stderr)
    if not inventory.manifests and not args.quiet:
        print("warning: no supported manifests found; the SBOM has no components",
              file=sys.stderr)
    return EXIT_OK


def command_bench_owasp(args: argparse.Namespace) -> int:
    from .bench.owasp import markdown_report, run_benchmark, write_outputs

    metrics = run_benchmark(
        args.bench_dir,
        engines=tuple(args.engine or ["java"]),
        jobs=max(1, args.jobs),
        cache_path=args.cache,
        sarif_path=args.sarif,
        verbose=not args.quiet,
    )
    if args.output:
        if args.format in ("json",):
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(metrics, handle, indent=2)
            print(f"report -> {args.output}", file=sys.stderr)
        elif args.format in ("md", "markdown"):
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(markdown_report(metrics))
            print(f"report -> {args.output}", file=sys.stderr)
        else:
            json_path, md_path = write_outputs(metrics, os.path.dirname(os.path.abspath(args.output)),
                                               prefix=os.path.basename(args.output))
            print(f"reports -> {json_path}, {md_path}", file=sys.stderr)
    else:
        if args.format in ("json",):
            print(json.dumps(metrics, indent=2))
        else:
            print(markdown_report(metrics))
    summary = metrics["summary"]
    return EXIT_FINDINGS if summary["score_pct"] < args.min_score else EXIT_OK


def command_bench_sca(args: argparse.Namespace) -> int:
    from .bench.sca_bench import run_sca_benchmark

    metrics = run_sca_benchmark(args.fixtures, jobs=max(1, args.jobs), verbose=not args.quiet,
                                cache_path=args.cache, offline=args.offline)
    if args.format == "json":
        payload = json.dumps(metrics, indent=2)
    else:
        from .bench.sca_bench import markdown_report
        payload = markdown_report(metrics)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        print(f"report -> {args.output}", file=sys.stderr)
    else:
        print(payload)
    return EXIT_FINDINGS if metrics["summary"]["score_pct"] < args.min_score else EXIT_OK


def command_db_update(args: argparse.Namespace) -> int:
    from .sca.osv import DEFAULT_DB_ECOSYSTEMS, LocalOSVDB

    database = LocalOSVDB(args.db_dir, verbose=not args.quiet)
    ecosystems = args.ecosystem or list(DEFAULT_DB_ECOSYSTEMS)
    results = database.update(ecosystems)
    failed = 0
    for ecosystem, size, error in results:
        if error:
            failed += 1
            print(f"{ecosystem:14s} failed: {error}", file=sys.stderr)
        else:
            print(f"{ecosystem:14s} {size / 1_048_576:.1f} MiB", file=sys.stderr)
    return EXIT_ERROR if failed else EXIT_OK


def command_db_status(args: argparse.Namespace) -> int:
    from .sca.osv import DB_ECOSYSTEMS, LocalOSVDB

    database = LocalOSVDB(args.db_dir)
    rows = []
    verify = bool(getattr(args, "verify", False))
    verified = 0
    failed = 0
    for ecosystem in DB_ECOSYSTEMS:
        path = database.archive_path(ecosystem)
        if os.path.isfile(path):
            stat = os.stat(path)
            row = {"ecosystem": ecosystem, "archive": path,
                   "size_bytes": stat.st_size, "modified": int(stat.st_mtime)}
            row.update({
                key: value for key, value in database.snapshot(ecosystem).items()
                if key not in ("ecosystem", "archive", "size_bytes")
            })
            if verify:
                result = database.verify(ecosystem)
                row["verified"] = bool(result.get("ok"))
                row["verify_reason"] = result.get("reason", "")
                if result.get("ok"):
                    verified += 1
                else:
                    failed += 1
            rows.append(row)
        else:
            rows.append({"ecosystem": ecosystem, "archive": path, "size_bytes": 0,
                         "modified": 0, "sha256": "", "downloaded_at": ""})
    payload = {"cache_root": cache_root(), "database_dir": database.directory,
               "ecosystems": rows}
    if verify:
        payload["verified"] = verified
        payload["failed"] = failed
    print(json.dumps(payload, indent=2))
    return EXIT_ERROR if failed else EXIT_OK


def command_rules_list(args: argparse.Namespace) -> int:
    from .sast import semgrep_engine
    from .sast.java import catalog

    semgrep_rules = semgrep_engine.list_rules(args.rules)
    java_rules = catalog.rule_catalog()
    if args.format == "json":
        print(json.dumps({"semgrep": semgrep_rules, "java": java_rules}, indent=2))
        return EXIT_OK
    print("# Semgrep rules")
    for rule in semgrep_rules:
        print(f"{rule.get('language', '?'):11s} {rule['id']:42s} {rule.get('severity', ''):8s} "
              f"{rule.get('cwe', '')}")
    print("\n# Java engine rules")
    for rule in java_rules:
        print(f"{rule['cwe']:9s} {rule['rule_id']:42s} {rule['severity']:8s} {rule['title']}")
    return EXIT_OK


def command_cwe(args: argparse.Namespace) -> int:
    from . import cwe

    requested = [str(value) for value in args.ids]
    invalid = [value for value in requested if cwe.normalize_cwe(value) is None]
    if invalid:
        print(f"error: not a CWE identifier: {', '.join(invalid)}", file=sys.stderr)
        return EXIT_ERROR
    entries = cwe.entries_for(requested) if requested else cwe.search(args.search)
    detailed = bool(requested)

    if args.format == "json":
        payload = {"count": len(entries), "entries": [entry.to_dict() for entry in entries]}
        output = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    elif args.format in ("md", "markdown"):
        output = _cwe_markdown(entries, detailed)
    else:
        output = _cwe_text(entries, detailed, args.search)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")
    return EXIT_OK


def _cwe_text(entries: Sequence, detailed: bool, query: str = "") -> str:
    if not entries:
        return f"No CWE entries match {query!r}.\n"
    if not detailed:
        lines = [f"{'CWE':9s} {'Категория':24s} Описание"]
        for entry in entries:
            lines.append(f"{entry.cwe_id:9s} {entry.category:24s} {entry.name_ru}")
        lines.append("")
        lines.append(f"Всего: {len(entries)}. "
                     "Подробности: argus cwe <ID>, поиск: argus cwe --search <текст>.")
        return "\n".join(lines) + "\n"
    blocks: List[str] = []
    for entry in entries:
        blocks.extend([
            f"{entry.cwe_id}  {entry.name}",
            f"  {entry.name_ru}",
            "",
            f"  Категория: {entry.category}",
            f"  Описание: {entry.description}",
            f"  Последствия: {entry.consequences}",
            "  Меры защиты:",
        ])
        blocks.extend(f"    - {item}" for item in entry.mitigations)
        blocks.extend(["", f"  Подробнее: {entry.url}", ""])
    return "\n".join(blocks)


def _cwe_markdown(entries: Sequence, detailed: bool) -> str:
    if not entries:
        return "# CWE reference\n\nНичего не найдено.\n"
    if not detailed:
        lines = ["# CWE reference", "",
                 "| CWE | Категория | Описание |",
                 "| --- | --- | --- |"]
        for entry in entries:
            lines.append(f"| [{entry.cwe_id}]({entry.url}) | {entry.category} | "
                         f"{entry.name_ru} |")
        lines.append("")
        return "\n".join(lines)
    lines = ["# CWE reference", ""]
    for entry in entries:
        lines.extend([
            f"## {entry.cwe_id} — {entry.name_ru}",
            "",
            f"* Официальное название: {entry.name}",
            f"* Категория: {entry.category}",
            f"* MITRE: <{entry.url}>",
            "",
            entry.description,
            "",
            f"**Последствия:** {entry.consequences}",
            "",
            "**Меры защиты:**",
        ])
        lines.extend(f"* {item}" for item in entry.mitigations)
        lines.append("")
    return "\n".join(lines)


def command_diff(args: argparse.Namespace) -> int:
    from .baseline import diff_files, render_diff

    diff = diff_files(args.old, args.new, include_suppressed=args.include_suppressed)
    payload = render_diff(diff, args.format)
    if args.output:
        _write_report(args.output, payload)
        if not args.quiet:
            counts = diff.counts
            print(f"new: {counts['new']}, fixed: {counts['fixed']}, "
                  f"unchanged: {counts['unchanged']} -> {args.output}", file=sys.stderr)
    else:
        print(payload, end="")
    if not args.quiet:
        regressions = diff.regressions(args.fail_on)
        if regressions:
            print(f"gate: {len(regressions)} new finding(s) at or above {args.fail_on}",
                  file=sys.stderr)
    return EXIT_FINDINGS if diff.regressions(args.fail_on) else EXIT_OK


def command_vex(args: argparse.Namespace) -> int:
    from . import vex
    from .baseline import load_report

    report = load_report(args.report)
    document = vex.build_from_report(report, author=args.author or "argus")
    payload = vex.render(document)
    if args.output:
        _write_report(args.output, payload)
        if not args.quiet:
            summary = ", ".join(f"{status}: {count}"
                                for status, count in sorted(vex.counts(document).items()))
            print(f"VEX statements: {summary or 'none'} -> {args.output}",
                  file=sys.stderr)
    else:
        print(payload, end="")
    return EXIT_OK


def command_version(args: argparse.Namespace) -> int:
    from .sast import semgrep_engine

    binary = semgrep_engine.find_semgrep()
    print(f"argus {__version__}")
    print(f"python {sys.version.split()[0]}")
    print(f"semgrep {binary or 'not found'}")
    return EXIT_OK


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="SAST + SCA scanner (Java dataflow engine, Semgrep, OSV).",
    )
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="run SAST and SCA together")
    scan.add_argument("target", help="file or directory to scan")
    scan.add_argument("--no-sast", action="store_true", help="skip static analysis")
    scan.add_argument("--no-sca", action="store_true", help="skip dependency analysis")
    _add_sast_arguments(scan)
    _add_sca_arguments(scan)
    _add_output_arguments(scan)
    scan.set_defaults(func=command_scan)

    sast = subparsers.add_parser("sast", help="static analysis only")
    sast.add_argument("target", help="file or directory to scan")
    _add_sast_arguments(sast)
    _add_output_arguments(sast)
    sast.set_defaults(func=command_sast)

    sca = subparsers.add_parser("sca", help="dependency analysis only")
    sca.add_argument("target", help="project directory")
    _add_sca_arguments(sca)
    _add_output_arguments(sca)
    sca.set_defaults(func=command_sca)

    sbom = subparsers.add_parser("sbom", help="generate or verify a CycloneDX/SPDX SBOM")
    sbom.add_argument("target", nargs="?", help="project directory (or a manifest file)")
    sbom.add_argument("--verify", metavar="FILE",
                      help="verify the signature of an existing SBOM and exit")
    sbom.add_argument("-f", "--format", default="cyclonedx",
                      choices=("cyclonedx", "spdx", "md", "markdown"),
                      help="cyclonedx (machine), spdx (machine) or md (human); "
                           "default: cyclonedx")
    sbom.add_argument("-o", "--output", help="write the SBOM to a file instead of stdout")
    sbom.add_argument("--summary", metavar="PATH",
                      help="also write a human-readable Markdown inventory to PATH")
    sbom.add_argument("--name", help="project name for the SBOM document")
    sbom.add_argument("--component-version", help="project version for the SBOM document")
    sbom.add_argument("--sign-key", metavar="KEY",
                      help="HMAC key used to sign the SBOM (or set ARGUS_SBOM_KEY)")
    sbom.add_argument("--sign-key-id", metavar="ID",
                      help="identifier recorded next to the signature")
    sbom.add_argument("--include-dev", action="store_true", help="include dev/test dependencies")
    sbom.add_argument("--range-policy", default="min", choices=("min", "skip"),
                      help="how to treat version ranges: resolve the lower bound or skip")
    sbom.add_argument("--exclude", action="append", default=[], metavar="PATH",
                      help="skip manifests whose path matches this glob (repeatable)")
    sbom.add_argument("--ecosystem", action="append", default=[], metavar="NAME",
                      help="restrict to an ecosystem (repeatable)")
    _add_debian_arguments(sbom)
    sbom.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages")
    sbom.add_argument("--config", metavar="PATH",
                      help="project configuration (argus.toml / argus.json)")
    sbom.set_defaults(func=command_sbom)

    diff = subparsers.add_parser("diff", help="compare two JSON reports")
    diff.add_argument("old", metavar="OLD", help="older JSON report")
    diff.add_argument("new", metavar="NEW", help="newer JSON report")
    diff.add_argument("-f", "--format", default="text",
                      choices=("text", "md", "markdown", "json"),
                      help="text (default), markdown or json")
    diff.add_argument("-o", "--output", help="write the diff to a file instead of stdout")
    diff.add_argument("--fail-on", default="high", choices=_FAIL_ON_CHOICES,
                      help="exit 1 when a new finding at/above this severity exists")
    diff.add_argument("--include-suppressed", action="store_true",
                      help="compare suppressed findings too")
    diff.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages")
    diff.add_argument("--config", metavar="PATH",
                      help="project configuration (argus.toml / argus.json)")
    diff.set_defaults(func=command_diff)

    vex_parser = subparsers.add_parser(
        "vex", help="export SCA findings from a JSON report as OpenVEX")
    vex_parser.add_argument("report", metavar="REPORT", help="argus JSON report")
    vex_parser.add_argument("-o", "--output", help="write the VEX document to a file")
    vex_parser.add_argument("--author", help="VEX author name (default: argus)")
    vex_parser.add_argument("-q", "--quiet", action="store_true",
                            help="suppress progress messages")
    vex_parser.add_argument("--config", metavar="PATH",
                            help="project configuration (argus.toml / argus.json)")
    vex_parser.set_defaults(func=command_vex)

    bench = subparsers.add_parser("bench", help="benchmark harnesses")
    bench_sub = bench.add_subparsers(dest="bench_command")

    owasp = bench_sub.add_parser("owasp", help="score an engine against OWASP Benchmark")
    owasp.add_argument("--bench-dir", default="benchmarks/owasp-benchmark",
                       help="where the BenchmarkJava checkout lives (cloned on demand)")
    owasp.add_argument("--engine", action="append", default=None,
                       choices=("java", "semgrep"),
                       help="engine(s) to score (repeatable, default: java)")
    owasp.add_argument("--sarif", help="score an external SARIF report instead of a built-in engine")
    owasp.add_argument("-j", "--jobs", type=int, default=4)
    owasp.add_argument("--cache", help="per-file findings cache (invalidated on engine changes)")
    owasp.add_argument("--min-score", type=float, default=0.0,
                       help="exit 1 when the score is below this value")
    owasp.add_argument("-f", "--format", default="text", choices=("text", "md", "markdown", "json"))
    owasp.add_argument("-o", "--output")
    owasp.add_argument("-q", "--quiet", action="store_true")
    owasp.set_defaults(func=command_bench_owasp)

    sca_bench = bench_sub.add_parser("sca", help="score the SCA engine against fixtures")
    sca_bench.add_argument("--fixtures", default="benchmarks/sca/fixtures",
                           help="fixture directory (each child has expected.json)")
    sca_bench.add_argument("-j", "--jobs", type=int, default=1)
    sca_bench.add_argument("--cache", help="OSV query cache path")
    sca_bench.add_argument("--offline", action="store_true")
    sca_bench.add_argument("--min-score", type=float, default=0.0)
    sca_bench.add_argument("-f", "--format", default="text", choices=("text", "md", "json"))
    sca_bench.add_argument("-o", "--output")
    sca_bench.add_argument("-q", "--quiet", action="store_true")
    sca_bench.set_defaults(func=command_bench_sca)

    db = subparsers.add_parser("db", help="offline OSV database management")
    db_sub = db.add_subparsers(dest="db_command")
    db_update = db_sub.add_parser("update", help="download per-ecosystem OSV archives")
    db_update.add_argument("--ecosystem", action="append", default=[])
    db_update.add_argument("--db-dir")
    db_update.add_argument("-q", "--quiet", action="store_true")
    db_update.set_defaults(func=command_db_update)
    db_status = db_sub.add_parser("status", help="show local cache contents")
    db_status.add_argument("--db-dir")
    db_status.add_argument("--verify", action="store_true",
                           help="recompute each archive SHA-256 and compare with the snapshot")
    db_status.set_defaults(func=command_db_status)

    rules = subparsers.add_parser("rules", help="rule management")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rules_list = rules_sub.add_parser("list", help="list bundled rules")
    rules_list.add_argument("--rules", help="external Semgrep rule directory")
    rules_list.add_argument("-f", "--format", default="text", choices=("text", "json"))
    rules_list.set_defaults(func=command_rules_list)

    cwe_parser = subparsers.add_parser("cwe", help="browse the built-in CWE reference")
    cwe_parser.add_argument("ids", nargs="*", metavar="ID",
                            help="CWE identifier(s), e.g. 79 or CWE-89")
    cwe_parser.add_argument("--search", default="", metavar="TEXT",
                            help="filter by number, name, category or description")
    cwe_parser.add_argument("-f", "--format", default="text",
                            choices=("text", "md", "markdown", "json"),
                            help="text (default), markdown or json")
    cwe_parser.add_argument("-o", "--output", help="write the reference to a file")
    cwe_parser.set_defaults(func=command_cwe)

    version = subparsers.add_parser("version", help="print tool and backend versions")
    version.set_defaults(func=command_version)

    return parser


def _subparser(parser: argparse.ArgumentParser,
               command: str) -> Optional[argparse.ArgumentParser]:
    """Return the subparser for ``command`` (used to install config defaults)."""
    for action in parser._actions:  # noqa: SLF001 - argparse has no public API
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(command)
    return None


def _early_parse(parser: argparse.ArgumentParser,
                 argv: Sequence[str]) -> Optional[argparse.Namespace]:
    """Parse enough to find ``--config`` and the target without failing hard."""
    try:
        return parser.parse_known_args(list(argv))[0]
    except SystemExit:
        return None


def _load_config(parser: argparse.ArgumentParser,
                 argv: Sequence[str]) -> tuple:
    """Find and install configuration defaults before the real parse."""
    pre = _early_parse(parser, argv)
    if pre is None:
        return None, None
    command = getattr(pre, "command", None)
    if command not in ("scan", "sast", "sca", "sbom", "diff"):
        return None, command
    start = (getattr(pre, "target", None) or getattr(pre, "old", None)
             or os.getcwd())
    loaded = config_module.find(start=start, explicit=getattr(pre, "config", None))
    if loaded is None:
        return None, command
    subparser = _subparser(parser, command)
    if subparser is not None:
        for key, value in config_module.argparse_defaults(loaded, command).items():
            subparser.set_defaults(**{key: value})
    return loaded, command


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        config, _command = _load_config(parser, raw_argv)
    except config_module.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    args = parser.parse_args(raw_argv)
    args.config_obj = config
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    if args.command == "bench" and not getattr(args, "bench_command", None):
        parser.parse_args(["bench", "--help"])
        return EXIT_OK
    if args.command == "db" and not getattr(args, "db_command", None):
        parser.parse_args(["db", "--help"])
        return EXIT_OK
    if args.command == "rules" and not getattr(args, "rules_command", None):
        parser.parse_args(["rules", "--help"])
        return EXIT_OK
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
