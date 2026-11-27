"""Report writers: JSON, SARIF 2.1.0 and human readable text."""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, List, Optional

from ..models import TOOL_NAME, TOOL_URL, TOOL_VERSION, Finding, ScanResult, Severity
from ..sca.graph import render_tree_from_data


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _visible(result: ScanResult) -> List[Finding]:
    """Findings included in human/SARIF reports by default.

    Suppressed findings stay in JSON (with their reason) but are hidden from
    reports unless ``include_suppressed`` is set on the result stats.
    """
    include = bool(result.stats.get("include_suppressed"))
    return [finding for finding in result.findings
            if include or not finding.suppressed]


def _finding_fix(finding: Finding) -> str:
    """One-line remediation summary for compact tables.

    A rule's suggested replacement wins over the generic remediation hint: it
    is concrete code, while the hint only names the class of the fix.
    """
    if finding.suggested_fix:
        return " ".join(finding.suggested_fix.split())
    if not finding.remediation:
        return ""
    if finding.kind == "sca":
        command = finding.remediation[0]
        return command
    return finding.remediation[0]


def _severity_by_purl(findings: List[Finding]) -> Dict[str, str]:
    """Highest severity per package PURL, used to annotate the dependency tree."""
    result: Dict[str, str] = {}
    for finding in findings:
        if finding.kind != "sca" or not finding.purl:
            continue
        existing = result.get(finding.purl)
        if existing is None or finding.severity.rank > Severity(existing).rank:
            result[finding.purl] = finding.severity.value
    return result


def _dependency_tree(result: ScanResult, max_lines: int = 200) -> str:
    data = result.stats.get("dependency_graph") or {}
    if not isinstance(data, dict):
        return ""
    return render_tree_from_data(data, max_lines=max_lines,
                                 severity_by_purl=_severity_by_purl(result.findings))


def json_report(result: ScanResult) -> Dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/argus-report-1.1.json",
        "schema_version": "1.1",
        "generated_at": _timestamp(),
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "url": TOOL_URL,
            "engines": list(dict.fromkeys(result.engines)),
        },
        "target": result.target,
        "summary": result.summary(),
        "stats": result.stats,
        "findings": [f.to_dict() for f in result.findings],
        "errors": [e.to_dict() for e in result.errors],
    }


# --------------------------------------------------------------------------- SARIF

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.UNKNOWN: "note",
}

_SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
    Severity.UNKNOWN: "0.0",
}


def _rule(finding: Finding) -> Dict[str, Any]:
    tags = ["security"]
    if finding.cwe:
        tags.append(finding.cwe.lower().replace("cwe-", "cwe/"))
    for category in finding.owasp:
        tags.append(f"owasp/{category.label.lower().replace(':', '-')}")
    rule: Dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("-", "_"),
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
        "properties": {
            "tags": tags,
            "precision": finding.confidence,
            "security-severity": _SARIF_SECURITY_SEVERITY[finding.severity],
            "kind": finding.kind,
        },
    }
    if finding.description:
        rule["fullDescription"] = {"text": finding.description}
    if finding.references:
        rule["helpUri"] = finding.references[0]
        rule["help"] = {"text": finding.description or finding.title, "markdown": finding.description or finding.title}
    return rule


def sarif_report(result: ScanResult, root: str) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []
    for finding in result.findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule(finding))
        phys: Dict[str, Any] = {
            "artifactLocation": {
                "uri": finding.file or "",
                "uriBaseId": "%SRCROOT%",
            }
        }
        snippet_start = finding.snippet_start or finding.start_line
        if snippet_start:
            region: Dict[str, Any] = {"startLine": snippet_start}
            if finding.start_line and snippet_start == finding.start_line and finding.start_col:
                region["startColumn"] = max(1, finding.start_col)
            if finding.end_line and snippet_start == finding.start_line:
                region["endLine"] = max(finding.end_line, finding.start_line)
            if (finding.end_col and snippet_start == finding.start_line
                    and finding.end_line == finding.start_line):
                region["endColumn"] = max(finding.end_col, finding.start_col + 1)
            if finding.snippet:
                region["snippet"] = {"text": "\n".join(finding.snippet)}
                region["contextRegion"] = {
                    "startLine": snippet_start,
                    "endLine": snippet_start + len(finding.snippet) - 1,
                    "snippet": {"text": "\n".join(finding.snippet)},
                }
            phys["region"] = region
        sarif_result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message or finding.title},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {
                "argus/v1": finding.fingerprint,
                "argus/stable": finding.stable_key,
            },
            "properties": {
                "kind": finding.kind,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
            },
        }
        if finding.baseline:
            sarif_result["baselineState"] = (
                "new" if finding.baseline == "new" else "unchanged")
        if finding.suppressed:
            justification = str(
                (finding.suppression or {}).get("reason")
                or (finding.suppression or {}).get("justification")
                or "suppressed by project policy")
            sarif_result["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": justification,
            }]
        if finding.cwe:
            sarif_result["properties"]["cwe"] = finding.cwe
        if finding.cwe_name:
            sarif_result["properties"]["cwe_name"] = finding.cwe_name
        if finding.owasp:
            sarif_result["properties"]["owasp"] = [
                category.label for category in finding.owasp]
            sarif_result["properties"]["owasp_name"] = [
                category.name for category in finding.owasp]
            first_url = next((category.url for category in finding.owasp
                              if category.url), "")
            if first_url:
                sarif_result["properties"]["owasp_url"] = first_url
        if finding.remediation:
            sarif_result["properties"]["remediation"] = list(finding.remediation)
        if finding.suggested_fix and finding.start_line:
            # SARIF "fixes" are a proposal, not an instruction: consumers such
            # as GitHub code scanning show the replacement for review.
            deleted: Dict[str, Any] = {"startLine": finding.start_line}
            if finding.start_col:
                deleted["startColumn"] = max(1, finding.start_col)
            if finding.end_line:
                deleted["endLine"] = max(finding.end_line, finding.start_line)
            if (finding.end_col and finding.end_col > finding.start_col
                    and finding.end_line == finding.start_line):
                deleted["endColumn"] = finding.end_col
            sarif_result["fixes"] = [{
                "description": {"text": "Suggested replacement; review before applying."},
                "artifactChanges": [{
                    "artifactLocation": {
                        "uri": finding.file or "",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "replacements": [{
                        "deletedRegion": deleted,
                        "insertedContent": {"text": finding.suggested_fix},
                    }],
                }],
            }]
        if finding.kind == "sca":
            sarif_result["properties"].update(
                {
                    "package": finding.package,
                    "version": finding.version,
                    "fixed_version": finding.fixed_version,
                }
            )
            if finding.purl:
                sarif_result["properties"]["purl"] = finding.purl
            for key in ("epss", "epss_percentile", "epss_cve"):
                if key in finding.metadata:
                    sarif_result["properties"][key] = finding.metadata[key]
            if finding.metadata.get("kev"):
                sarif_result["properties"]["kev"] = True
                for key in ("kev_cve", "kev_ransomware", "kev_due_date",
                            "kev_date_added"):
                    if key in finding.metadata:
                        sarif_result["properties"][key] = finding.metadata[key]
        if finding.aliases:
            sarif_result["properties"]["aliases"] = finding.aliases
        results.append(sarif_result)

    base_uri = "file://" + os.path.abspath(root).replace(os.sep, "/")
    if not base_uri.endswith("/"):
        base_uri += "/"
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URL,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": base_uri}},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _timestamp(),
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": f"{e.scanner}: {e.message}"},
                            }
                            for e in result.errors
                        ],
                    }
                ],
                "results": results,
            }
        ],
    }


# --------------------------------------------------------------------------- text

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[0;36m",
    Severity.INFO: "\033[0;37m",
    Severity.UNKNOWN: "\033[0;37m",
}
_RESET = "\033[0m"


def text_report(result: ScanResult, color: bool = False, max_items: int = 0) -> str:
    def paint(severity: Severity, text: str) -> str:
        if not color:
            return text
        return f"{_COLORS[severity]}{text}{_RESET}"

    lines: List[str] = []
    visible = _visible(result)
    findings = visible if not max_items else visible[:max_items]
    for finding in findings:
        marker = " [new]" if finding.baseline == "new" else ""
        head = f"{paint(finding.severity, finding.severity.value.upper()):<18} {finding.rule_id}{marker}"
        lines.append(head)
        if finding.kind == "sca":
            lines.append(f"    package: {finding.package} {finding.version}"
                        + (f" (fixed in {finding.fixed_version})" if finding.fixed_version else ""))
        lines.append(f"    at: {finding.location or '-'}")
        if finding.cwe:
            named = finding.cwe_name and finding.cwe_name != finding.cwe
            label = f" ({finding.cwe_name})" if named else ""
            lines.append(f"    cwe: {finding.cwe}{label}")
        if finding.owasp:
            lines.append("    owasp: " + ", ".join(
                category.display for category in finding.owasp))
        message = (finding.message or finding.title).strip().replace("\n", " ")
        if len(message) > 400:
            message = message[:397] + "..."
        lines.append(f"    {message}")
        if finding.snippet:
            start = finding.snippet_start or max(1, finding.start_line)
            for offset, code_line in enumerate(finding.snippet):
                number = start + offset
                arrow = ">" if number == finding.start_line else " "
                lines.append(f"    {arrow} {number:>5} | {code_line}")
        if finding.suggested_fix:
            lines.append("    suggested fix (not applied):")
            for fix_line in finding.suggested_fix.splitlines():
                lines.append(f"      {fix_line}")
        if finding.remediation:
            lines.append(f"    fix: {finding.remediation[0]}")
        lines.append("")

    if len(visible) > len(findings):
        lines.append(f"... {len(visible) - len(findings)} more findings (see JSON/SARIF report)")
        lines.append("")

    tree = _dependency_tree(result)
    if tree:
        lines.append("Dependency tree:")
        lines.append(tree)
        lines.append("")

    summary = result.summary()
    counts = summary["by_severity"]
    parts = [f"{name}: {counts[name]}" for name in ("critical", "high", "medium", "low", "info")]
    extra = f", suppressed: {summary['suppressed']}" if summary.get("suppressed") else ""
    if summary.get("new"):
        extra += f", new: {summary['new']}"
    lines.append("Summary: " + ", ".join(parts)
                 + f", total: {summary['total']}{extra}")
    if summary.get("by_owasp"):
        edition = summary.get("owasp_version") or ""
        lines.append(f"OWASP Top 10 {edition}: " + ", ".join(
            f"{label} ×{count}" for label, count in summary["by_owasp"].items()))
    for error in result.errors:
        lines.append(f"warning [{error.scanner}] {error.message}")
    return "\n".join(lines)


def _md_cell(value: Any, limit: int = 0) -> str:
    """Escape a value for a Markdown table cell."""
    text = str(value if value is not None else "")
    text = text.replace("\r", " ").replace("\n", " ").strip()
    if limit and len(text) > limit:
        text = text[: max(0, limit - 3)] + "..."
    return text.replace("|", "\\|")


def _cwe_label(finding: Finding) -> str:
    """Compact ``CWE-89 SQL Injection`` label for report tables."""
    if not finding.cwe:
        return ""
    if finding.cwe_name:
        return f"{finding.cwe} {finding.cwe_name}"
    return finding.cwe


def _owasp_label(finding: Finding) -> str:
    """Compact ``A03:2021`` list for report tables."""
    return ", ".join(category.label for category in finding.owasp)


def _epss_label(finding: Finding) -> str:
    """``0.421 (97%)`` — EPSS probability and percentile, when available."""
    score = finding.metadata.get("epss")
    if score is None:
        return "-"
    percentile = finding.metadata.get("epss_percentile")
    if percentile is None:
        return f"{float(score):.3f}"
    return f"{float(score):.3f} ({float(percentile) * 100:.0f}%)"


def _kev_label(finding: Finding) -> str:
    if not finding.metadata.get("kev"):
        return "-"
    if finding.metadata.get("kev_ransomware"):
        return "yes (ransomware)"
    return "yes"


def markdown_report(result: ScanResult, title: str = "argus report") -> str:
    """Human-readable Markdown report: summary, findings, dependencies, errors."""
    summary = result.summary()
    by_severity = summary["by_severity"]
    by_kind = summary["by_kind"]
    lines: List[str] = [
        f"# {title}",
        "",
        f"* Target: `{result.target}`",
        f"* Generated: {_timestamp()}",
        f"* Tool: {TOOL_NAME} {TOOL_VERSION} ({', '.join(result.engines) or 'no engines'})",
        f"* Status: **{summary['status']}** "
        f"({summary['total']} findings, max severity: **{summary['max_severity']}**)",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    gate = result.stats.get("gate") or {}
    if gate:
        state = "passed" if gate.get("passed") else "FAILED"
        lines.insert(6, f"* Quality gate: **{state}**")
    workflow = result.stats.get("workflow") or {}
    if workflow.get("baseline"):
        lines.insert(6, f"* Baseline: `{workflow['baseline']}` "
                        f"({workflow.get('new', 0)} new, "
                        f"{workflow.get('suppressed', 0)} suppressed)")
    threat = result.stats.get("threat_intel") or {}
    if threat:
        lines.insert(6, f"* Threat intel: {threat.get('epss_matches', 0)} EPSS "
                        f"match(es), {threat.get('kev_matches', 0)} KEV match(es)"
                        + (f", {threat['kev_ransomware']} ransomware-linked"
                           if threat.get("kev_ransomware") else ""))
    for name in ("critical", "high", "medium", "low", "info", "unknown"):
        lines.append(f"| {name} | {by_severity.get(name, 0)} |")
    lines.extend([
        f"| **total** | **{summary['total']}** |",
        f"| suppressed | {summary.get('suppressed', 0)} |",
    ])
    if summary.get("new") or summary.get("existing"):
        lines.append(f"| new / existing | {summary.get('new', 0)} / "
                     f"{summary.get('existing', 0)} |")
    lines.extend([
        "",
        "| Area | Count |",
        "| --- | ---: |",
        f"| SAST findings | {by_kind.get('sast', 0)} |",
        f"| SCA findings | {by_kind.get('sca', 0)} |",
        f"| Dependency packages | {summary['packages']} |",
        f"| Direct / transitive / unknown | {summary.get('packages_direct', 0)} / "
        f"{summary.get('packages_transitive', 0)} / {summary.get('packages_unknown', 0)} |",
        f"| Dependency graph | "
        f"{'resolved from lock files' if summary.get('dependency_graph') else 'not resolved'} |",
        f"| Scan errors | {summary['errors']} |",
        "",
    ])
    if summary.get("by_owasp"):
        names = {}
        for finding in result.findings:
            for category in finding.owasp:
                names.setdefault(category.label, category)
        edition = summary.get("owasp_version") or ""
        lines.extend([
            "## OWASP Top 10",
            "",
            f"Edition: **{edition or '—'}**",
            "",
            "| Category | Name | Findings |",
            "| --- | --- | ---: |",
        ])
        for label, count in summary["by_owasp"].items():
            category = names.get(label)
            name = ""
            if category is not None:
                name = category.name_ru or category.name
                if category.url:
                    label = f"[{label}]({category.url})"
            lines.append(f"| {_md_cell(label)} | {_md_cell(name)} | {count} |")
        lines.append("")
    if summary["top_rules"]:
        lines.extend([
            "## Rules that fired",
            "",
            "| Rule | Kind | Severity | Findings |",
            "| --- | --- | --- | ---: |",
        ])
        for entry in summary["top_rules"]:
            lines.append(
                f"| `{_md_cell(entry['rule_id'])}` | {entry['kind']} | "
                f"{entry['severity']} | {entry['count']} |"
            )
        lines.append("")

    visible = _visible(result)
    sast = [finding for finding in visible if finding.kind == "sast"]
    sca = [finding for finding in visible if finding.kind == "sca"]
    if not visible:
        if summary.get("suppressed"):
            lines.extend(["## Findings", "",
                          f"All {summary['suppressed']} finding(s) are suppressed by policy.", ""])
        else:
            lines.extend(["## Findings", "", "No findings.", ""])
    if sast:
        lines.extend([
            "## SAST findings",
            "",
            "| Severity | Rule | CWE | OWASP | Location | Engine | Message |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ])
        for finding in sast:
            rule = _md_cell(finding.rule_id)
            if finding.baseline == "new":
                rule += " **new**"
            lines.append(
                f"| {finding.severity.value} | `{rule}` | {_md_cell(_cwe_label(finding))} | "
                f"{_md_cell(_owasp_label(finding))} | "
                f"`{_md_cell(finding.location or '-')}` | {_md_cell(finding.engine)} | "
                f"{_md_cell(finding.message or finding.title, 200)} |"
            )
        lines.append("")
    if sca:
        lines.extend([
            "## SCA findings",
            "",
            "| Severity | Advisory | CWE | OWASP | EPSS | KEV | Package | Installed | Fixed | Manifest |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ])
        for finding in sca:
            rule = _md_cell(finding.rule_id)
            if finding.baseline == "new":
                rule += " **new**"
            lines.append(
                f"| {finding.severity.value} | `{rule}` | {_md_cell(_cwe_label(finding))} | "
                f"{_md_cell(_owasp_label(finding))} | "
                f"{_epss_label(finding)} | {_kev_label(finding)} | "
                f"{_md_cell(finding.package)} | {_md_cell(finding.version)} | "
                f"{_md_cell(finding.fixed_version or '-')} | "
                f"`{_md_cell(finding.file or '-')}` |"
            )
        lines.append("")

    fixes = [finding for finding in visible
             if finding.remediation or finding.suggested_fix]
    if fixes:
        lines.extend([
            "## Remediation",
            "",
            "| Finding | Where | Suggested fix |",
            "| --- | --- | --- |",
        ])
        for finding in fixes[:60]:
            where = (finding.package or finding.location or "-")
            fix = _md_cell(_finding_fix(finding), 300)
            lines.append(f"| `{_md_cell(finding.rule_id)}` | {_md_cell(where)} | {fix} |")
        if len(fixes) > 60:
            lines.append(f"| ... | | {len(fixes) - 60} more findings with fixes |")
        lines.append("")

    suggested = [finding for finding in visible if finding.suggested_fix]
    if suggested:
        lines.extend([
            "## Suggested fixes",
            "",
            "These replacements are proposals from the rule set. argus never "
            "modifies the scanned sources; apply them manually or with your "
            "own autofix step after review.",
            "",
        ])
        for finding in suggested[:20]:
            lines.extend([
                f"### `{_md_cell(finding.rule_id)}` — "
                f"`{_md_cell(finding.location or '-')}`",
                "",
                "```text",
                finding.suggested_fix,
                "```",
                "",
            ])
        if len(suggested) > 20:
            lines.extend([f"*Suggested fixes shown for the first 20 of "
                          f"{len(suggested)} findings.*", ""])

    snippets = [finding for finding in sast if finding.snippet]
    if snippets:
        lines.extend(["## SAST context", ""])
        for finding in snippets[:20]:
            start = finding.snippet_start or finding.start_line
            lines.extend([
                f"### `{_md_cell(finding.rule_id)}` — `{_md_cell(finding.location or '-')}`",
                "",
                "```text",
            ])
            width = len(str(start + len(finding.snippet)))
            for offset, code_line in enumerate(finding.snippet):
                number = start + offset
                marker = ">" if number == finding.start_line else " "
                lines.append(f"{marker} {number:>{width}} | {code_line}")
            lines.extend(["```", ""])
        if len(snippets) > 20:
            lines.extend([f"*Context shown for the first 20 of {len(snippets)} findings.*", ""])

    suppressed = [finding for finding in result.findings if finding.suppressed]
    if suppressed and result.stats.get("include_suppressed"):
        lines.extend([
            "## Suppressed findings",
            "",
            "| Severity | Rule | Where | Reason | Expires |",
            "| --- | --- | --- | --- | --- |",
        ])
        for finding in suppressed:
            info = finding.suppression or {}
            where = finding.package or finding.location or "-"
            lines.append(
                f"| {finding.severity.value} | `{_md_cell(finding.rule_id)}` | "
                f"{_md_cell(where)} | {_md_cell(info.get('reason') or '-', 160)} | "
                f"{_md_cell(info.get('expires') or '-')} |")
        lines.append("")

    packages = summary["by_ecosystem"]
    if result.stats.get("manifests_scanned") is not None:
        lines.extend([
            "## Dependencies",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Manifests scanned | {result.stats.get('manifests_scanned', 0)} |",
            f"| Package versions | {result.stats.get('packages_total', 0)} |",
            f"| Unique packages | {result.stats.get('packages_unique', 0)} |",
            f"| Direct / transitive / unknown | {result.stats.get('packages_direct', 0)} / "
            f"{result.stats.get('packages_transitive', 0)} / "
            f"{result.stats.get('packages_unknown', 0)} |",
            f"| Skipped dependencies | {result.stats.get('skipped_dependencies', 0)} |",
            "| Ecosystems | "
            + (", ".join(f"{name}: {count}" for name, count in sorted(packages.items())) or "-")
            + " |",
            "",
        ])
        skipped = result.stats.get("skipped_sample") or []
        if skipped:
            lines.append("Skipped dependencies:")
            lines.append("")
            for item in skipped:
                lines.append(f"* `{_md_cell(item.get('name'))}` — "
                             f"{_md_cell(item.get('reason'))} (`{_md_cell(item.get('manifest'))}`)")
            lines.append("")

        tree = _dependency_tree(result)
        if tree:
            lines.extend([
                "## Dependency tree",
                "",
                "```text",
                tree,
                "```",
                "",
            ])

    if result.errors:
        lines.extend(["## Scan errors", ""])
        for error in result.errors:
            lines.append(f"* **{_md_cell(error.scanner)}**"
                         + (f" `{_md_cell(error.file)}`" if error.file else "")
                         + f": {_md_cell(error.message, 500)}")
        lines.append("")
    return "\n".join(lines)


def render(result: ScanResult, fmt: str, root: Optional[str] = None, color: bool = False) -> str:
    fmt = fmt.lower()
    root = root or result.target
    if fmt == "json":
        return json.dumps(json_report(result), indent=2, ensure_ascii=False) + "\n"
    if fmt == "sarif":
        return json.dumps(sarif_report(result, root), indent=2, ensure_ascii=False) + "\n"
    if fmt in ("md", "markdown"):
        return markdown_report(result) + "\n"
    if fmt == "text":
        return text_report(result, color=color) + "\n"
    raise ValueError(f"unknown report format: {fmt!r} (expected json, sarif, md or text)")
