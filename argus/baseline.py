"""Baseline files and report comparison.

A baseline stores the stable identity of every finding that a team has already
seen and accepted.  On the next run argus marks findings as ``new`` or
``existing``; ``--fail-on-new`` can then block a pipeline only on regressions.

The stable key deliberately ignores line numbers for SAST findings.  A code
change above a vulnerable line should not make the issue look new: the key is
``kind + rule + file + message``.  SCA findings use
``kind + advisory + package + version`` so upgrading a dependency produces a
fixed entry and a new vulnerable version produces a new one.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .models import TOOL_NAME, TOOL_VERSION, Finding, ScanResult, Severity, parse_severity

BASELINE_VERSION = 1


def _normalise_message(value: Any) -> str:
    return " ".join(str(value or "").split()).lower()


def stable_key_fields(kind: Any, rule_id: Any, file: Any = "", package: Any = "",
                      version: Any = "", message: Any = "", title: Any = "") -> str:
    """Compute a line-independent identity from plain finding fields."""
    kind_text = str(kind or "")
    if kind_text == "sca":
        return "sca|{}|{}|{}".format(
            str(rule_id or ""), str(package or "").lower(), str(version or ""))
    text = _normalise_message(message) or _normalise_message(title)
    return "{}|{}|{}|{}".format(
        kind_text, str(rule_id or ""),
        str(file or "").replace(os.sep, "/"), text)


def stable_key(finding: Finding) -> str:
    """Stable identity of a :class:`Finding` object."""
    return stable_key_fields(
        finding.kind, finding.rule_id, finding.file, finding.package,
        finding.version, finding.message, finding.title)


def stable_key_dict(finding: Mapping[str, Any]) -> str:
    """Stable identity of a finding loaded from JSON."""
    package = finding.get("package") or {}
    location = finding.get("location") or {}
    return stable_key_fields(
        finding.get("kind"), finding.get("rule_id"), location.get("file"),
        package.get("name"), package.get("version"),
        finding.get("message"), finding.get("title"))


# --------------------------------------------------------------------------- model


@dataclasses.dataclass
class Baseline:
    """An loaded baseline file."""

    path: str = ""
    keys: Dict[str, Dict[str, Any]] = dataclasses.field(default_factory=dict)
    created_at: str = ""
    target: str = ""
    tool: str = ""

    @property
    def count(self) -> int:
        return len(self.keys)

    def contains(self, finding: Any) -> bool:
        key = stable_key(finding) if isinstance(finding, Finding) else stable_key_dict(finding)
        return key in self.keys

    def entry(self, finding: Any) -> Optional[Dict[str, Any]]:
        key = stable_key(finding) if isinstance(finding, Finding) else stable_key_dict(finding)
        return self.keys.get(key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": BASELINE_VERSION,
            "created_at": self.created_at,
            "target": self.target,
            "tool": self.tool or f"{TOOL_NAME} {TOOL_VERSION}",
            "count": self.count,
            "entries": self.keys,
        }


def _entry(finding: Finding) -> Dict[str, Any]:
    return {
        "kind": finding.kind,
        "rule_id": finding.rule_id,
        "file": finding.file,
        "start_line": finding.start_line,
        "package": finding.package,
        "version": finding.version,
        "severity": finding.severity.value,
        "message": (finding.message or finding.title)[:500],
    }


def build(findings: Iterable[Finding], target: str = "") -> Baseline:
    """Build a baseline object from findings, preserving the first occurrence."""
    keys: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        keys.setdefault(stable_key(finding), _entry(finding))
    return Baseline(
        keys=keys,
        created_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        target=target,
        tool=f"{TOOL_NAME} {TOOL_VERSION}",
    )


def load(path: str) -> Baseline:
    """Load a baseline file.

    Both the current ``entries`` mapping and a plain ``keys`` list are
    accepted, which keeps old handwritten baselines working.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"baseline file not found: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{path}: baseline must be a JSON object")
    keys: Dict[str, Dict[str, Any]] = {}
    entries = payload.get("entries")
    if isinstance(entries, Mapping):
        for key, value in entries.items():
            keys[str(key)] = dict(value) if isinstance(value, Mapping) else {}
    raw_keys = payload.get("keys")
    if isinstance(raw_keys, Sequence) and not isinstance(raw_keys, (str, bytes)):
        for key in raw_keys:
            keys.setdefault(str(key), {})
    return Baseline(
        path=os.path.abspath(path),
        keys=keys,
        created_at=str(payload.get("created_at") or ""),
        target=str(payload.get("target") or ""),
        tool=str(payload.get("tool") or ""),
    )


def write(path: str, findings: Iterable[Finding], target: str = "") -> Baseline:
    """Write a baseline file and return the written object."""
    baseline = build(findings, target=target)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(baseline.to_dict(), handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    baseline.path = os.path.abspath(path)
    return baseline


def apply(findings: Iterable[Finding], baseline: Baseline) -> Dict[str, int]:
    """Mark findings as ``new`` or ``existing`` in place."""
    counts = {"new": 0, "existing": 0}
    for finding in findings:
        if baseline.contains(finding):
            finding.baseline = "existing"
            counts["existing"] += 1
        else:
            finding.baseline = "new"
            counts["new"] += 1
    return counts


# --------------------------------------------------------------------------- diff


@dataclasses.dataclass
class ReportDiff:
    """Difference between two JSON reports."""

    old_path: str = ""
    new_path: str = ""
    new: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    fixed: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    unchanged: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    changed: List[Tuple[Dict[str, Any], Dict[str, Any]]] = dataclasses.field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "unchanged": len(self.unchanged),
            "changed": len(self.changed),
        }

    def regressions(self, fail_on: str = "high") -> List[Dict[str, Any]]:
        if str(fail_on).lower() == "none":
            return []
        threshold = parse_severity(fail_on)
        return [finding for finding in self.new
                if parse_severity(finding.get("severity")).rank >= threshold.rank]


def load_report(path: str) -> Dict[str, Any]:
    """Load an argus JSON report and validate its basic shape."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"report not found: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{path}: report must be a JSON object")
    if not isinstance(payload.get("findings"), list):
        raise ValueError(f"{path}: report has no findings array")
    return dict(payload)


def _active(findings: Iterable[Mapping[str, Any]], include_suppressed: bool) -> List[Dict[str, Any]]:
    result = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if finding.get("suppressed") and not include_suppressed:
            continue
        result.append(dict(finding))
    return result


def diff_reports(old: Mapping[str, Any], new: Mapping[str, Any],
                 include_suppressed: bool = False,
                 old_path: str = "", new_path: str = "") -> ReportDiff:
    """Compare two loaded reports by stable finding identity."""
    old_by_key: Dict[str, Dict[str, Any]] = {}
    for finding in _active(old.get("findings") or [], include_suppressed):
        old_by_key.setdefault(stable_key_dict(finding), finding)
    new_by_key: Dict[str, Dict[str, Any]] = {}
    for finding in _active(new.get("findings") or [], include_suppressed):
        new_by_key.setdefault(stable_key_dict(finding), finding)

    diff = ReportDiff(old_path=old_path, new_path=new_path)
    for key, finding in new_by_key.items():
        if key not in old_by_key:
            diff.new.append(finding)
    for key, finding in old_by_key.items():
        if key not in new_by_key:
            diff.fixed.append(finding)
        else:
            current = new_by_key[key]
            diff.unchanged.append(current)
            if str(finding.get("severity")) != str(current.get("severity")):
                diff.changed.append((finding, current))

    def sort_key(finding: Mapping[str, Any]):
        package = finding.get("package") or {}
        location = finding.get("location") or {}
        return (-parse_severity(finding.get("severity")).rank,
                str(finding.get("rule_id") or ""),
                str(package.get("name") or location.get("file") or ""),
                str(package.get("version") or ""))

    diff.new.sort(key=sort_key)
    diff.fixed.sort(key=sort_key)
    diff.unchanged.sort(key=sort_key)
    return diff


def diff_files(old_path: str, new_path: str,
               include_suppressed: bool = False) -> ReportDiff:
    return diff_reports(load_report(old_path), load_report(new_path),
                        include_suppressed=include_suppressed,
                        old_path=old_path, new_path=new_path)


# --------------------------------------------------------------------------- rendering


def _location(finding: Mapping[str, Any]) -> str:
    package = finding.get("package") or {}
    if finding.get("kind") == "sca" or package:
        return f"{package.get('name', '')} {package.get('version', '')}".strip() or "-"
    location = finding.get("location") or {}
    file = location.get("file") or "-"
    line = location.get("start_line")
    return f"{file}:{line}" if line else str(file)


def _label(finding: Mapping[str, Any]) -> str:
    severity = str(finding.get("severity") or "unknown").upper()
    rule = str(finding.get("rule_id") or "")
    message = str(finding.get("message") or finding.get("title") or "").strip()
    message = " ".join(message.split())
    if len(message) > 160:
        message = message[:157] + "..."
    return f"{severity:9s} {rule:24s} {_location(finding):36s} {message}"


def diff_to_dict(diff: ReportDiff) -> Dict[str, Any]:
    return {
        "old": diff.old_path,
        "new": diff.new_path,
        "counts": diff.counts,
        "new_findings": diff.new,
        "fixed_findings": diff.fixed,
        "unchanged_findings": diff.unchanged,
        "severity_changes": [
            {
                "rule_id": current.get("rule_id"),
                "location": _location(current),
                "old_severity": previous.get("severity"),
                "new_severity": current.get("severity"),
            }
            for previous, current in diff.changed
        ],
    }


def render_diff(diff: ReportDiff, fmt: str = "text") -> str:
    """Render a diff as text, Markdown or JSON."""
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return json.dumps(diff_to_dict(diff), indent=2, ensure_ascii=False) + "\n"
    if fmt in ("md", "markdown"):
        return _diff_markdown(diff)

    counts = diff.counts
    lines = [
        f"argus diff: {diff.old_path or 'old'} -> {diff.new_path or 'new'}",
        f"new: {counts['new']}  fixed: {counts['fixed']}  "
        f"unchanged: {counts['unchanged']}  severity changes: {counts['changed']}",
        "",
    ]
    sections = (("NEW", diff.new), ("FIXED", diff.fixed))
    for title, items in sections:
        lines.append(f"{title} ({len(items)})")
        if not items:
            lines.append("  -")
        for finding in items:
            lines.append("  " + _label(finding))
        lines.append("")
    if diff.changed:
        lines.append(f"SEVERITY CHANGED ({len(diff.changed)})")
        for previous, current in diff.changed:
            lines.append(f"  {current.get('rule_id')} {_location(current)}: "
                         f"{previous.get('severity')} -> {current.get('severity')}")
        lines.append("")
    return "\n".join(lines)


def _diff_markdown(diff: ReportDiff) -> str:
    counts = diff.counts
    lines = [
        "# argus report diff",
        "",
        f"* Old: `{diff.old_path or '-'}`",
        f"* New: `{diff.new_path or '-'}`",
        f"* New findings: **{counts['new']}**",
        f"* Fixed: **{counts['fixed']}**",
        f"* Unchanged: {counts['unchanged']}",
        "",
    ]
    for title, items in (("New findings", diff.new), ("Fixed findings", diff.fixed)):
        lines.extend([f"## {title}", ""])
        if not items:
            lines.extend(["None.", ""])
            continue
        lines.extend([
            "| Severity | Rule | Location | Message |",
            "| --- | --- | --- | --- |",
        ])
        for finding in items:
            message = str(finding.get("message") or finding.get("title") or "")
            message = message.replace("|", "\\|").replace("\n", " ")[:200]
            lines.append(
                f"| {finding.get('severity', '')} | `{finding.get('rule_id', '')}` | "
                f"`{_location(finding)}` | {message} |")
        lines.append("")
    if diff.changed:
        lines.extend([
            "## Severity changed", "",
            "| Rule | Location | Old | New |",
            "| --- | --- | --- | --- |",
        ])
        for previous, current in diff.changed:
            lines.append(f"| `{current.get('rule_id', '')}` | `{_location(current)}` | "
                         f"{previous.get('severity', '')} | {current.get('severity', '')} |")
        lines.append("")
    return "\n".join(lines)


def baseline_from_result(result: ScanResult) -> Baseline:
    """Convenience helper used by the CLI and tests."""
    return build(result.findings, target=result.target)


def severity_rank(value: Any) -> int:
    return parse_severity(value).rank


__all__ = [
    "BASELINE_VERSION",
    "Baseline",
    "ReportDiff",
    "apply",
    "baseline_from_result",
    "build",
    "diff_files",
    "diff_reports",
    "diff_to_dict",
    "load",
    "load_report",
    "render_diff",
    "stable_key",
    "stable_key_dict",
    "stable_key_fields",
    "write",
]
