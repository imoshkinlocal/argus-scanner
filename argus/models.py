"""Core data model shared by the SAST and SCA engines."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import os
import posixpath
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "argus"
TOOL_VERSION = "1.1.0"
TOOL_URL = "https://example.invalid/argus"


class Severity(str, enum.Enum):
    """Ordered severity levels used across the tool."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
    Severity.UNKNOWN: 0,
}

_ALIASES = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.UNKNOWN,
    "unknown": Severity.UNKNOWN,
    "": Severity.UNKNOWN,
}


def parse_severity(value: Any, default: Severity = Severity.UNKNOWN) -> Severity:
    """Parse a severity from a string/number in a forgiving way."""
    if isinstance(value, Severity):
        return value
    if isinstance(value, (int, float)):
        return severity_from_cvss(float(value))
    if value is None:
        return default
    text = str(value).strip().lower()
    return _ALIASES.get(text, default)


def severity_from_cvss(score: Optional[float]) -> Severity:
    """Map a CVSS base score to a qualitative severity (CVSS v3 spec)."""
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def normalize_path(path: str, root: str) -> str:
    """Return a stable POSIX-style path relative to the scan root."""
    try:
        absolute = os.path.abspath(path)
        relative = os.path.relpath(absolute, os.path.abspath(root))
    except (OSError, ValueError):
        relative = path
    if relative.startswith(".." + os.sep) or relative == "..":
        relative = os.path.abspath(path)
    return relative.replace(os.sep, "/")


@dataclasses.dataclass
class Finding:
    """A single security issue produced by either engine."""

    rule_id: str
    title: str
    severity: Severity
    kind: str  # "sast" | "sca"
    engine: str  # "argus-java" | "semgrep" | "osv"
    file: str = ""
    start_line: int = 0
    start_col: int = 0
    end_line: int = 0
    end_col: int = 0
    message: str = ""
    description: str = ""
    cwe: str = ""
    cwe_name: str = ""
    cwe_name_ru: str = ""
    confidence: str = "medium"  # low | medium | high
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    purl: str = ""
    licenses: List[str] = dataclasses.field(default_factory=list)
    remediation: List[str] = dataclasses.field(default_factory=list)
    #: "new" | "existing" once a baseline has been applied, empty otherwise.
    baseline: str = ""
    suppressed: bool = False
    suppression: Dict[str, Any] = dataclasses.field(default_factory=dict)
    snippet: List[str] = dataclasses.field(default_factory=list)
    snippet_start: int = 0
    aliases: List[str] = dataclasses.field(default_factory=list)
    references: List[str] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        if self.start_line:
            return f"{self.file}:{self.start_line}"
        return self.file

    @property
    def fingerprint(self) -> str:
        """Stable identity used for deduplication and SARIF partial fingerprints."""
        parts = [self.kind, self.rule_id, self.file, str(self.start_line)]
        if self.kind == "sca":
            parts = [self.kind, self.rule_id, self.package, self.version]
        digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
        return digest[:32]

    @property
    def stable_key(self) -> str:
        """Line-independent identity used by baselines.

        SAST findings keep ``kind + rule + file + message``. SCA findings use
        ``kind + advisory + package + version``. Moving a vulnerable statement
        down the file therefore does not make it look like a regression.
        """
        if self.kind == "sca":
            return "sca|{}|{}|{}".format(
                self.rule_id, self.package.lower(), self.version)
        message = " ".join((self.message or self.title or "").split()).lower()
        return "{}|{}|{}|{}".format(self.kind, self.rule_id, self.file, message)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.fingerprint,
            "kind": self.kind,
            "engine": self.engine,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "message": self.message,
            "cwe": self.cwe,
            "location": {
                "file": self.file,
                "start_line": self.start_line,
                "start_column": self.start_col,
                "end_line": self.end_line,
                "end_column": self.end_col,
            },
        }
        if self.cwe_name:
            payload["cwe_name"] = self.cwe_name
        if self.cwe_name_ru:
            payload["cwe_name_ru"] = self.cwe_name_ru
        if self.description:
            payload["description"] = self.description
        if self.remediation:
            payload["remediation"] = list(self.remediation)
        if self.baseline:
            payload["baseline"] = self.baseline
        if self.suppressed:
            payload["suppressed"] = True
            if self.suppression:
                payload["suppression"] = dict(self.suppression)
        if self.snippet:
            payload["snippet"] = {
                "start_line": self.snippet_start,
                "lines": list(self.snippet),
            }
        if self.kind == "sca" or self.package:
            payload["package"] = {
                "name": self.package,
                "version": self.version,
                "fixed_version": self.fixed_version,
                "purl": self.purl,
            }
            if "direct" in self.metadata:
                payload["package"]["direct"] = self.metadata.get("direct")
            if "depth" in self.metadata:
                payload["package"]["depth"] = self.metadata.get("depth")
            if self.licenses:
                payload["package"]["licenses"] = list(self.licenses)
        if self.aliases:
            payload["aliases"] = list(self.aliases)
        if self.references:
            payload["references"] = list(self.references)
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclasses.dataclass
class ScanError:
    """A non-fatal error encountered while scanning."""

    scanner: str
    message: str
    file: str = ""

    def to_dict(self) -> Dict[str, str]:
        out = {"scanner": self.scanner, "message": self.message}
        if self.file:
            out["file"] = self.file
        return out


@dataclasses.dataclass
class ScanResult:
    """Aggregated output of a scan run."""

    target: str
    findings: List[Finding] = dataclasses.field(default_factory=list)
    errors: List[ScanError] = dataclasses.field(default_factory=list)
    stats: Dict[str, Any] = dataclasses.field(default_factory=dict)
    engines: List[str] = dataclasses.field(default_factory=list)

    def add(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def sort(self) -> None:
        self.findings.sort(
            key=lambda f: (
                -f.severity.rank,
                f.kind,
                f.file,
                f.start_line,
                f.rule_id,
                f.package,
            )
        )

    def active_findings(self) -> List[Finding]:
        """Findings that are not suppressed and therefore reported by default."""
        return [finding for finding in self.findings if not finding.suppressed]

    def counts_by_severity(self, include_suppressed: bool = False) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            if finding.suppressed and not include_suppressed:
                continue
            counts[finding.severity.value] += 1
        return counts

    def counts_by_kind(self, include_suppressed: bool = False) -> Dict[str, int]:
        counts = {"sast": 0, "sca": 0}
        for finding in self.findings:
            if finding.suppressed and not include_suppressed:
                continue
            counts[finding.kind] = counts.get(finding.kind, 0) + 1
        return counts

    def max_severity(self, include_suppressed: bool = False) -> Severity:
        findings = [finding for finding in self.findings
                    if include_suppressed or not finding.suppressed]
        if not findings:
            return Severity.UNKNOWN
        return max((f.severity for f in findings), key=lambda s: s.rank)

    def summary(self) -> Dict[str, Any]:
        active = self.active_findings()
        suppressed = len(self.findings) - len(active)
        by_engine: Dict[str, int] = {}
        rules: Dict[str, Dict[str, Any]] = {}
        for finding in active:
            by_engine[finding.engine] = by_engine.get(finding.engine, 0) + 1
            entry = rules.get(finding.rule_id)
            if entry is None:
                rules[finding.rule_id] = {
                    "rule_id": finding.rule_id,
                    "kind": finding.kind,
                    "severity": finding.severity.value,
                    "count": 1,
                }
            else:
                entry["count"] += 1
                if finding.severity.rank > parse_severity(entry["severity"]).rank:
                    entry["severity"] = finding.severity.value
        top_rules = sorted(
            rules.values(),
            key=lambda item: (-item["count"], -parse_severity(item["severity"]).rank,
                              item["rule_id"]),
        )[:10]
        total = len(active)
        new = sum(1 for finding in active if finding.baseline == "new")
        existing = sum(1 for finding in active if finding.baseline == "existing")
        if total:
            status = "findings"
        elif suppressed:
            status = "suppressed"
        elif self.errors:
            status = "error"
        else:
            status = "clean"
        return {
            "total": total,
            "all": len(self.findings),
            "suppressed": suppressed,
            "new": new,
            "existing": existing,
            "by_severity": self.counts_by_severity(),
            "by_kind": self.counts_by_kind(),
            "by_engine": by_engine,
            "by_ecosystem": dict(self.stats.get("by_ecosystem") or {}),
            "packages": int(self.stats.get("packages_unique") or 0),
            "packages_direct": int(self.stats.get("packages_direct") or 0),
            "packages_transitive": int(self.stats.get("packages_transitive") or 0),
            "packages_unknown": int(self.stats.get("packages_unknown") or 0),
            "dependency_graph": bool((self.stats.get("dependency_graph") or {}).get("resolved")),
            "max_severity": self.max_severity().value,
            "errors": len(self.errors),
            "status": status,
            "top_rules": top_rules,
        }


#: Confidence ordering used when the same finding is produced more than once.
DEDUPE_KEEP_ORDER = ("low", "medium", "high")


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Drop duplicate findings, keeping the highest-confidence instance."""
    best: Dict[Tuple[str, str, str, str], Finding] = {}
    order: List[Tuple[str, str, str, str]] = []
    for finding in findings:
        key = (finding.kind, finding.rule_id, finding.file, str(finding.start_line))
        if finding.kind == "sca":
            key = (finding.kind, finding.rule_id, finding.package, finding.version)
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            order.append(key)
        elif _confidence_rank(finding.confidence) > _confidence_rank(existing.confidence):
            best[key] = finding
    return [best[key] for key in order]


def _confidence_rank(confidence: str) -> int:
    try:
        return DEDUPE_KEEP_ORDER.index(confidence)
    except ValueError:
        return -1


def filter_findings(
    findings: Iterable[Finding],
    min_severity: Severity = Severity.UNKNOWN,
    include_kinds: Optional[Iterable[str]] = None,
) -> List[Finding]:
    kinds = set(include_kinds) if include_kinds else None
    result = []
    for finding in findings:
        if finding.severity.rank < min_severity.rank:
            continue
        if kinds is not None and finding.kind not in kinds:
            continue
        result.append(finding)
    return result


def json_dumps(payload: Any, indent: int = 2) -> str:
    return json.dumps(payload, indent=indent, ensure_ascii=False, sort_keys=False)
