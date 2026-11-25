"""Quality gates and package policies.

Exit codes answer one question: is the result acceptable for this pipeline?
The answer is not only ``--fail-on``.  A project may also cap the number of
findings, allow a small number of high findings while forbidding criticals,
block specific packages or enforce a CVSS ceiling.
"""

from __future__ import annotations

import dataclasses
import fnmatch
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .models import Finding, Severity, parse_severity


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [str(item) for item in value]
    if isinstance(value, Iterable):
        return [str(item) for item in value]
    return [str(value)]


def _match(value: str, pattern: str) -> bool:
    return (fnmatch.fnmatchcase(value, pattern)
            or fnmatch.fnmatchcase(value.lower(), pattern.lower()))


@dataclasses.dataclass
class GatePolicy:
    """Declarative acceptance policy for one scan."""

    fail_on: str = "high"
    fail_on_new: bool = False
    max_total: Optional[int] = None
    max_by_severity: Dict[str, int] = dataclasses.field(default_factory=dict)
    deny_packages: Tuple[str, ...] = ()
    deny_cwes: Tuple[str, ...] = ()
    max_cvss: Optional[float] = None
    deny_licenses: Tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, values: Optional[Mapping[str, Any]],
                     base: Optional["GatePolicy"] = None) -> "GatePolicy":
        policy = dataclasses.replace(base) if base is not None else cls()
        if not values:
            return policy
        if values.get("fail_on") is not None:
            policy.fail_on = str(values["fail_on"])
        if values.get("fail_on_new") is not None:
            policy.fail_on_new = bool(values["fail_on_new"])
        if values.get("max_total") is not None:
            policy.max_total = _as_int(values["max_total"])
        raw_severity = values.get("max_by_severity")
        if isinstance(raw_severity, Mapping):
            policy.max_by_severity = {
                str(key).lower(): int(limit) for key, limit in raw_severity.items()
                if _as_int(limit) is not None
            }
        elif raw_severity is not None:
            policy.max_by_severity = {
                str(key).lower(): limit for key, limit in dict(raw_severity).items()
            }
        if values.get("deny_packages") is not None:
            policy.deny_packages = tuple(_as_list(values["deny_packages"]))
        if values.get("deny_cwes") is not None:
            policy.deny_cwes = tuple(_as_list(values["deny_cwes"]))
        if values.get("max_cvss") is not None:
            policy.max_cvss = _as_float(values["max_cvss"])
        if values.get("deny_licenses") is not None:
            policy.deny_licenses = tuple(_as_list(values["deny_licenses"]))
        return policy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fail_on": self.fail_on,
            "fail_on_new": self.fail_on_new,
            "max_total": self.max_total,
            "max_by_severity": dict(self.max_by_severity),
            "deny_packages": list(self.deny_packages),
            "deny_cwes": list(self.deny_cwes),
            "max_cvss": self.max_cvss,
            "deny_licenses": list(self.deny_licenses),
        }


@dataclasses.dataclass
class GateResult:
    """Outcome of evaluating a :class:`GatePolicy`."""

    policy: GatePolicy
    violations: List[str] = dataclasses.field(default_factory=list)
    counts: Dict[str, int] = dataclasses.field(default_factory=dict)
    considered: int = 0
    new: int = 0

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": list(self.violations),
            "counts": dict(self.counts),
            "considered": self.considered,
            "new": self.new,
            "policy": self.policy.to_dict(),
        }


def _active(findings: Iterable[Finding], fail_on_new: bool) -> List[Finding]:
    result = []
    for finding in findings:
        if finding.suppressed:
            continue
        if fail_on_new and finding.baseline != "new":
            continue
        result.append(finding)
    return result


def _source_rank(finding: Finding) -> int:
    return finding.severity.rank


def evaluate(findings: Iterable[Finding],
             policy: Optional[GatePolicy] = None,
             packages: Optional[Mapping[str, Iterable[str]]] = None) -> GateResult:
    """Evaluate the policy against the findings that remain visible.

    ``packages`` optionally maps a package reference (purl) to its declared
    licences.  It lets the licence policy cover components that have no known
    vulnerability and therefore no finding of their own.
    """
    policy = policy or GatePolicy()
    active = _active(findings, policy.fail_on_new)
    counts = {severity.value: 0 for severity in Severity}
    for finding in active:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    result = GateResult(policy=policy, counts=counts, considered=len(active),
                        new=sum(1 for finding in active if finding.baseline == "new"))

    scope = "new " if policy.fail_on_new else ""
    if policy.fail_on.lower() != "none":
        threshold = parse_severity(policy.fail_on)
        offenders = [finding for finding in active if finding.severity.rank >= threshold.rank]
        if offenders:
            result.violations.append(
                f"{len(offenders)} {scope}finding(s) at or above "
                f"{policy.fail_on} (limit: none)")

    if policy.max_total is not None and len(active) > policy.max_total:
        result.violations.append(
            f"{len(active)} {scope}finding(s) exceed max_total={policy.max_total}")

    for severity_name, limit in policy.max_by_severity.items():
        limit_value = _as_int(limit)
        if limit_value is None:
            continue
        actual = counts.get(severity_name, 0)
        if actual > limit_value:
            result.violations.append(
                f"{actual} {scope}{severity_name} finding(s) exceed "
                f"max_by_severity.{severity_name}={limit_value}")

    if policy.deny_packages:
        for finding in active:
            if not finding.package:
                continue
            candidates = [finding.package, finding.purl,
                          f"{finding.package}@{finding.version}"]
            for pattern in policy.deny_packages:
                if any(candidate and _match(candidate, pattern) for candidate in candidates):
                    result.violations.append(
                        f"denied package {finding.package} {finding.version} "
                        f"matches policy {pattern}")
                    break

    if policy.deny_cwes:
        for finding in active:
            for pattern in policy.deny_cwes:
                if finding.cwe and _match(finding.cwe, pattern):
                    result.violations.append(
                        f"{finding.rule_id} at {finding.location or finding.package} "
                        f"matches denied {finding.cwe}")
                    break

    if policy.deny_licenses:
        seen_license: set = set()
        for finding in active:
            for license_name in finding.licenses:
                if not any(_match(license_name, pattern)
                           for pattern in policy.deny_licenses):
                    continue
                marker = (finding.package or finding.rule_id, license_name)
                if marker in seen_license:
                    continue
                seen_license.add(marker)
                result.violations.append(
                    f"{finding.package or finding.rule_id} uses denied licence "
                    f"{license_name}")
        for reference, licenses in (packages or {}).items():
            for license_name in licenses:
                if not any(_match(license_name, pattern)
                           for pattern in policy.deny_licenses):
                    continue
                marker = (reference, license_name)
                if marker in seen_license:
                    continue
                seen_license.add(marker)
                result.violations.append(
                    f"{reference} uses denied licence {license_name}")

    if policy.max_cvss is not None:
        for finding in active:
            score = _as_float(finding.metadata.get("cvss_score"))
            if score is not None and score >= policy.max_cvss:
                result.violations.append(
                    f"{finding.rule_id} has CVSS {score:g} >= max_cvss={policy.max_cvss:g}")

    # De-duplicate identical messages while preserving order.
    seen: set = set()
    unique: List[str] = []
    for violation in result.violations:
        if violation not in seen:
            seen.add(violation)
            unique.append(violation)
    result.violations = unique
    return result


def format_gate(result: GateResult) -> str:
    """Human-readable one-liner used by the CLI summary."""
    if result.passed:
        return f"quality gate passed ({result.considered} active findings)"
    return "quality gate failed: " + "; ".join(result.violations)


__all__ = ["GatePolicy", "GateResult", "evaluate", "format_gate"]
