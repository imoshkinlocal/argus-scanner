"""VEX (Vulnerability Exploitability eXchange) export in OpenVEX format.

A scan report answers "which advisories affect which component versions".  A
VEX document answers the follow-up question that downstream consumers ask:
"is this project actually affected, and if not, why?".  argus derives the
statements from the same report that drives the quality gate:

* an active SCA finding becomes ``affected``;
* a suppressed finding becomes ``not_affected`` with the suppression reason as
  the justification and the recorded explanation as an impact statement;
* a finding whose installed version is already at or above the published fix
  becomes ``fixed``.

The output follows OpenVEX 0.2.0 and is written as JSON.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .models import ScanResult, TOOL_NAME, TOOL_VERSION

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _document_id() -> str:
    seed = _timestamp() + str(id(object()))
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"https://argus.local/vex/{digest}"


def _version_tuple(value: Any) -> Optional[tuple]:
    """Very small numeric version parser used only to detect an applied fix."""
    text = str(value or "").strip().lstrip("vV")
    if not text:
        return None
    parts: List[int] = []
    for chunk in text.replace("-", ".").split("."):
        digits = "".join(char for char in chunk if char.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def _already_fixed(installed: Any, fixed: Any) -> bool:
    current = _version_tuple(installed)
    target = _version_tuple(fixed)
    if current is None or target is None:
        return False
    length = max(len(current), len(target))
    return current + (0,) * (length - len(current)) >= target + (0,) * (length - len(target))


def _product(finding: Mapping[str, Any]) -> Dict[str, Any]:
    package = finding.get("package") or {}
    purl = str(package.get("purl") or "")
    product: Dict[str, Any] = {"@id": purl or str(package.get("name") or "unknown")}
    if purl:
        product["identifiers"] = {"purl": purl}
    name = str(package.get("name") or "")
    if name:
        product["name"] = name
    version = str(package.get("version") or "")
    if version:
        product["version"] = version
    return product


def _statement(finding: Mapping[str, Any]) -> Dict[str, Any]:
    package = finding.get("package") or {}
    statement: Dict[str, Any] = {
        "vulnerability": {"name": str(finding.get("rule_id") or "")},
        "products": [_product(finding)],
    }
    aliases = [str(alias) for alias in finding.get("aliases") or () if alias]
    if aliases:
        statement["vulnerability"]["aliases"] = aliases

    suppression = finding.get("suppression") or {}
    fixed = package.get("fixed_version") or finding.get("fixed_version")
    installed = package.get("version") or finding.get("version")
    if finding.get("suppressed"):
        statement["status"] = "not_affected"
        reason = str(suppression.get("reason") or suppression.get("justification")
                     or "accepted risk")
        statement["justification"] = "vulnerable_code_not_in_execute_path"
        statement["impact_statement"] = reason
    elif _already_fixed(installed, fixed):
        statement["status"] = "fixed"
        statement["impact_statement"] = (
            f"Installed version {installed} already includes the fix from {fixed}.")
    else:
        statement["status"] = "affected"
        if fixed:
            statement["action_statement"] = (
                f"Upgrade {package.get('name', 'the component')} to {fixed} or later.")
    return statement


def build_from_report(report: Mapping[str, Any], author: str = TOOL_NAME) -> Dict[str, Any]:
    """Build an OpenVEX document from an argus JSON report mapping."""
    findings = [finding for finding in report.get("findings") or ()
                if isinstance(finding, Mapping) and finding.get("kind") == "sca"]
    statements = [_statement(finding) for finding in findings]
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": _document_id(),
        "author": author,
        "timestamp": _timestamp(),
        "version": 1,
        "tooling": f"{TOOL_NAME} {TOOL_VERSION}",
        "statements": statements,
    }


def build(result: ScanResult, author: str = TOOL_NAME) -> Dict[str, Any]:
    """Build an OpenVEX document directly from a :class:`ScanResult`."""
    return build_from_report(
        {"findings": [finding.to_dict() for finding in result.findings]},
        author=author)


def render(document: Mapping[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def counts(document: Mapping[str, Any]) -> Dict[str, int]:
    """Statement counts per status, used by the CLI summary line."""
    result: Dict[str, int] = {}
    for statement in document.get("statements") or ():
        status = str(statement.get("status") or "unknown")
        result[status] = result.get(status, 0) + 1
    return result


__all__ = [
    "OPENVEX_CONTEXT",
    "build",
    "build_from_report",
    "counts",
    "render",
]
