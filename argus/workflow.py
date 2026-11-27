"""End-to-end reporting workflow: baseline -> suppress -> enrich -> gate.

The CLI and the GUI both run the same scanner; this module makes sure they also
share the same post-processing.  The order matters:

1. severity overrides (a policy decision about the finding itself);
2. baseline comparison (``new`` / ``existing``);
3. suppressions (accepted risks, expired entries are reported);
4. enrichment (CWE names, snippets, remediation commands);
5. baseline write-out (only findings that are still visible);
6. quality gate evaluation (exit code).
"""

from __future__ import annotations

import dataclasses
import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from . import baseline as baseline_module
from . import enrich as enrich_module
from . import gates as gates_module
from . import owasp as owasp_module
from . import suppress as suppress_module
from .config import Config
from .models import ScanResult


@dataclasses.dataclass
class WorkflowOptions:
    """Options collected from the command line and the project config."""

    root: str = ""
    baseline: Optional[str] = None
    baseline_out: Optional[str] = None
    fail_on_new: bool = False
    ignore_files: Sequence[str] = ()
    suppression_entries: Sequence[Any] = ()
    config: Optional[Config] = None
    severity_overrides: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    gate_policy: Optional[gates_module.GatePolicy] = None
    context_lines: int = enrich_module.DEFAULT_CONTEXT_LINES
    snippets: bool = True
    include_suppressed: bool = False
    #: OWASP Top 10 mapping: enabled by default, edition selected by
    #: ``owasp_version`` (empty means the bundled default) or ``owasp_file``.
    owasp: bool = True
    owasp_version: str = ""
    owasp_file: Optional[str] = None


@dataclasses.dataclass
class WorkflowSummary:
    """Counters and decisions produced by :func:`finalize`."""

    baseline_path: str = ""
    baseline_out: str = ""
    new: int = 0
    existing: int = 0
    suppressed: int = 0
    expired_suppressions: int = 0
    severity_overrides: int = 0
    snippets: int = 0
    remediation: int = 0
    cwe_names: int = 0
    owasp: int = 0
    owasp_version: str = ""
    gate: Optional[gates_module.GateResult] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "baseline": self.baseline_path,
            "baseline_out": self.baseline_out,
            "new": self.new,
            "existing": self.existing,
            "suppressed": self.suppressed,
            "expired_suppressions": self.expired_suppressions,
            "severity_overrides": self.severity_overrides,
            "enrichment": {
                "snippets": self.snippets,
                "remediation": self.remediation,
                "cwe_names": self.cwe_names,
            },
            "owasp": {
                "version": self.owasp_version,
                "mapped": self.owasp,
            },
        }
        if self.gate is not None:
            payload["gate"] = self.gate.to_dict()
        return payload


def _absolute(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return path if os.path.isabs(path) else os.path.abspath(path)


def finalize(result: ScanResult, options: Optional[WorkflowOptions] = None) -> WorkflowSummary:
    """Apply baseline, suppressions, enrichment and the quality gate."""
    opts = options or WorkflowOptions()
    root = opts.root or result.target
    summary = WorkflowSummary()

    summary.severity_overrides = enrich_module.apply_severity_overrides(
        result.findings, opts.severity_overrides)

    baseline_path = _absolute(opts.baseline)
    if opts.fail_on_new and not baseline_path:
        raise ValueError("--fail-on-new requires a baseline (--baseline PATH)")
    if baseline_path:
        loaded = baseline_module.load(baseline_path)
        counts = baseline_module.apply(result.findings, loaded)
        summary.baseline_path = baseline_path
        summary.new = counts["new"]
        summary.existing = counts["existing"]

    suppressions = suppress_module.load(
        paths=list(opts.ignore_files or ()),
        entries=list(opts.suppression_entries or ()),
        config=opts.config,
    )
    applied = suppress_module.apply(result.findings, suppressions)
    summary.suppressed = applied.applied
    summary.expired_suppressions = len(applied.expired)

    owasp_mapping = None
    if opts.owasp:
        owasp_mapping = owasp_module.load_mapping(
            opts.owasp_version or None, opts.owasp_file)
        summary.owasp_version = owasp_mapping.version
        result.stats["owasp_version"] = owasp_mapping.version
    else:
        result.stats.pop("owasp_version", None)

    enriched = enrich_module.enrich(
        result.findings,
        enrich_module.EnrichOptions(
            root=root,
            context_lines=max(0, int(opts.context_lines)),
            snippets=opts.snippets,
            owasp=bool(opts.owasp),
            owasp_mapping=owasp_mapping,
        ),
    )
    summary.snippets = enriched["snippets"]
    summary.remediation = enriched["remediation"]
    summary.cwe_names = enriched["cwe"]
    summary.owasp = enriched.get("owasp", 0)

    if opts.baseline_out:
        path = _absolute(opts.baseline_out) or opts.baseline_out
        written = baseline_module.write(
            path, [finding for finding in result.findings if not finding.suppressed],
            target=result.target)
        summary.baseline_out = written.path

    policy = opts.gate_policy or gates_module.GatePolicy()
    gate = gates_module.evaluate(
        result.findings, policy,
        packages=result.stats.get("license_packages") or {})
    summary.gate = gate

    result.sort()
    result.stats["include_suppressed"] = bool(opts.include_suppressed)
    result.stats["workflow"] = summary.to_dict()
    result.stats["gate"] = gate.to_dict()
    return summary


__all__ = ["WorkflowOptions", "WorkflowSummary", "finalize"]
