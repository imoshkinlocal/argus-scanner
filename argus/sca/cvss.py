"""Minimal CVSS v3.0/v3.1 base score calculator (no external deps).

OSV advisories carry either a qualitative severity (GHSA ``database_specific``)
or a CVSS vector string.  Being able to turn a vector into a score gives the
SCA engine a uniform severity model even for advisories without a rating.
"""

from __future__ import annotations

import math
from typing import Dict, Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A round up (to one decimal)."""
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> Dict[str, str]:
    metrics: Dict[str, str] = {}
    for chunk in vector.strip().split("/"):
        if ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        metrics[key.strip().upper()] = value.strip().upper()
    return metrics


def base_score(vector: str) -> Optional[float]:
    """Return the CVSS v3.x base score for ``vector`` (``None`` if unsupported)."""
    if not vector:
        return None
    vector = vector.strip()
    if not vector.upper().startswith("CVSS:3"):
        return None
    metrics = parse_vector(vector)
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics.get("S", "U") == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity_from_vector(vector: str) -> Optional[float]:
    return base_score(vector)
