"""Exploit intelligence: EPSS scores and the CISA KEV catalogue.

A vulnerability identifier and a severity bucket answer "how bad would this be".
Two public feeds answer the complementary question "is anyone actually
exploiting it":

* **EPSS** (FIRST.org) — a probability that a CVE will be exploited in the wild
  in the next 30 days, plus a percentile;
* **KEV** (CISA) — the catalogue of vulnerabilities known to be exploited,
  including ransomware usage and the remediation due date.

Both feeds are optional.  The module never makes a scan fail: network problems
are reported through the returned statistics, and a cached snapshot is reused
when it is still fresh.  Tests and air-gapped runs can point the loader at a
local JSON file (``--epss-file`` / ``--kev-file``) and skip the network entirely.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .models import Finding, TOOL_NAME, TOOL_VERSION

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

DEFAULT_TTL_HOURS = 12.0
DEFAULT_TIMEOUT = 30.0

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class ThreatIntelError(ValueError):
    """Raised when a caller supplies an unreadable local feed."""


@dataclass
class ThreatOptions:
    """Where the feeds come from and how aggressively to cache them."""

    epss_file: Optional[str] = None
    kev_file: Optional[str] = None
    cache: bool = True
    cache_dir: Optional[str] = None
    ttl_hours: float = DEFAULT_TTL_HOURS
    timeout: float = DEFAULT_TIMEOUT
    verbose: bool = False


@dataclass
class Dataset:
    """One loaded feed and the provenance used in the report."""

    records: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    source: str = ""
    fetched_at: float = 0.0
    error: str = ""


def default_directory() -> str:
    """Threat-intel cache location, honouring ``XDG_CACHE_HOME``."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache")
    return os.path.join(base, "argus", "threat")


def _read_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise ThreatIntelError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ThreatIntelError(f"{path}: invalid JSON ({exc})") from exc


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- parsers

def parse_epss(payload: Any) -> Dict[str, Dict[str, Any]]:
    """Normalise the EPSS API response (or a plain mapping) into records."""
    records: Dict[str, Dict[str, Any]] = {}
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if data is None:
            data = [{"cve": key, **value} if isinstance(value, Mapping)
                    else {"cve": key, "epss": value}
                    for key, value in payload.items() if _CVE_RE.match(str(key))]
        entries = data if isinstance(data, list) else []
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = []

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        cve = str(entry.get("cve") or entry.get("CVE") or "").upper()
        if not _CVE_RE.match(cve):
            continue
        score = _as_float(entry.get("epss"))
        if score is None:
            continue
        percentile = _as_float(entry.get("percentile"))
        records[cve] = {
            "epss": score,
            "percentile": percentile if percentile is not None else 0.0,
            "date": str(entry.get("date") or ""),
        }
    return records


def parse_kev(payload: Any) -> Dict[str, Dict[str, Any]]:
    """Normalise the CISA KEV JSON catalogue into per-CVE records."""
    if isinstance(payload, Mapping):
        entries = payload.get("vulnerabilities")
    else:
        entries = payload
    records: Dict[str, Dict[str, Any]] = {}
    if not isinstance(entries, list):
        return records
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        cve = str(entry.get("cveID") or entry.get("cve") or "").upper()
        if not _CVE_RE.match(cve):
            continue
        ransomware = str(entry.get("knownRansomwareCampaignUse") or "").lower()
        records[cve] = {
            "vendor": str(entry.get("vendorProject") or ""),
            "product": str(entry.get("product") or ""),
            "name": str(entry.get("vulnerabilityName") or ""),
            "date_added": str(entry.get("dateAdded") or ""),
            "due_date": str(entry.get("dueDate") or ""),
            "ransomware": ransomware == "known",
            "required_action": str(entry.get("requiredAction") or ""),
        }
    return records


# --------------------------------------------------------------------------- loading

def _cache_path(directory: str, name: str) -> str:
    return os.path.join(directory, f"{name}.json")


def _read_cache(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if not isinstance(payload.get("records"), dict):
        return None
    return payload


def _write_cache(path: str, url: str, records: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        temporary = path + ".part"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"url": url, "fetched_at": time.time(), "records": records},
                      handle, ensure_ascii=False)
        os.replace(temporary, path)
    except OSError:
        pass


def _download(url: str, timeout: float) -> Any:
    request = urllib.request.Request(
        url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _load_dataset(name: str, url: str, options: ThreatOptions,
                  parser, wanted: Optional[Set[str]] = None,
                  targeted: bool = False) -> Dataset:
    """Load one feed from a file, the cache or the network, in that order.

    ``targeted`` feeds (EPSS) are queried only for the CVEs that the scan
    actually needs: the public API paginates at 100 records by default, so
    downloading the whole catalogue would silently miss most identifiers.
    """
    path = options.epss_file if name == "epss" else options.kev_file
    if path:
        records = parser(_read_json(path))
        return Dataset(records=records, source=f"file:{path}", fetched_at=time.time())

    directory = os.path.abspath(options.cache_dir or default_directory())
    cache_path = _cache_path(directory, name)
    now = time.time()
    ttl_seconds = max(0.0, float(options.ttl_hours)) * 3600.0
    cached = _read_cache(cache_path) if options.cache else None
    cached_records = dict(cached["records"]) if cached else {}
    cached_at = float(cached.get("fetched_at") or 0.0) if cached else 0.0
    fresh = bool(cached is not None and ttl_seconds > 0
                 and now - cached_at <= ttl_seconds)

    if targeted:
        query = sorted(set(wanted or ()))
        if not query:
            if cached is not None:
                return Dataset(records=cached_records, source="cache",
                               fetched_at=cached_at)
            return Dataset(source="skipped")
        missing = [cve for cve in query if cve not in cached_records]
        if fresh and not missing:
            return Dataset(records=cached_records, source="cache",
                           fetched_at=cached_at)
        request_url = url + "?cve=" + ",".join(missing or query)
    else:
        if fresh:
            return Dataset(records=cached_records, source="cache",
                           fetched_at=cached_at)
        request_url = url

    try:
        records = parser(_download(request_url, options.timeout))
    except Exception as exc:  # noqa: BLE001 - a feed outage must not break a scan
        if cached is not None:
            return Dataset(records=cached_records, source="cache-stale",
                           fetched_at=cached_at, error=str(exc))
        return Dataset(source="unavailable", error=str(exc))

    merged = dict(cached_records)
    merged.update(records)
    if options.cache:
        _write_cache(cache_path, url, merged)
    return Dataset(records=merged, source="network", fetched_at=now)


# --------------------------------------------------------------------------- matching

def finding_cves(finding: Finding) -> Set[str]:
    """All CVE identifiers attached to an SCA finding."""
    candidates: List[str] = [finding.rule_id]
    candidates.extend(finding.aliases)
    cwes = finding.metadata.get("cwes") if finding.metadata else None
    if isinstance(cwes, (list, tuple)):
        candidates.extend(str(item) for item in cwes)
    return {value.upper() for value in candidates
            if isinstance(value, str) and _CVE_RE.match(value)}


def _best_match(cves: Iterable[str], records: Mapping[str, Dict[str, Any]]
                ) -> Tuple[str, Dict[str, Any]]:
    best_cve = ""
    best: Dict[str, Any] = {}
    for cve in cves:
        record = records.get(cve)
        if record is None:
            continue
        if not best or float(record.get("epss") or 0.0) > float(best.get("epss") or 0.0):
            best_cve, best = cve, record
    return best_cve, best


def apply(findings: Iterable[Finding],
          options: Optional[ThreatOptions] = None) -> Dict[str, Any]:
    """Annotate SCA findings with EPSS/KEV metadata and return statistics.

    Local files win over the network so that a scan can reproduce results from
    a recorded feed snapshot.  Nothing is raised for feed outages: the caller
    receives ``errors`` and the rest of the scan proceeds unchanged.
    """
    options = options or ThreatOptions()
    all_cves: Set[str] = set()
    sca_findings: List[Finding] = []
    for finding in findings:
        if finding.kind != "sca":
            continue
        cves = finding_cves(finding)
        if cves:
            sca_findings.append(finding)
            all_cves.update(cves)

    if not all_cves and not options.epss_file and not options.kev_file:
        return {
            "epss_records": 0,
            "kev_records": 0,
            "epss_matches": 0,
            "kev_matches": 0,
            "kev_ransomware": 0,
            "sources": {"epss": "skipped", "kev": "skipped"},
            "fetched_at": {"epss": "", "kev": ""},
            "errors": [],
        }

    epss = _load_dataset("epss", EPSS_URL, options, parse_epss,
                         wanted=all_cves, targeted=True)
    kev = _load_dataset("kev", KEV_URL, options, parse_kev)

    stats: Dict[str, Any] = {
        "epss_records": len(epss.records),
        "kev_records": len(kev.records),
        "epss_matches": 0,
        "kev_matches": 0,
        "kev_ransomware": 0,
        "sources": {
            "epss": epss.source,
            "kev": kev.source,
        },
        "fetched_at": {
            "epss": _iso(epss.fetched_at),
            "kev": _iso(kev.fetched_at),
        },
        "errors": [value for value in (epss.error, kev.error) if value],
    }

    for finding in findings:
        if finding.kind != "sca":
            continue
        cves = finding_cves(finding)
        if not cves:
            continue
        if epss.records:
            cve, record = _best_match(cves, epss.records)
            if record:
                finding.metadata["epss"] = float(record.get("epss") or 0.0)
                finding.metadata["epss_percentile"] = float(
                    record.get("percentile") or 0.0)
                finding.metadata["epss_cve"] = cve
                stats["epss_matches"] += 1
        if kev.records:
            cve, record = _best_match(cves, kev.records)
            if record:
                finding.metadata["kev"] = True
                finding.metadata["kev_cve"] = cve
                finding.metadata["kev_ransomware"] = bool(record.get("ransomware"))
                finding.metadata["kev_due_date"] = record.get("due_date", "")
                finding.metadata["kev_date_added"] = record.get("date_added", "")
                finding.metadata["kev_name"] = record.get("name", "")
                stats["kev_matches"] += 1
                if record.get("ransomware"):
                    stats["kev_ransomware"] += 1
    return stats


def _iso(timestamp: float) -> str:
    if not timestamp:
        return ""
    return datetime.datetime.fromtimestamp(
        timestamp, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_summary(stats: Mapping[str, Any]) -> str:
    """One-line human summary used by the CLI and the Markdown report."""
    return (
        f"EPSS {stats.get('epss_matches', 0)}/{stats.get('epss_records', 0)}, "
        f"KEV {stats.get('kev_matches', 0)}/{stats.get('kev_records', 0)}"
    )


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_TTL_HOURS",
    "Dataset",
    "EPSS_URL",
    "KEV_URL",
    "ThreatIntelError",
    "ThreatOptions",
    "apply",
    "default_directory",
    "finding_cves",
    "format_summary",
    "parse_epss",
    "parse_kev",
]
