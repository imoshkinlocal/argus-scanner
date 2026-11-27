"""OSV.dev client: online batch queries, on-disk cache and offline database."""

from __future__ import annotations

import concurrent.futures
import datetime
import gzip
import hashlib
import hmac
import io
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import TOOL_NAME, TOOL_VERSION, parse_severity, severity_from_cvss
from . import versions as version_utils
from .cvss import base_score
from .parsers import Package

API_BASE = "https://api.osv.dev"
DB_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

BATCH_LIMIT = 400
DETAIL_TTL_SECONDS = 24 * 60 * 60
QUERY_TTL_SECONDS = 12 * 60 * 60

SUPPORTED_ECOSYSTEMS = [
    "Maven", "PyPI", "npm", "Go", "Packagist", "RubyGems",
    "crates.io", "NuGet", "ConanCenter", "Debian", "Ubuntu",
]

#: Ecosystems downloaded by default.  Debian (~85 MB) and Ubuntu (~800 MB) are
#: only needed for package inventories, so they stay opt-in:
#: ``argus db update --ecosystem Debian`` / ``--ecosystem Ubuntu``.
DEFAULT_DB_ECOSYSTEMS = [
    "Maven", "PyPI", "npm", "Go", "Packagist", "RubyGems",
    "crates.io", "NuGet", "ConanCenter",
]

#: Ecosystems with a published offline archive (same set as the API support).
DB_ECOSYSTEMS = SUPPORTED_ECOSYSTEMS

#: Debian-family ecosystems: one archive holds every release, and the release
#: is selected per package (``Debian:12``, ``Ubuntu:22.04:LTS``).
DEB_FAMILY = ("Debian", "Ubuntu")


class OSVError(RuntimeError):
    """Raised when the vulnerability data source cannot be reached."""


def cache_root() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "argus")


@dataclass
class VulnMatch:
    """A vulnerability that affects a concrete package version."""

    package: Package
    vuln: dict
    fixed_version: str = ""

    @property
    def id(self) -> str:
        return str(self.vuln.get("id", ""))


def osv_name(package: Package) -> str:
    """Return the package name exactly as OSV expects it."""
    if package.ecosystem == "PyPI":
        return package.name.lower().replace("_", "-").replace(".", "-")
    if package.ecosystem in DEB_FAMILY and package.source_name:
        # OSV publishes Debian/Ubuntu advisories under source package names.
        return package.source_name
    return package.name


def osv_version(package: Package) -> str:
    """Return the version OSV ranges refer to (the source version for Debian)."""
    if package.ecosystem in DEB_FAMILY and package.source_version:
        return package.source_version
    return package.version


def osv_ecosystem(package: Package) -> str:
    """Return the OSV ecosystem used for queries.

    OSV publishes Debian-family advisories per release (``Debian:12``,
    ``Ubuntu:22.04:LTS``); without a known suite there is no safe way to match
    them, so the result is empty and the caller must skip the package instead
    of guessing.
    """
    if package.ecosystem in DEB_FAMILY:
        from .debian import debian_ecosystem

        return debian_ecosystem(package.distro, package.ecosystem)
    return package.ecosystem


def osv_archive(package: Package) -> str:
    """Return the offline archive name; Debian-family ships all suites in one file."""
    return "Debian" if package.ecosystem == "Debian" else package.ecosystem


def _gzip_bytes(payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as handle:
        handle.write(payload)
    return buffer.getvalue()


def http_json(url: str, payload: Optional[dict] = None, timeout: float = 25.0,
              retries: int = 3, headers: Optional[Dict[str, str]] = None) -> dict:
    """POST/GET JSON with retries and exponential backoff."""
    body = None
    request_headers = {
        "Accept": "application/json",
        "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    delay = 1.0
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=body, headers=request_headers,
                                         method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read()
                if response.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return json.loads(data.decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:  # noqa: BLE001
                pass
            raise OSVError(f"OSV API returned HTTP {exc.code} for {url}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise OSVError(f"cannot reach OSV API ({url}): {exc}") from exc
    raise OSVError(f"cannot reach OSV API ({url}): {last_error}")


def download_file(url: str, destination: str, timeout: float = 300.0) -> int:
    """Download ``url`` to ``destination`` atomically, returning bytes written."""
    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
    temporary = destination + ".part"
    request = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    with urllib.request.urlopen(request, timeout=timeout) as response, open(temporary, "wb") as handle:
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            handle.write(chunk)
    os.replace(temporary, destination)
    return os.path.getsize(destination)


def file_sha256(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Stream a file through SHA-256 without loading it into memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class _Cache:
    """SQLite backed cache for advisory documents and query results."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.path.join(cache_root(), "osv-cache.sqlite3")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.path, timeout=10)
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS vulns (id TEXT PRIMARY KEY, fetched INTEGER, payload TEXT)"
            )
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS queries (key TEXT PRIMARY KEY, fetched INTEGER, ids TEXT)"
            )
            self._connection.commit()
        return self._connection

    def get_vuln(self, vuln_id: str, ttl: int = DETAIL_TTL_SECONDS) -> Optional[dict]:
        row = self.connection.execute("SELECT fetched, payload FROM vulns WHERE id = ?", (vuln_id,)).fetchone()
        if not row:
            return None
        fetched, payload = row
        if time.time() - fetched > ttl:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def put_vuln(self, vuln: dict) -> None:
        vuln_id = vuln.get("id")
        if not vuln_id:
            return
        self.connection.execute(
            "INSERT OR REPLACE INTO vulns (id, fetched, payload) VALUES (?, ?, ?)",
            (vuln_id, int(time.time()), json.dumps(vuln)),
        )
        self.connection.commit()

    def get_query(self, key: str, ttl: int = QUERY_TTL_SECONDS) -> Optional[List[str]]:
        row = self.connection.execute("SELECT fetched, ids FROM queries WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        fetched, ids = row
        if time.time() - fetched > ttl:
            return None
        try:
            return json.loads(ids)
        except json.JSONDecodeError:
            return None

    def put_query(self, key: str, ids: Sequence[str]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO queries (key, fetched, ids) VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(list(ids))),
        )
        self.connection.commit()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None


class OSVClient:
    """Queries OSV.dev over HTTP, using a local cache to stay fast and polite."""

    def __init__(self, use_cache: bool = True, timeout: float = 25.0, retries: int = 3,
                 cache_path: Optional[str] = None, verbose: bool = False) -> None:
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self.cache = _Cache(cache_path) if use_cache else None

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, file=sys.stderr)

    def query(self, packages: Sequence[Package]) -> List[VulnMatch]:
        unique: Dict[Tuple[str, str, str], Package] = {}
        skipped = 0
        skipped_suite = 0
        for package in packages:
            ecosystem = osv_ecosystem(package)
            if package.ecosystem in DEB_FAMILY and not ecosystem:
                # A Debian-family advisory is tied to one release; without the
                # suite a query would return versions from other releases.
                skipped_suite += 1
                continue
            version = osv_version(package)
            if not version:
                # Debian dependencies without a known version cannot be matched.
                skipped += 1
                continue
            unique.setdefault((ecosystem, osv_name(package), version), package)
        if skipped:
            self._log(f"[osv] skipped {skipped} package(s) without a version")
        if skipped_suite:
            self._log(f"[osv] skipped {skipped_suite} Debian/Ubuntu package(s) without a suite")
        if not unique:
            return []

        ids_per_key: Dict[Tuple[str, str, str], List[str]] = {}
        pending: List[Tuple[str, str, str]] = []
        for key in unique:
            cached = self.cache.get_query("|".join(key)) if self.cache else None
            if cached is not None:
                ids_per_key[key] = cached
            else:
                pending.append(key)

        if pending:
            self._log(f"[osv] querying {len(pending)} package versions")
            for start in range(0, len(pending), BATCH_LIMIT):
                chunk = pending[start:start + BATCH_LIMIT]
                payload = {
                    "queries": [
                        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                        for ecosystem, name, version in chunk
                    ]
                }
                response = http_json(f"{API_BASE}/v1/querybatch", payload,
                                     timeout=self.timeout, retries=self.retries)
                results = response.get("results") or []
                for key, item in zip(chunk, results):
                    ids = [v.get("id") for v in (item or {}).get("vulns") or [] if v.get("id")]
                    ids_per_key[key] = ids
                    if self.cache:
                        self.cache.put_query("|".join(key), ids)

        all_ids = sorted({vuln_id for ids in ids_per_key.values() for vuln_id in ids})
        details = self._fetch_details(all_ids)
        return build_matches(unique, ids_per_key, details)

    def _fetch_details(self, vuln_ids: Sequence[str]) -> Dict[str, dict]:
        details: Dict[str, dict] = {}
        missing: List[str] = []
        for vuln_id in vuln_ids:
            cached = self.cache.get_vuln(vuln_id) if self.cache else None
            if cached is not None:
                details[vuln_id] = cached
            else:
                missing.append(vuln_id)
        if not missing:
            return details
        self._log(f"[osv] fetching {len(missing)} advisory documents")

        def fetch(vuln_id: str) -> Tuple[str, Optional[dict]]:
            try:
                document = http_json(f"{API_BASE}/v1/vulns/{vuln_id}", timeout=self.timeout,
                                     retries=self.retries)
                return vuln_id, document
            except OSVError:
                return vuln_id, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for vuln_id, document in pool.map(fetch, missing):
                if document:
                    details[vuln_id] = document
                    if self.cache:
                        self.cache.put_vuln(document)
        return details

    def close(self) -> None:
        if self.cache:
            self.cache.close()


def build_matches(unique: Dict[Tuple[str, str, str], Package],
                  ids_per_key: Dict[Tuple[str, str, str], List[str]],
                  details: Dict[str, dict]) -> List[VulnMatch]:
    matches: List[VulnMatch] = []
    for key, ids in ids_per_key.items():
        package = unique.get(key)
        if package is None:
            continue
        ecosystem = osv_ecosystem(package)
        if not ecosystem:
            continue
        for vuln_id in ids:
            document = details.get(vuln_id)
            if not document or document.get("withdrawn"):
                continue
            fixed = ""
            for affected in document.get("affected") or []:
                affected_package = affected.get("package") or {}
                if affected_package.get("ecosystem") != ecosystem:
                    continue
                if affected_package.get("name") not in (package.name, osv_name(package)):
                    continue
                candidate = version_utils.fixed_version_for(
                    osv_version(package), affected, package.ecosystem)
                if candidate and (not fixed or version_utils.compare(candidate, fixed, package.ecosystem) < 0):
                    fixed = candidate
            matches.append(VulnMatch(package=package, vuln=document, fixed_version=fixed))
    return matches


class LocalOSVDB:
    """Offline database built from OSV's published per-ecosystem archives."""

    def __init__(self, directory: Optional[str] = None, verbose: bool = False) -> None:
        self.directory = directory or os.path.join(cache_root(), "osv-db")
        self.verbose = verbose
        self._index: Dict[str, Dict[str, List[dict]]] = {}

    def archive_path(self, ecosystem: str) -> str:
        return os.path.join(self.directory, ecosystem, "all.zip")

    def metadata_path(self, ecosystem: str) -> str:
        return self.archive_path(ecosystem) + ".meta.json"

    def available(self, ecosystem: str) -> bool:
        return os.path.isfile(self.archive_path(ecosystem))

    def _write_metadata(self, ecosystem: str, path: str, url: str) -> Dict[str, object]:
        """Record the identity of a downloaded snapshot next to the archive."""
        metadata = {
            "ecosystem": ecosystem,
            "url": url,
            "size_bytes": os.path.getsize(path),
            "sha256": file_sha256(path),
            "downloaded_at": datetime.datetime.now(datetime.timezone.utc)
                             .strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with open(self.metadata_path(ecosystem), "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
            handle.write("\n")
        return metadata

    def snapshot(self, ecosystem: str) -> Dict[str, object]:
        """Snapshot metadata for an ecosystem (sidecar file when available)."""
        path = self.archive_path(ecosystem)
        if not os.path.isfile(path):
            return {}
        info: Dict[str, object] = {"ecosystem": ecosystem, "archive": path}
        try:
            with open(self.metadata_path(ecosystem), encoding="utf-8") as handle:
                stored = json.load(handle)
            if isinstance(stored, dict):
                info.update(stored)
        except (OSError, json.JSONDecodeError):
            pass
        stat = os.stat(path)
        info.setdefault("size_bytes", stat.st_size)
        info.setdefault("downloaded_at", datetime.datetime.fromtimestamp(
            stat.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        info.setdefault("sha256", "")
        return info

    def snapshots(self) -> Dict[str, Dict[str, object]]:
        """All available ecosystems mapped to their snapshot metadata."""
        result: Dict[str, Dict[str, object]] = {}
        for ecosystem in DB_ECOSYSTEMS:
            info = self.snapshot(ecosystem)
            if info:
                result[ecosystem] = info
        return result

    def verify(self, ecosystem: str) -> Dict[str, object]:
        """Check an archive against the SHA-256 recorded at download time."""
        path = self.archive_path(ecosystem)
        info = self.snapshot(ecosystem)
        if not info:
            return {"ecosystem": ecosystem, "ok": False, "reason": "archive missing"}
        expected = str(info.get("sha256") or "")
        if not expected:
            return {"ecosystem": ecosystem, "ok": False,
                    "reason": "no recorded checksum (re-run: argus db update)"}
        actual = file_sha256(path)
        info["ok"] = hmac.compare_digest(actual, expected)
        info["actual_sha256"] = actual
        return info

    def update(self, ecosystems: Sequence[str]) -> List[Tuple[str, int, str]]:
        results = []
        for ecosystem in ecosystems:
            url = f"{DB_BASE}/{urllib.parse.quote(ecosystem)}/all.zip"
            destination = self.archive_path(ecosystem)
            try:
                size = download_file(url, destination)
                self._write_metadata(ecosystem, destination, url)
                results.append((ecosystem, size, ""))
            except Exception as exc:  # noqa: BLE001
                results.append((ecosystem, 0, str(exc)))
        return results

    def _load(self, ecosystem: str) -> Dict[str, List[dict]]:
        if ecosystem in self._index:
            return self._index[ecosystem]
        index: Dict[str, List[dict]] = {}
        path = self.archive_path(ecosystem)
        if not os.path.isfile(path):
            self._index[ecosystem] = index
            return index
        if self.verbose:
            print(f"[osv] loading offline database {path}", file=sys.stderr)
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        document = json.loads(archive.read(name))
                    except (json.JSONDecodeError, KeyError):
                        continue
                    if document.get("withdrawn"):
                        # Withdrawn records stay in the archive but must not be
                        # reported (the online API filters them out too).
                        continue
                    names = set()
                    for affected in document.get("affected") or []:
                        affected_package = affected.get("package") or {}
                        affected_ecosystem = str(affected_package.get("ecosystem") or "")
                        if ecosystem in DEB_FAMILY:
                            # One archive holds Debian:11, Debian:12, ... (or
                            # Ubuntu:22.04:LTS, ...); the suite is selected
                            # later, per package.
                            if not affected_ecosystem.startswith(ecosystem + ":"):
                                continue
                        elif affected_ecosystem != ecosystem:
                            continue
                        package_name = affected_package.get("name")
                        if package_name:
                            names.add(package_name)
                    for package_name in names:
                        index.setdefault(package_name, []).append(document)
        except (zipfile.BadZipFile, OSError) as exc:
            if self.verbose:
                print(f"[osv] cannot read {path}: {exc}", file=sys.stderr)
        self._index[ecosystem] = index
        return index

    def query(self, packages: Sequence[Package]) -> List[VulnMatch]:
        matches: List[VulnMatch] = []
        for package in packages:
            version = osv_version(package)
            if not version:
                continue
            ecosystem = osv_ecosystem(package)
            if not ecosystem:
                continue
            name = osv_name(package)
            index = self._load(osv_archive(package))
            for document in index.get(name, []):
                fixed = ""
                hit = False
                for affected in document.get("affected") or []:
                    affected_package = affected.get("package") or {}
                    if affected_package.get("ecosystem") != ecosystem:
                        continue
                    if affected_package.get("name") != name:
                        continue
                    versions = affected.get("versions") or []
                    if version in versions:
                        hit = True
                    for entry in affected.get("ranges") or []:
                        if entry.get("type") not in ("ECOSYSTEM", "SEMVER"):
                            continue
                        inclusive = any("last_affected" in event for event in entry.get("events") or [])
                        if version_utils.range_contains(version, entry.get("events") or [],
                                                       package.ecosystem, inclusive):
                            hit = True
                    candidate = version_utils.fixed_version_for(version, affected,
                                                                package.ecosystem)
                    if candidate and (not fixed or version_utils.compare(candidate, fixed, package.ecosystem) < 0):
                        fixed = candidate
                if hit:
                    matches.append(VulnMatch(package=package, vuln=document, fixed_version=fixed))
        return matches


def vulnerability_severity(document: dict) -> Tuple[str, Optional[float]]:
    """Return ``(severity_name, cvss_score)`` for an OSV document."""
    database_specific = document.get("database_specific") or {}
    ecosystem_specific = document.get("ecosystem_specific") or {}

    score: Optional[float] = None
    for entry in document.get("severity") or []:
        candidate = base_score(str(entry.get("score", "")))
        if candidate is not None and (score is None or candidate > score):
            score = candidate
    if score is None:
        raw = database_specific.get("cvss_score") or ecosystem_specific.get("cvss_score")
        if isinstance(raw, (int, float)):
            score = float(raw)

    qualitative = database_specific.get("severity") or ecosystem_specific.get("severity")
    if qualitative:
        severity = parse_severity(qualitative)
        if severity.value != "unknown":
            if score is None:
                score = {
                    "critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0,
                }.get(severity.value)
            return severity.value, score
    if score is not None:
        return severity_from_cvss(score).value, score
    return "unknown", None


def vulnerability_cwes(document: dict) -> List[str]:
    found: List[str] = []
    for key in ("cwe_ids", "cwes"):
        for value in (document.get("database_specific") or {}).get(key) or []:
            found.append(str(value))
    for affected in document.get("affected") or []:
        for key in ("cwe_ids", "cwes"):
            for value in (affected.get("database_specific") or {}).get(key) or []:
                found.append(str(value))
    normalized = []
    for item in found:
        item = item.strip().upper()
        if not item:
            continue
        if not item.startswith("CWE-"):
            item = f"CWE-{item.lstrip('CWEcwe-')}"
        if item not in normalized:
            normalized.append(item)
    return normalized


def canonical_id(document: dict) -> str:
    """Prefer the CVE identifier when an advisory only carries vendor aliases."""
    for alias in document.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return str(document.get("id", ""))
