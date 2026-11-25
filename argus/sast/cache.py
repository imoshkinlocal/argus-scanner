"""Incremental cache for the built-in Java analyser.

Scanning a large repository twice should not re-analyse files that did not
change.  The cache stores the findings of one file keyed by a digest of:

* the file contents,
* the engine name and tool version,
* the resolved ``*.properties`` constants,
* the path relative to the scan root.

Writes are atomic at the SQLite level, and entries older than the retention
window are pruned when the cache is opened.  Nothing is cached when the cache
is disabled (``--no-cache``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sqlite3
import time
from typing import Dict, Iterable, List, Optional, Sequence

from ..models import TOOL_VERSION, Finding, parse_severity

CACHE_VERSION = 1
DEFAULT_RETENTION_DAYS = 30


def default_directory() -> str:
    """Cache location, honouring ``XDG_CACHE_HOME``."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache")
    return os.path.join(base, "argus", "sast")


def cache_key(path: str, source: bytes, *,
              engine: str = "argus-java",
              properties: Optional[Dict[str, str]] = None) -> str:
    """Content-addressed key for one analysed file."""
    digest = hashlib.sha256()
    digest.update(f"argus-sast-cache/{CACHE_VERSION}/{TOOL_VERSION}/{engine}\0".encode())
    digest.update(str(path).replace(os.sep, "/").encode("utf-8"))
    digest.update(b"\0")
    for key in sorted((properties or {})):
        digest.update(f"{key}={properties[key]}\0".encode("utf-8"))
    digest.update(b"\0")
    digest.update(source)
    return digest.hexdigest()


def _dump(findings: Iterable[Finding]) -> str:
    payload: List[Dict[str, object]] = []
    for finding in findings:
        item = dataclasses.asdict(finding)
        item["severity"] = finding.severity.value
        payload.append(item)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _load(payload: str) -> List[Finding]:
    findings: List[Finding] = []
    for item in json.loads(payload):
        if not isinstance(item, dict):
            continue
        data = dict(item)
        data["severity"] = parse_severity(data.get("severity"))
        findings.append(Finding(**data))
    return findings


class SastCache:
    """SQLite-backed findings cache for the Java engine."""

    def __init__(self, directory: Optional[str] = None, *,
                 enabled: bool = True, verbose: bool = False,
                 retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
        self.enabled = enabled
        self.verbose = verbose
        self.directory = os.path.abspath(directory or default_directory())
        self.retention_days = retention_days
        self.hits = 0
        self.misses = 0
        self.stored = 0
        self._connection: Optional[sqlite3.Connection] = None
        if self.enabled:
            os.makedirs(self.directory, exist_ok=True)
            self._open()

    @property
    def path(self) -> str:
        return os.path.join(self.directory, "findings.sqlite3")

    def _open(self) -> None:
        self._connection = sqlite3.connect(self.path)
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS findings ("
            "key TEXT PRIMARY KEY, created REAL NOT NULL, payload TEXT NOT NULL)")
        self._connection.commit()
        self.prune()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "SastCache":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def prune(self, max_age_days: Optional[int] = None) -> int:
        """Delete entries older than the retention window."""
        if self._connection is None:
            return 0
        days = self.retention_days if max_age_days is None else max_age_days
        if days <= 0:
            return 0
        cutoff = time.time() - days * 86_400
        cursor = self._connection.execute(
            "DELETE FROM findings WHERE created < ?", (cutoff,))
        self._connection.commit()
        return cursor.rowcount or 0

    def get(self, key: str) -> Optional[List[Finding]]:
        if self._connection is None:
            return None
        row = self._connection.execute(
            "SELECT payload FROM findings WHERE key = ?", (key,)).fetchone()
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        try:
            return _load(row[0])
        except (json.JSONDecodeError, TypeError, ValueError):
            self.misses += 1
            return None

    def put(self, key: str, findings: Sequence[Finding]) -> None:
        if self._connection is None:
            return
        self._connection.execute(
            "INSERT OR REPLACE INTO findings (key, created, payload) VALUES (?, ?, ?)",
            (key, time.time(), _dump(findings)))
        self._connection.commit()
        self.stored += 1

    def clear(self) -> int:
        """Remove every entry and return how many rows existed."""
        if self._connection is None:
            return 0
        count = self._connection.execute(
            "SELECT COUNT(*) FROM findings").fetchone()[0]
        self._connection.execute("DELETE FROM findings")
        self._connection.commit()
        return int(count)

    def stats(self) -> Dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "stored": self.stored}


__all__ = [
    "CACHE_VERSION",
    "DEFAULT_RETENTION_DAYS",
    "SastCache",
    "cache_key",
    "default_directory",
]
