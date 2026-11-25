"""Finding suppression: accepted risks, false positives and expiry dates.

Suppressions can live in the project configuration, in a JSON/TOML file passed
with ``--ignore`` or in a plain ``.argusignore`` list.  A suppression matches on
any combination of rule id, file glob, CWE, package and stable finding id.  An
entry without criteria never matches, so a broken configuration cannot hide the
whole report.

Suppressed findings stay in the JSON report with ``"suppressed": true`` and the
reason, but they do not affect the exit code and the human reports hide them by
default.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import config as config_module
from . import cwe as cwe_module
from .models import Finding

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def parse_date(value: Any) -> Optional[datetime.date]:
    """Parse ``YYYY-MM-DD`` (or a full ISO timestamp) into a date."""
    if value in (None, "", False):
        return None
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    text = str(value).strip()
    if not _DATE_RE.match(text):
        return None
    try:
        return datetime.date.fromisoformat(text[:10])
    except ValueError:
        return None


@dataclasses.dataclass
class Suppression:
    """One accepted risk / false-positive entry."""

    rule: str = ""
    file: str = ""
    cwe: str = ""
    package: str = ""
    finding_id: str = ""
    message: str = ""
    reason: str = ""
    author: str = ""
    expires: str = ""
    source: str = ""

    @classmethod
    def from_value(cls, value: Any, source: str = "") -> Optional["Suppression"]:
        if isinstance(value, Suppression):
            if source and not value.source:
                value.source = source
            return value
        if isinstance(value, str):
            return cls.from_line(value, source=source)
        if not isinstance(value, Mapping):
            return None
        raw = {str(key): item for key, item in value.items()}
        finding_id = raw.get("id") or raw.get("fingerprint") or raw.get("finding_id") or ""
        rule = raw.get("rule") or raw.get("rule_id") or raw.get("rules") or ""
        if isinstance(rule, (list, tuple)):
            rule = rule[0] if rule else ""
        return cls(
            rule=str(rule or ""),
            file=str(raw.get("file") or raw.get("path") or ""),
            cwe=str(raw.get("cwe") or ""),
            package=str(raw.get("package") or raw.get("purl") or ""),
            finding_id=str(finding_id),
            message=str(raw.get("message") or raw.get("title") or ""),
            reason=str(raw.get("reason") or raw.get("justification") or ""),
            author=str(raw.get("author") or raw.get("owner") or ""),
            expires=str(raw.get("expires") or raw.get("until") or ""),
            source=str(source or raw.get("source") or ""),
        )

    @classmethod
    def from_line(cls, line: str, source: str = "") -> Optional["Suppression"]:
        """Parse one ``.argusignore`` line.

        Supported forms::

            java-sqli-*
            rule:java-sqli-*
            file:src/legacy/*
            cwe:CWE-79
            package:lodash@*
            id:4f7c...
            rule:java-sqli-*  # accepted risk, expires 2027-01-01
        """
        text = line.strip()
        if not text or text.startswith("#"):
            return None
        reason = ""
        if "#" in text:
            text, reason = text.split("#", 1)
            text, reason = text.strip(), reason.strip()
        if not text:
            return None
        prefix, _, rest = text.partition(":")
        prefix = prefix.strip().lower()
        value = rest.strip()
        entry = cls(reason=reason, source=source)
        if prefix == "rule" and value:
            entry.rule = value
        elif prefix in ("file", "path") and value:
            entry.file = value
        elif prefix == "cwe" and value:
            entry.cwe = value
        elif prefix in ("pkg", "package", "purl") and value:
            entry.package = value
        elif prefix in ("id", "fingerprint") and value:
            entry.finding_id = value
        elif prefix in ("message", "title") and value:
            entry.message = value
        else:
            value = text
            normalised = cwe_module.format_cwe(value)
            if normalised:
                entry.cwe = normalised
            else:
                entry.rule = value
        return entry

    @property
    def expired(self) -> bool:
        """True when the entry declares an expiry date in the past."""
        return self.is_expired()

    def is_expired(self, today: Optional[datetime.date] = None) -> bool:
        expiry = parse_date(self.expires)
        if expiry is None:
            return False
        return expiry < (today or datetime.date.today())

    def has_criteria(self) -> bool:
        return bool(self.rule or self.file or self.cwe or self.package
                    or self.finding_id or self.message)

    def matches(self, finding: Mapping[str, Any],
                today: Optional[datetime.date] = None) -> bool:
        """True when every configured criterion matches the finding."""
        if not self.has_criteria() or self.is_expired(today):
            return False
        location = finding.get("location") or {}
        package = finding.get("package") or {}
        file_path = str(location.get("file") or finding.get("file") or "")
        package_name = str(package.get("name") or finding.get("package") or "")
        package_version = str(package.get("version") or finding.get("version") or "")
        package_purl = str(package.get("purl") or finding.get("purl") or "")
        finding_id = str(finding.get("id") or finding.get("fingerprint") or "")

        if self.finding_id and not (
            finding_id == self.finding_id
            or finding_id.startswith(self.finding_id)
        ):
            return False
        if self.rule and not config_module.glob_match(
                str(finding.get("rule_id") or ""), self.rule):
            return False
        if self.file and not config_module.glob_match(file_path, self.file):
            return False
        if self.cwe:
            wanted = cwe_module.format_cwe(self.cwe)
            actual = cwe_module.format_cwe(finding.get("cwe"))
            if wanted and actual:
                if wanted != actual:
                    return False
            elif not config_module.glob_match(str(finding.get("cwe") or ""), self.cwe):
                return False
        if self.package:
            candidates = [package_name, package_purl,
                          f"{package_name}@{package_version}".strip("@"),
                          f"{package_name} {package_version}".strip()]
            if not any(config_module.glob_match(candidate, self.package)
                       for candidate in candidates if candidate):
                return False
        if self.message:
            haystack = " ".join((str(finding.get("message") or ""),
                                 str(finding.get("title") or ""))).lower()
            needle = self.message.lower()
            if needle not in haystack and not config_module.glob_match(haystack, needle):
                return False
        return True

    def describe(self) -> str:
        parts = []
        for label, value in (("rule", self.rule), ("file", self.file),
                             ("cwe", self.cwe), ("package", self.package),
                             ("id", self.finding_id), ("message", self.message)):
            if value:
                parts.append(f"{label}={value}")
        return ", ".join(parts) or "empty"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "file": self.file,
            "cwe": self.cwe,
            "package": self.package,
            "id": self.finding_id,
            "message": self.message,
            "reason": self.reason,
            "author": self.author,
            "expires": self.expires,
            "source": self.source,
        }


@dataclasses.dataclass
class SuppressionResult:
    """Outcome of applying suppressions to a list of findings."""

    applied: int = 0
    expired: List[Suppression] = dataclasses.field(default_factory=list)
    entries: List[Suppression] = dataclasses.field(default_factory=list)
    matched: List[Suppression] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suppressed": self.applied,
            "entries": len(self.entries),
            "expired": [entry.to_dict() for entry in self.expired],
        }


def load_file(path: str) -> List[Suppression]:
    """Load suppressions from JSON, TOML or a plain ignore list."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"suppression file not found: {path}")
    lowered = path.lower()
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ValueError(f"cannot read suppression file {path}: {exc}") from exc

    if lowered.endswith(".json"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {path}: {exc}") from exc
        return _entries_from_payload(payload, path)
    if lowered.endswith((".toml", ".tml")):
        try:
            payload = config_module.parse_text(text, path)
        except config_module.ConfigError as exc:
            raise ValueError(str(exc)) from exc
        return _entries_from_payload(payload, path)
    entries: List[Suppression] = []
    for line in text.splitlines():
        entry = Suppression.from_line(line, source=os.path.abspath(path))
        if entry is not None:
            entries.append(entry)
    return entries


def _entries_from_payload(payload: Any, source: str) -> List[Suppression]:
    if isinstance(payload, Mapping):
        raw = payload.get("suppress")
        if raw is None:
            raw = payload.get("suppressions")
        if raw is None:
            raw = payload.get("ignore")
        if raw is None:
            raw = payload
    else:
        raw = payload
    if isinstance(raw, Mapping):
        raw = [raw]
    entries: List[Suppression] = []
    if isinstance(raw, (str, bytes)):
        raw = [raw]
    if not isinstance(raw, Iterable):
        return entries
    for item in raw:
        entry = Suppression.from_value(item, source=os.path.abspath(source))
        if entry is not None and entry.has_criteria():
            entries.append(entry)
    return entries


def load(paths: Sequence[str] = (), entries: Sequence[Any] = (),
         config: Optional[config_module.Config] = None) -> List[Suppression]:
    """Load suppressions from files and inline configuration entries."""
    result: List[Suppression] = []
    seen: set = set()

    def add(entry: Optional[Suppression]) -> None:
        if entry is None or not entry.has_criteria():
            return
        marker = (entry.rule, entry.file, entry.cwe, entry.package,
                  entry.finding_id, entry.message, entry.expires)
        if marker in seen:
            return
        seen.add(marker)
        result.append(entry)

    for path in paths or ():
        for entry in load_file(path):
            add(entry)
    inline = list(entries or ())
    if config is not None:
        inline.extend(config.suppressions())
    for item in inline:
        add(Suppression.from_value(item, source="config"))
    return result


def apply(findings: Iterable[Finding], suppressions: Sequence[Suppression],
          today: Optional[datetime.date] = None) -> SuppressionResult:
    """Mark matching findings as suppressed.

    Every finding keeps the first matching suppression so the JSON report
    explains why it was hidden.
    """
    result = SuppressionResult(entries=list(suppressions))
    result.expired = [entry for entry in suppressions if entry.is_expired(today)]
    active = [entry for entry in suppressions if not entry.is_expired(today)]
    matched_ids: set = set()
    for finding in findings:
        payload = finding.to_dict()
        for entry in active:
            if entry.matches(payload, today):
                finding.suppressed = True
                finding.suppression = entry.to_dict()
                result.applied += 1
                matched_ids.add(id(entry))
                break
    result.matched = [entry for entry in active if id(entry) in matched_ids]
    return result


def format_suppression(entry: Suppression) -> str:
    """One-line description used by ``argus suppressions`` style output."""
    reason = f" — {entry.reason}" if entry.reason else ""
    expiry = f" (expires {entry.expires})" if entry.expires else ""
    return f"{entry.describe()}{reason}{expiry}"


__all__ = [
    "Suppression",
    "SuppressionResult",
    "apply",
    "format_suppression",
    "load",
    "load_file",
    "parse_date",
]
