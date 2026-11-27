"""OWASP Top 10 reference: map a CWE to its Top 10 category.

The mapping is data, not code.  The official editions ship in
``argus/owasp_top10.json`` and can be refreshed with
``scripts/update_owasp.py``.  ``--owasp-file`` loads a newer or custom mapping
without rebuilding argus, so a future edition (or an organisation's own
taxonomy) is one JSON/TOML document away.

A CWE may belong to more than one category: CWE-259, for example, is both
A02:2021 and A07:2021.  Findings therefore carry a list, with the first match
kept as the primary category by the report renderers.

2017 note: the official 2017 document lists only representative CWEs per
category, and its A09 page has no CWE list.  The bundled 2017 mapping follows
that document; A09 uses the three successor CWEs (937, 1035, 1104) from the
2021 A06 list so dependency findings still map to it.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import cwe as cwe_module
from .models import OwaspCategory

DATA_NAME = "owasp_top10.json"
DEFAULT_VERSION = "2021"

_VERSION_RE = re.compile(
    r"(?i)^\s*(?:owasp[\s:_-]*)?(?:top[\s:_-]*10[\s:_-]*)?v?\s*(\d{4})\s*$")
_CATEGORY_RE = re.compile(r"(?i)^(A\d{1,2})$")


class OwaspError(ValueError):
    """Raised for an unknown edition or a malformed custom mapping."""


def data_path() -> str:
    """Absolute path of the bundled mapping document."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DATA_NAME)


def normalize_version(value: Any) -> str:
    """Normalise ``2021``, ``v2021`` or ``owasp-2021`` to ``2021``."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    number = _VERSION_RE.match(str(value).strip())
    return number.group(1) if number else str(value).strip()


def normalize_category_id(value: Any) -> str:
    """Normalise ``A3``/``A03:2021``/``a3`` to ``A3``/``A03``."""
    text = str(value or "").strip().upper()
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    match = _CATEGORY_RE.match(text)
    if not match:
        raise OwaspError(f"not an OWASP category identifier: {value!r}")
    return match.group(1)


@dataclasses.dataclass(frozen=True)
class OwaspMapping:
    """A complete CWE -> category index for one Top 10 edition."""

    version: str
    source: str = ""
    categories: Tuple[OwaspCategory, ...] = ()
    #: Built from ``categories``; a CWE may resolve to several categories.
    by_cwe: Mapping[int, Tuple[OwaspCategory, ...]] = dataclasses.field(
        default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.by_cwe:
            return
        index: Dict[int, List[OwaspCategory]] = {}
        for category in self.categories:
            for number in category.cwes:
                index.setdefault(number, []).append(category)
        object.__setattr__(
            self, "by_cwe", {number: tuple(items) for number, items in index.items()})

    def lookup(self, cwe: Any) -> Tuple[OwaspCategory, ...]:
        """Return every category the CWE belongs to (empty when unmapped)."""
        number = cwe_module.normalize_cwe(cwe)
        if number is None:
            return ()
        return self.by_cwe.get(number, ())

    def category(self, value: Any) -> Optional[OwaspCategory]:
        """Return a category by id (``A03`` or ``A03:2021``)."""
        try:
            wanted = normalize_category_id(value)
        except OwaspError:
            return None
        for category in self.categories:
            if category.id == wanted:
                return category
        return None

    @property
    def mapped_cwes(self) -> List[int]:
        return sorted(self.by_cwe)

    def cwes(self) -> List[int]:
        return self.mapped_cwes

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the complete mapping, including each category's CWEs."""
        categories = []
        for category in self.categories:
            payload = category.to_dict()
            payload["cwes"] = list(category.cwes)
            categories.append(payload)
        return {
            "version": self.version,
            "source": self.source,
            "categories": categories,
        }

    def to_document(self) -> Dict[str, Any]:
        """Serialise in the multi-edition format used by the bundled file."""
        return {
            "schema": 1,
            "source": self.source,
            "default": self.version,
            "versions": {self.version: {
                "source": self.source,
                "categories": self.to_dict()["categories"],
            }},
        }


@functools.lru_cache(maxsize=1)
def _builtin_document() -> Dict[str, Any]:
    path = data_path()
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise OwaspError(f"cannot read the bundled OWASP mapping {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise OwaspError(f"invalid bundled OWASP mapping {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise OwaspError(f"{path}: the top level must be an object")
    return data


def default_version() -> str:
    """The edition used when neither the CLI nor a config sets one."""
    raw = _builtin_document().get("default")
    return normalize_version(raw) or DEFAULT_VERSION


def available_versions() -> List[str]:
    """Bundled editions in chronological order."""
    versions = _builtin_document().get("versions")
    if not isinstance(versions, Mapping):
        return [DEFAULT_VERSION]
    return sorted((normalize_version(key) for key in versions), key=_version_sort_key)


def _version_sort_key(value: str) -> Tuple[int, str]:
    return (int(value), value) if value.isdigit() else (0, value)


def _categories_from(raw: Any, version: str) -> Tuple[OwaspCategory, ...]:
    if not isinstance(raw, Iterable) or isinstance(raw, (str, bytes, Mapping)):
        raise OwaspError("'categories' must be a list of category objects")
    seen: Dict[int, OwaspCategory] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise OwaspError(f"category #{index + 1} must be an object")
        category_id = normalize_category_id(
            item.get("id") or item.get("category") or "")
        number = int(category_id[1:])
        if number in seen:
            raise OwaspError(f"duplicate OWASP category: {category_id}")
        values = item.get("cwes", item.get("cwe", ()))
        if values is None:
            values = ()
        if isinstance(values, (str, int)):
            values = [values]
        if not isinstance(values, Iterable):
            raise OwaspError(f"{category_id}: 'cwes' must be a list")
        numbers = set()
        for value in values:
            value_number = cwe_module.normalize_cwe(value)
            if value_number is None:
                raise OwaspError(f"{category_id}: invalid CWE identifier {value!r}")
            numbers.add(value_number)
        seen[number] = OwaspCategory(
            id=category_id,
            version=version,
            name=str(item.get("name") or "").strip(),
            name_ru=str(item.get("name_ru") or "").strip(),
            url=str(item.get("url") or "").strip(),
            cwes=tuple(sorted(numbers)),
        )
    if not seen:
        raise OwaspError("the mapping contains no categories")
    return tuple(seen.values())


def mapping_from_document(document: Any,
                          version: Optional[str] = None) -> OwaspMapping:
    """Build a mapping from a parsed JSON/TOML document.

    Two shapes are accepted: the bundled multi-edition document with a
    ``versions`` object, and a single-edition document with ``version`` and
    ``categories`` keys.
    """
    if not isinstance(document, Mapping):
        raise OwaspError("the OWASP mapping must be an object")
    root_source = str(document.get("source") or "").strip()
    requested = normalize_version(version)

    if "versions" in document:
        versions = document.get("versions")
        if not isinstance(versions, Mapping) or not versions:
            raise OwaspError("'versions' must be a non-empty object")
        resolved = requested or normalize_version(document.get("default"))
        lookup = {normalize_version(key): key for key in versions}
        if not resolved:
            if len(lookup) != 1:
                raise OwaspError(
                    "the file defines several editions; pass --owasp-version "
                    f"({', '.join(sorted(lookup))})")
            resolved = next(iter(lookup))
        if resolved not in lookup:
            raise OwaspError(
                f"edition {resolved!r} is not in the file "
                f"(available: {', '.join(sorted(lookup))})")
        raw = versions[lookup[resolved]]
        if not isinstance(raw, Mapping):
            raise OwaspError(f"edition {resolved!r} must be an object")
    else:
        raw = document
        resolved = (requested or normalize_version(document.get("version"))
                    or "custom")

    categories = _categories_from(raw.get("categories"), resolved)
    source = str(raw.get("source") or root_source).strip()
    return OwaspMapping(version=resolved, source=source, categories=categories)


def _parse_text(text: str, path: str) -> Any:
    """Parse JSON, or TOML for any other extension."""
    stripped = text.lstrip()
    if path.lower().endswith(".json") or stripped.startswith(("{", "[")):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise OwaspError(f"invalid JSON in {path}: {exc}") from exc
    from .config import ConfigError, parse_text as parse_config

    try:
        return parse_config(text, path)
    except ConfigError as exc:
        raise OwaspError(str(exc)) from exc


def load_document(path: str) -> Any:
    """Read and parse a custom mapping file."""
    if not os.path.isfile(path):
        raise OwaspError(f"OWASP mapping not found: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise OwaspError(f"cannot read the OWASP mapping {path}: {exc}") from exc
    return _parse_text(text, path)


@functools.lru_cache(maxsize=8)
def load_builtin(version: Optional[str] = None) -> OwaspMapping:
    """Load one of the bundled editions (2017, 2021, 2025)."""
    document = _builtin_document()
    versions = document.get("versions")
    if not isinstance(versions, Mapping) or not versions:
        raise OwaspError("the bundled OWASP mapping has no editions")
    resolved = normalize_version(version) or default_version()
    lookup = {normalize_version(key): key for key in versions}
    if resolved not in lookup:
        raise OwaspError(
            f"unknown OWASP Top 10 edition {resolved!r}; "
            f"available: {', '.join(sorted(lookup, key=_version_sort_key))}")
    mapping = mapping_from_document(document, resolved)
    return mapping


def load_mapping(version: Optional[str] = None,
                 path: Optional[str] = None) -> OwaspMapping:
    """Load a bundled edition, or a custom/updated file when ``path`` is set."""
    if path:
        return mapping_from_document(load_document(path), version)
    return load_builtin(version)


def attach(findings: Iterable[Any], mapping: OwaspMapping) -> int:
    """Attach OWASP categories to every finding that has a CWE.

    Existing references are replaced, which keeps repeated enrichment calls
    idempotent.  Returns the number of findings that received a category.
    """
    attached = 0
    for finding in findings:
        categories = mapping.lookup(getattr(finding, "cwe", ""))
        finding.owasp = list(categories)
        if categories:
            attached += 1
    return attached


__all__ = [
    "DATA_NAME",
    "DEFAULT_VERSION",
    "OwaspCategory",
    "OwaspError",
    "OwaspMapping",
    "attach",
    "available_versions",
    "data_path",
    "default_version",
    "load_builtin",
    "load_document",
    "load_mapping",
    "mapping_from_document",
    "normalize_category_id",
    "normalize_version",
]
