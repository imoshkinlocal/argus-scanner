"""Project configuration: ``argus.toml`` / ``argus.json`` discovery and loading.

The configuration file is optional.  It exists so a repository can describe
its scan policy once instead of repeating a long command line in CI and in the
desktop UI.  Command line flags always win over configuration values.

The file is split into sections::

    [scan]      report format, severity gates, baseline, suppressions
    [sast]      engine, languages, exclusions, rule directory
    [sca]       dependency options (dev scope, offline database, ...)
    [sbom]      SBOM document metadata and defaults
    [gates]     quality gate limits and package policies
    [severity]  per-rule / per-CWE severity overrides
    [[suppress]] individual suppressed findings

Relative paths are resolved against the directory that contains the file, so
the same configuration works from any working directory.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import json
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

CONFIG_FILENAMES: Tuple[str, ...] = (
    "argus.toml",
    ".argus.toml",
    "argus.json",
    ".argus.json",
)

CONFIG_ENV = "ARGUS_CONFIG"

#: Sections that are copied to argparse defaults for every command.
_SCAN_KEYS: Dict[str, str] = {
    "format": "format",
    "output": "output",
    "summary": "summary",
    "fail_on": "fail_on",
    "min_severity": "min_severity",
    "quiet": "quiet",
    "baseline": "baseline",
    "baseline_out": "baseline_out",
    "fail_on_new": "fail_on_new",
    "include_suppressed": "include_suppressed",
    "context_lines": "context_lines",
    "no_context": "no_context",
    "ignore": "ignore",
}

_SAST_KEYS: Dict[str, str] = {
    "engine": "engine",
    "jobs": "jobs",
    "languages": "language",
    "language": "language",
    "exclude": "exclude",
    "excludes": "exclude",
    "rules": "rules",
    "java_properties": "java_properties",
}

_SCA_KEYS: Dict[str, str] = {
    "include_dev": "include_dev",
    "range_policy": "range_policy",
    "offline": "offline",
    "no_cache": "no_cache",
    "db_dir": "db_dir",
    "ecosystems": "ecosystem",
    "ecosystem": "ecosystem",
    "threat_intel": "threat_intel",
    "epss_file": "epss_file",
    "kev_file": "kev_file",
    "threat_cache_dir": "threat_cache_dir",
    "threat_ttl": "threat_ttl",
    "threat_ttl_hours": "threat_ttl",
}

_SBOM_KEYS: Dict[str, str] = {
    "format": "format",
    "output": "output",
    "summary": "summary",
    "name": "name",
    "component_version": "component_version",
    "sign_key": "sign_key",
    "sign_key_id": "sign_key_id",
    "include_dev": "include_dev",
    "range_policy": "range_policy",
    "exclude": "exclude",
    "excludes": "exclude",
    "ecosystems": "ecosystem",
    "ecosystem": "ecosystem",
    "quiet": "quiet",
}

_PATH_KEYS = {
    "baseline", "baseline_out", "rules", "java_properties", "db_dir",
    "output", "summary", "sast_cache_dir", "epss_file", "kev_file",
    "threat_cache_dir", "owasp_file",
}

_GATE_KEYS = (
    "fail_on", "fail_on_new", "max_total", "max_by_severity", "deny_packages",
    "deny_cwes", "max_cvss", "deny_licenses",
)


class ConfigError(ValueError):
    """Raised for malformed or missing configuration files."""


@dataclasses.dataclass
class Config:
    """A loaded configuration file."""

    path: str
    data: Dict[str, Any]

    @property
    def directory(self) -> str:
        return os.path.dirname(os.path.abspath(self.path))

    def section(self, name: str) -> Dict[str, Any]:
        value = self.data.get(name)
        return dict(value) if isinstance(value, Mapping) else {}

    def get(self, section: str, key: str, default: Any = None) -> Any:
        return self.section(section).get(key, default)

    def resolve(self, value: Any) -> Any:
        """Resolve a path-like value relative to the configuration directory."""
        if not isinstance(value, str) or not value:
            return value
        expanded = os.path.expanduser(value)
        if os.path.isabs(expanded):
            return expanded
        return os.path.normpath(os.path.join(self.directory, expanded))

    def suppressions(self) -> List[Any]:
        """Raw suppression entries from ``[scan].ignore`` and ``[[suppress]]``."""
        entries: List[Any] = []
        ignore = self.get("scan", "ignore")
        if isinstance(ignore, str):
            entries.append(ignore)
        elif isinstance(ignore, Iterable):
            entries.extend(ignore)
        raw = self.data.get("suppress") or self.data.get("suppressions") or []
        if isinstance(raw, Mapping):
            raw = [raw]
        if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
            entries.extend(raw)
        return list(entries)

    def severity_overrides(self) -> Dict[str, str]:
        raw = self.data.get("severity")
        if not isinstance(raw, Mapping):
            return {}
        return {str(key): str(value) for key, value in raw.items() if str(value).strip()}

    def gate_options(self) -> Dict[str, Any]:
        gates = self.section("gates")
        policies = self.section("policies")
        merged: Dict[str, Any] = {}
        for key in _GATE_KEYS:
            if key in gates:
                merged[key] = gates[key]
            elif key in policies:
                merged[key] = policies[key]
        # [scan] carries the two most common gates for backwards comfort.
        for key in ("fail_on", "fail_on_new"):
            if key in merged:
                continue
            value = self.get("scan", key)
            if value is not None:
                merged[key] = value
        return merged

    def report_options(self) -> Dict[str, Any]:
        report = self.section("report")
        scan = self.section("scan")
        options: Dict[str, Any] = {}
        for key in ("context_lines", "include_suppressed", "no_context",
                    "owasp", "owasp_version", "owasp_file"):
            if key in report:
                options[key] = report[key]
            elif key in scan:
                options[key] = scan[key]
        return options


def _minimal_toml(text: str) -> Dict[str, Any]:
    """Parse the small TOML subset used when neither ``tomllib`` nor ``tomli`` is available.

    Supported: comments, ``[table]``/``[[array]]`` headers, bare and quoted
    keys, strings, integers, floats, booleans, arrays and inline tables.  This
    is a last-resort fallback: Python 3.11+ provides ``tomllib`` and 3.10
    installs ``tomli`` through the declared dependency.
    """
    root: Dict[str, Any] = {}
    current: Dict[str, Any] = root
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]"):
            name = line[2:-2].strip().strip("\"'")
            parent = _ensure_table(root, name, list_table=False)
            bucket = parent.setdefault(name.split(".")[-1], [])
            if not isinstance(bucket, list):
                raise ConfigError(f"cannot redefine table {name!r} as an array")
            current = {}
            bucket.append(current)
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().strip("\"'")
            current = _ensure_table(root, name, list_table=False)
            continue
        if "=" not in line:
            raise ConfigError(f"cannot parse TOML line: {raw!r}")
        key, value = line.split("=", 1)
        current[_parse_key(key.strip())] = _parse_value(value.strip())
    return root


def _strip_comment(line: str) -> str:
    """Remove a TOML comment while respecting quoted strings."""
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if char in "\"'":
            quote = "" if quote == char else (char if not quote else quote)
            continue
        if char == "#" and not quote:
            return line[:index]
    return line


def _ensure_table(root: Dict[str, Any], name: str, list_table: bool) -> Dict[str, Any]:
    current = root
    parts = [part.strip().strip("\"'") for part in name.split(".")]
    for part in parts:
        value = current.get(part)
        if isinstance(value, list):
            if not value or not isinstance(value[-1], dict):
                raise ConfigError(f"invalid table path: {name!r}")
            current = value[-1]
            continue
        if value is None:
            value = {}
            current[part] = value
        if not isinstance(value, dict):
            raise ConfigError(f"invalid table path: {name!r}")
        current = value
    return current


def _parse_key(key: str) -> str:
    return key.strip().strip("\"'")


def _split_items(text: str) -> List[str]:
    items: List[str] = []
    depth = 0
    quote = ""
    escaped = False
    start = 0
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if char in "\"'":
            quote = "" if quote == char else (char if not quote else quote)
            continue
        if quote:
            continue
        if char in "[{(":
            depth += 1
        elif char in "]})":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index])
            start = index + 1
    items.append(text[start:])
    return [item.strip() for item in items if item.strip()]


def _parse_value(text: str) -> Any:
    if text.startswith('"""') and text.endswith('"""'):
        return text[3:-3]
    if text.startswith("'''") and text.endswith("'''"):
        return text[3:-3]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return _unescape(text[1:-1], text[0])
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if text.startswith("[") and text.endswith("]"):
        return [_parse_value(item) for item in _split_items(text[1:-1])]
    if text.startswith("{") and text.endswith("}"):
        table: Dict[str, Any] = {}
        for item in _split_items(text[1:-1]):
            if "=" not in item:
                raise ConfigError(f"invalid inline table entry: {item!r}")
            key, value = item.split("=", 1)
            table[_parse_key(key)] = _parse_value(value.strip())
        return table
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    if re.fullmatch(r"[+-]?(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?", text):
        return float(text)
    return text


def _unescape(value: str, quote: str) -> str:
    if quote == "'":
        return value
    return (
        value.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )


def parse_text(text: str, path: str = "<memory>") -> Dict[str, Any]:
    """Parse a TOML or JSON document based on the file name and content."""
    lowered = path.lower()
    if lowered.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: the top level must be an object")
        return data
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:  # pragma: no cover - minimal installs
            return _minimal_toml(text)
    try:
        return tomllib.loads(text)
    except Exception as exc:  # tomllib.TOMLDecodeError lives in a private module
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc


def load(path: str) -> Config:
    """Load one explicit configuration file."""
    if not os.path.isfile(path):
        raise ConfigError(f"configuration file not found: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file {path}: {exc}") from exc
    return Config(path=os.path.abspath(path), data=parse_text(text, path))


def find(start: Optional[str] = None, explicit: Optional[str] = None) -> Optional[Config]:
    """Find and load a configuration file.

    ``explicit`` (``--config``) wins.  Otherwise the file is searched from
    ``start`` upwards, then in the current directory, and finally in
    ``$ARGUS_CONFIG``.  Returns ``None`` when no file exists.
    """
    if explicit:
        return load(explicit)
    env_path = os.environ.get(CONFIG_ENV)
    if env_path:
        return load(env_path)
    directories: List[str] = []
    if start:
        current = os.path.abspath(start)
        if not os.path.isdir(current):
            current = os.path.dirname(current)
    else:
        current = os.getcwd()
    while True:
        directories.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    cwd = os.path.abspath(os.getcwd())
    if cwd not in directories:
        directories.append(cwd)
    for directory in directories:
        for name in CONFIG_FILENAMES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return load(candidate)
    return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def argparse_defaults(config: Config, command: str) -> Dict[str, Any]:
    """Return argparse defaults for ``command`` derived from the config file."""
    defaults: Dict[str, Any] = {}
    scan = config.section("scan")
    gates = config.gate_options()
    report = config.report_options()

    if command in ("scan", "sast", "sca"):
        for key, dest in _SCAN_KEYS.items():
            if key in scan:
                defaults[dest] = scan[key]
        for key, dest in (("context_lines", "context_lines"),
                          ("include_suppressed", "include_suppressed"),
                          ("no_context", "no_context"),
                          ("owasp_version", "owasp_version"),
                          ("owasp_file", "owasp_file")):
            if key in report:
                defaults[dest] = report[key]
        if "owasp" in report:
            defaults["no_owasp"] = not bool(report["owasp"])
        if gates.get("fail_on") is not None:
            defaults["fail_on"] = str(gates["fail_on"])
        if gates.get("fail_on_new") is not None:
            defaults["fail_on_new"] = bool(gates["fail_on_new"])

    if command in ("scan", "sast"):
        sast = config.section("sast")
        for key, dest in _SAST_KEYS.items():
            if key in sast:
                if dest in ("language", "exclude"):
                    defaults[dest] = _as_list(sast[key])
                else:
                    defaults[dest] = sast[key]
        if "cache" in sast:
            defaults["no_sast_cache"] = not bool(sast["cache"])
        if "cache_dir" in sast:
            defaults["sast_cache_dir"] = sast["cache_dir"]

    if command in ("scan", "sca"):
        sca = config.section("sca")
        for key, dest in _SCA_KEYS.items():
            if key in sca:
                if dest == "ecosystem":
                    defaults[dest] = _as_list(sca[key])
                elif dest == "no_cache":
                    defaults[dest] = bool(sca[key])
                else:
                    defaults[dest] = sca[key]
        if "threat_cache" in sca:
            defaults["no_threat_cache"] = not bool(sca["threat_cache"])

    if command == "scan":
        exclusions: List[str] = []
        for section in ("scan", "sast", "sca"):
            for value in _as_list(config.get(section, "exclude")):
                if str(value) not in exclusions:
                    exclusions.append(str(value))
        if exclusions:
            defaults["exclude"] = exclusions

    if command == "sbom":
        sbom = config.section("sbom")
        for key, dest in _SBOM_KEYS.items():
            if key in sbom:
                if dest in ("exclude", "ecosystem"):
                    defaults[dest] = _as_list(sbom[key])
                else:
                    defaults[dest] = sbom[key]

    if command == "diff":
        diff = config.section("diff")
        for key, dest in (("format", "format"), ("fail_on", "fail_on"),
                          ("include_suppressed", "include_suppressed"),
                          ("quiet", "quiet")):
            if key in diff:
                defaults[dest] = diff[key]
            elif key in scan:
                defaults[dest] = scan[key]

    for key in _PATH_KEYS:
        if key in defaults:
            defaults[key] = config.resolve(defaults[key])
    if "ignore" in defaults:
        defaults["ignore"] = [config.resolve(item) for item in _as_list(defaults["ignore"])]
    return defaults


def glob_match(value: str, pattern: str) -> bool:
    """Case-insensitive glob helper shared by suppressions and policies."""
    value = str(value or "").replace(os.sep, "/")
    pattern = str(pattern or "").replace(os.sep, "/")
    if fnmatch.fnmatchcase(value, pattern):
        return True
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def as_mapping(value: Any) -> Dict[str, Any]:
    """Best-effort conversion used for loosely typed suppression entries."""
    return dict(value) if isinstance(value, Mapping) else {}


def unique(items: Iterable[str]) -> List[str]:
    seen: set = set()
    result: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


__all__ = [
    "CONFIG_FILENAMES",
    "CONFIG_ENV",
    "Config",
    "ConfigError",
    "argparse_defaults",
    "find",
    "glob_match",
    "load",
    "parse_text",
]
