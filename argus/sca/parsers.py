"""Manifest discovery and parsing for the SCA engine.

Every parser returns :class:`Package` objects with an OSV ecosystem name so the
vulnerability lookup layer stays ecosystem agnostic.  Parsers never raise on
malformed input: unsupported or unpinned entries are reported as
:class:`SkippedDep` records and surfaced in the scan statistics.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - fallback for 3.9/3.10
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:  # pragma: no cover
        _toml = None  # type: ignore


IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".bzr", ".idea", ".vs", ".vscode",
    "node_modules", "bower_components", "jspm_packages",
    ".venv", "venv", "env", ".env", "virtualenv", "site-packages",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox",
    "target", "build", "dist", "out", "bin", "obj", ".gradle", ".m2",
    ".terraform", ".serverless", "coverage", ".nyc_output", ".next", ".nuxt",
    ".cache", "vendor", "third_party", ".pc",
}

MAX_MANIFEST_BYTES = 8 * 1024 * 1024

_PURL_TYPES = {
    "Maven": "maven",
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "Packagist": "composer",
    "RubyGems": "gem",
    "crates.io": "cargo",
    "NuGet": "nuget",
    "ConanCenter": "conan",
    "Hex": "hex",
    "Debian": "deb",
    "Ubuntu": "deb",
}


@dataclass
class Package:
    """A dependency extracted from a manifest (or lock file)."""

    name: str
    version: str
    ecosystem: str
    manifest: str
    scope: str = "runtime"
    parser: str = ""
    assumed: bool = False
    #: ``True`` for a declared dependency, ``False`` for a discovered
    #: transitive one and ``None`` while it is still unknown.
    direct: Optional[bool] = None
    #: Distance from a root in the reconstructed graph (``0`` = direct).
    depth: Optional[int] = None
    #: SPDX licence identifiers or names declared by the lock file.
    licenses: List[str] = field(default_factory=list)
    #: Hex digests declared by the lock file, keyed by algorithm (``sha256``...).
    hashes: Dict[str, str] = field(default_factory=dict)
    #: Debian package architecture (``all``, ``amd64``) when known.
    arch: str = ""
    #: Debian suite/codename (``bookworm``) when known.
    distro: str = ""
    #: Debian source package, when it differs from the binary package name.
    source_name: str = ""
    #: Version of the Debian source package.
    source_version: str = ""

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.ecosystem, self.name.lower(), self.version)

    def purl(self) -> str:
        purl_type = _PURL_TYPES.get(self.ecosystem, self.ecosystem.lower())
        name = self.name
        deb_family = self.ecosystem in ("Debian", "Ubuntu")
        if self.ecosystem == "Maven" and ":" in name:
            group, artifact = name.split(":", 1)
            name = f"{quote(group, safe='.')}/{quote(artifact, safe='')}"
        elif self.ecosystem == "npm" and name.startswith("@"):
            name = "%40" + name[1:].replace("/", "%2F")
        elif deb_family:
            # The purl namespace is the distribution (``debian`` or ``ubuntu``).
            name = self.ecosystem.lower() + "/" + quote(name, safe="-._~")
        else:
            name = quote(name, safe="/-._~")
        version_safe = ".-_~" if deb_family else ".-_~+"
        version = f"@{quote(self.version, safe=version_safe)}" if self.version else ""
        qualifiers = ""
        if deb_family:
            pairs = []
            if self.arch:
                pairs.append("arch=" + quote(self.arch, safe=""))
            if self.distro:
                pairs.append("distro=" + quote(self.distro, safe=""))
            if pairs:
                qualifiers = "?" + "&".join(pairs)
        return f"pkg:{purl_type}/{name}{version}{qualifiers}"


@dataclass
class SkippedDep:
    name: str
    reason: str
    manifest: str


@dataclass
class ParseResult:
    packages: List[Package] = field(default_factory=list)
    skipped: List[SkippedDep] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    #: Resolved parent -> child links recovered from a lock file.
    edges: List[Tuple[Tuple[str, str, str], Tuple[str, str, str]]] = field(default_factory=list)


#: Parsers that describe an already resolved dependency set (lock files).  Their
#: packages are transitive by default unless the lock file marks them as roots.
LOCK_PARSERS = frozenset({
    "Gemfile.lock", "package-lock", "poetry-lock", "uv-lock", "pipfile-lock",
    "composer.lock", "Cargo.lock", "yarn.lock", "pnpm-lock", "conan-lock", "conan.lock",
})


# --------------------------------------------------------------------------- discovery

_MANIFEST_BASENAMES = {
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "pyproject.toml": "pyproject",
    "poetry.lock": "poetry-lock",
    "Pipfile": "pipfile",
    "Pipfile.lock": "pipfile-lock",
    "uv.lock": "uv-lock",
    "package.json": "npm-package",
    "package-lock.json": "npm-lock",
    "npm-shrinkwrap.json": "npm-lock",
    "yarn.lock": "yarn-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "go.mod": "go-mod",
    "composer.json": "composer-json",
    "composer.lock": "composer-lock",
    "Gemfile.lock": "gemfile-lock",
    "Gemfile": "gemfile",
    "gems.rb": "gemfile",
    "Cargo.lock": "cargo-lock",
    "conan.lock": "conan-lock",
    "conanfile.txt": "conanfile",
    "vcpkg.json": "vcpkg",
    "packages.config": "nuget-packages",
}


def _is_requirements(name: str) -> bool:
    """requirements.txt, requirements-dev.txt, requirements/prod.txt, constraints.txt."""
    lowered = name.lower()
    base = os.path.basename(lowered)
    if not lowered.endswith(".txt"):
        return False
    if base.startswith(("requirements", "constraints")):
        return True
    parts = lowered.split("/")
    return len(parts) >= 2 and parts[-2] in ("requirements", "constraints")


def detect_parser(relpath: str) -> Optional[str]:
    base = os.path.basename(relpath)
    normalized = relpath.replace(os.sep, "/")
    if normalized == "debian/control" or normalized.endswith("/debian/control"):
        return "debian-control"
    if base in _MANIFEST_BASENAMES:
        return _MANIFEST_BASENAMES[base]
    if _is_requirements(relpath) and "node_modules" not in relpath:
        return "requirements"
    if base.endswith(".csproj") or base.endswith(".fsproj") or base.endswith(".vbproj"):
        return "nuget-project"
    if base.endswith(".gemspec"):
        return "gemspec"
    return None


def discover(root: str, exclude: Iterable[str] = (), max_files: int = 0) -> List[str]:
    """Return relative paths of all supported manifests under ``root``."""
    exclude = [pattern for pattern in exclude if pattern]
    found: List[str] = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".git")
        )
        for filename in sorted(filenames):
            absolute = os.path.join(dirpath, filename)
            rel = os.path.relpath(absolute, root).replace(os.sep, "/")
            if detect_parser(rel) is None:
                continue
            if any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(filename, pattern) for pattern in exclude):
                continue
            if os.path.islink(absolute):
                continue
            found.append(rel)
            if max_files and len(found) >= max_files:
                return found
    return found


# --------------------------------------------------------------------------- helpers

def _read(path: str) -> str:
    if os.path.getsize(path) > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest is larger than {MAX_MANIFEST_BYTES} bytes")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _load_toml(path: str) -> dict:
    if _toml is None:  # pragma: no cover
        raise ValueError("tomllib/tomli is required to parse TOML manifests")
    return _toml.loads(_read(path))


def _clean_version(version: str) -> str:
    value = str(version).strip().strip("'\"")
    value = value.split()[0] if value else ""
    if value.lower().startswith("v") and len(value) > 1 and value[1].isdigit():
        value = value[1:]
    return value


def _normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


#: CycloneDX algorithm names for the digests found in lock files.
_HASH_ALGORITHMS = {"sha1", "sha256", "sha384", "sha512", "md5"}


def _licenses_from_value(value: object) -> List[str]:
    """Normalise the many licence shapes used by lock files into a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        identifier = value.get("id") or value.get("type") or value.get("name")
        return [str(identifier).strip()] if identifier else []
    if isinstance(value, (list, tuple)):
        result: List[str] = []
        for item in value:
            result.extend(_licenses_from_value(item))
        return list(dict.fromkeys(result))
    return []


def _hashes_from_integrity(value: object) -> Dict[str, str]:
    """Decode an SRI ``sha512-<base64>`` string into hex digests."""
    result: Dict[str, str] = {}
    if not isinstance(value, str):
        return result
    for token in value.split():
        algorithm, separator, encoded = token.partition("-")
        algorithm = algorithm.lower()
        if not separator or algorithm not in _HASH_ALGORITHMS:
            continue
        try:
            digest = base64.b64decode(encoded, validate=True).hex()
        except (ValueError, TypeError):
            continue
        result.setdefault(algorithm, digest)
    return result


def _hash_from_entry(value: object) -> Dict[str, str]:
    """Parse ``sha256:<hex>`` (poetry/uv) or a bare hex digest (Cargo)."""
    if not isinstance(value, str) or not value:
        return {}
    algorithm, separator, digest = value.partition(":")
    if separator and algorithm.lower() in _HASH_ALGORITHMS:
        return {algorithm.lower(): digest.strip().lower()}
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return {"sha256": value.lower()}
    return {}


_PEP508_RE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    \s*(?:\[(?P<extras>[^\]]*)\])?
    \s*(?P<spec>[^;]*?)
    \s*(?:;\s*(?P<marker>.+))?
    \s*$""",
    re.VERBOSE,
)


def _spec_to_version(spec: str, policy: str = "min") -> Tuple[Optional[str], str]:
    """Turn a PEP 440 / semver style specifier into a concrete version.

    Returns ``(version, reason)``; ``reason`` is empty when a version was found.
    """
    spec = spec.strip()
    if not spec or spec in ("*", "latest"):
        return None, "no-version"

    # Direct references and URL requirements cannot be resolved offline.
    if spec.startswith("@") or spec.startswith("://") or "://" in spec:
        return None, "url-requirement"

    parts = [part.strip() for part in spec.split(",") if part.strip()]
    exact = None
    minimum = None
    for part in parts:
        match = re.match(r"^(===|==|~=|~>|>=|>|<=|<|!=|=)?\s*([0-9][^\s]*)$", part)
        if not match:
            if part.startswith("!="):
                continue
            return None, "unparsed-specifier"
        operator = match.group(1) or "=="
        version = match.group(2).rstrip("*").strip(".")
        if operator in ("==", "===", "="):
            if "*" in match.group(2):
                minimum = version
                continue
            exact = version
        elif operator in (">=", "~=", "~>", ">") and minimum is None:
            minimum = version
    if exact:
        return exact, ""
    if policy == "skip":
        # Only exact pins are trustworthy; open ranges stay unresolved.
        return None, "range"
    if minimum:
        # The bound is a floor, not the resolved version: matches are advisory.
        return minimum, "range-assumed"
    return None, "range"


# --------------------------------------------------------------------------- Maven

def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element, name: str) -> str:
    for child in list(element):
        if _localname(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def _parse_pom(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        result.issues.append(f"{rel}: invalid XML ({exc})")
        return result

    properties: Dict[str, str] = {}
    parent_group = parent_version = ""
    for element in root.iter():
        local = _localname(element.tag)
        if local == "parent":
            parent_group = _child_text(element, "groupId")
            parent_version = _child_text(element, "version")
        if local == "properties":
            for prop in list(element):
                if prop.text:
                    properties[_localname(prop.tag)] = prop.text.strip()

    group_id = _child_text(root, "groupId") or parent_group
    version = _child_text(root, "version") or parent_version
    artifact_id = _child_text(root, "artifactId")
    properties.setdefault("project.version", version)
    properties.setdefault("project.groupId", group_id)
    properties.setdefault("project.artifactId", artifact_id)
    properties.setdefault("project.parent.version", parent_version)
    properties.setdefault("version", version)
    properties.setdefault("groupId", group_id)
    properties.setdefault("revision", version)

    def resolve(value: str, depth: int = 0) -> str:
        if not value or depth > 10:
            return value
        replaced = re.sub(r"\$\{([^}]+)\}", lambda m: properties.get(m.group(1), m.group(0)), value)
        return replaced if replaced == value else resolve(replaced, depth + 1)

    dependency_management: Dict[Tuple[str, str], str] = {}
    dependencies: List[Tuple[str, str, str, str]] = []

    def walk(element, inside_management: bool, inside_plugin: bool) -> None:
        local = _localname(element.tag)
        if local == "plugin":
            inside_plugin = True
        if local == "dependencyManagement":
            inside_management = True
        if local == "dependency":
            group = resolve(_child_text(element, "groupId"))
            artifact = resolve(_child_text(element, "artifactId"))
            dep_version = resolve(_child_text(element, "version"))
            scope = _child_text(element, "scope") or "compile"
            if group and artifact:
                if inside_management:
                    dependency_management[(group, artifact)] = dep_version
                elif not inside_plugin and scope != "import":
                    dependencies.append((group, artifact, dep_version, scope))
            return
        for child in list(element):
            walk(child, inside_management, inside_plugin)

    walk(root, False, False)

    scope_map = {"test": "dev", "provided": "build", "system": "build", "runtime": "runtime", "compile": "runtime", "import": "build"}
    for group, artifact, dep_version, scope in dependencies:
        if not dep_version:
            dep_version = dependency_management.get((group, artifact), "")
        if not dep_version or "${" in dep_version:
            result.skipped.append(SkippedDep(f"{group}:{artifact}", "unresolved-version", rel))
            continue
        result.packages.append(
            Package(
                name=f"{group}:{artifact}",
                version=dep_version,
                ecosystem="Maven",
                manifest=rel,
                scope=scope_map.get(scope, "runtime"),
                parser="pom",
            )
        )
    return result


_GRADLE_STRING_DEP = re.compile(
    r"""(?:^|[^\w.])(implementation|api|compile|compileOnly|runtimeOnly|testImplementation\b|testCompile\b|annotationProcessor|kapt|classpath)"""
    r"""\s*[\(\s]\s*(?:platform\s*\(\s*)?(?:enforcedPlatform\s*\(\s*)?['"]([^'"\s]+)['"]""",
    re.MULTILINE,
)
_GRADLE_MAP_DEP = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|testImplementation|classpath)\s*[\(\s]\s*group\s*:\s*['"]([^'"]+)['"]\s*,\s*name\s*:\s*['"]([^'"]+)['"]\s*,\s*version\s*:\s*['"]([^'"]+)['"]"""
)


def _parse_gradle(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    seen = set()

    def add(coord: str, scope: str) -> None:
        if "$" in coord or "@" in coord:
            result.skipped.append(SkippedDep(coord, "dynamic-version", rel))
            return
        parts = coord.split(":")
        if len(parts) < 3:
            result.skipped.append(SkippedDep(coord, "unparsed-coordinate", rel))
            return
        name = f"{parts[0]}:{parts[1]}"
        version = parts[2]
        if not re.match(r"^[0-9]", version):
            result.skipped.append(SkippedDep(coord, "non-numeric-version", rel))
            return
        key = (name, version)
        if key in seen:
            return
        seen.add(key)
        result.packages.append(
            Package(name=name, version=version, ecosystem="Maven", manifest=rel,
                    scope=scope, parser="gradle")
        )

    for match in _GRADLE_STRING_DEP.finditer(text):
        configuration, coord = match.group(1), match.group(2)
        scope = "dev" if configuration.startswith("test") else (
            "build" if configuration in ("compileOnly", "annotationProcessor", "kapt", "classpath") else "runtime"
        )
        add(coord, scope)
    for match in _GRADLE_MAP_DEP.finditer(text):
        add(f"{match.group(1)}:{match.group(2)}:{match.group(3)}", "runtime")
    return result


# --------------------------------------------------------------------------- Python

def _parse_requirements(text: str, rel: str, policy: str) -> ParseResult:
    result = ParseResult()
    seen = set()
    for raw_line in text.replace("\\\n", " ").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            if line.startswith(("-e", "--editable")):
                result.skipped.append(SkippedDep(line[:80], "editable-install", rel))
            continue
        line = line.split(" --hash", 1)[0].strip()
        match = _PEP508_RE.match(line)
        if not match:
            result.skipped.append(SkippedDep(line[:80], "unparsed-requirement", rel))
            continue
        raw_name = match.group("name")
        name = _normalize_pypi(raw_name)
        spec = match.group("spec") or ""
        version, reason = _spec_to_version(spec, policy)
        if not version:
            result.skipped.append(SkippedDep(name, reason or "no-version", rel))
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        result.packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="PyPI",
                manifest=rel,
                scope="runtime",
                parser="requirements",
                assumed=bool(reason),
            )
        )
    return result


_POETRY_PRE_RE = re.compile(r"^(\^|~|>=|==|=|>|<=|<)?\s*v?([0-9][^\s,]*)")


def _parse_poetry_spec(spec: str, policy: str) -> Tuple[Optional[str], str]:
    if policy == "skip":
        return None, "range"
    spec = spec.strip()
    if not spec or spec in ("*", "latest"):
        return None, "no-version"
    if spec.startswith(("git+", "http://", "https://", "file:")):
        return None, "url-requirement"
    spec = spec.split(",")[0].strip()
    match = _POETRY_PRE_RE.match(spec)
    if not match:
        return None, "unparsed-specifier"
    return _clean_version(match.group(2)), ""


def _add_python_dep(result: ParseResult, rel: str, name: str, version_spec: str,
                    policy: str, scope: str) -> None:
    if name.lower() == "python":
        return
    normalized = _normalize_pypi(name)
    version, reason = _spec_to_version(version_spec, policy) if version_spec else (None, "no-version")
    if not version:
        result.skipped.append(SkippedDep(normalized, reason, rel))
        return
    result.packages.append(
        Package(name=normalized, version=version, ecosystem="PyPI", manifest=rel,
                scope=scope, parser="pyproject", assumed=bool(reason))
    )


def _parse_pyproject(text: str, rel: str, policy: str) -> ParseResult:
    result = ParseResult()
    try:
        data = _toml.loads(text)
    except Exception as exc:  # noqa: BLE001 - malformed manifests must not abort the scan
        result.issues.append(f"{rel}: invalid TOML ({exc})")
        return result

    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        match = _PEP508_RE.match(str(spec))
        if match:
            _add_python_dep(result, rel, match.group("name"), match.group("spec") or "",
                            policy, "runtime")
    for group, specs in (project.get("optional-dependencies") or {}).items():
        scope = "dev" if group.lower() in ("dev", "test", "tests", "testing") else "optional"
        for spec in specs or []:
            match = _PEP508_RE.match(str(spec))
            if match:
                _add_python_dep(result, rel, match.group("name"), match.group("spec") or "",
                                policy, scope)

    poetry = (((data.get("tool") or {}).get("poetry")) or {})
    _poetry_section(result, rel, poetry.get("dependencies") or {}, policy, "runtime")
    _poetry_section(result, rel, poetry.get("dev-dependencies") or {}, policy, "dev")
    for group, payload in ((poetry.get("group") or {}) or {}).items():
        if isinstance(payload, dict):
            _poetry_section(result, rel, payload.get("dependencies") or {}, policy,
                            "dev" if group in ("dev", "test") else "optional")

    for group, specs in (((data.get("dependency-groups")) or {})).items():
        if isinstance(specs, list):
            for spec in specs:
                if isinstance(spec, str):
                    match = _PEP508_RE.match(spec)
                    if match:
                        _add_python_dep(result, rel, match.group("name"), match.group("spec") or "",
                                        policy, "dev")
    return result


def _poetry_section(result: ParseResult, rel: str, section: dict, policy: str, scope: str) -> None:
    for name, value in section.items():
        entry_scope = scope
        if isinstance(value, dict):
            if value.get("optional"):
                entry_scope = "optional"
            spec = str(value.get("version", ""))
        else:
            spec = str(value)
        _add_python_dep(result, rel, name, spec, policy, entry_scope)


def _parse_poetry_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = _toml.loads(text)
    except Exception as exc:  # noqa: BLE001
        result.issues.append(f"{rel}: invalid TOML ({exc})")
        return result
    parsed: List[Tuple[dict, Package]] = []
    by_name: Dict[str, Package] = {}
    for entry in data.get("package") or []:
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        groups = entry.get("groups") or []
        scope = "dev" if entry.get("category") == "dev" or (
            groups and "main" not in groups) else "runtime"
        package = Package(name=_normalize_pypi(name), version=str(version),
                          ecosystem="PyPI", manifest=rel, parser="poetry-lock",
                          scope=scope)
        for item in entry.get("files") or []:
            if isinstance(item, dict):
                package.hashes.update(_hash_from_entry(item.get("hash")))
        parsed.append((entry, package))
        by_name.setdefault(package.name, package)

    for entry, package in parsed:
        dependencies = entry.get("dependencies") or {}
        if isinstance(dependencies, dict):
            names = list(dependencies)
        elif isinstance(dependencies, list):
            names = [item.get("name") for item in dependencies if isinstance(item, dict)]
        else:
            names = []
        for name in names:
            if not name:
                continue
            child = by_name.get(_normalize_pypi(str(name)))
            if child is not None and child.key != package.key:
                result.edges.append((package.key, child.key))
        result.packages.append(package)
    return result


def _parse_pipfile_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        for name, payload in (data.get(section) or {}).items():
            version = str((payload or {}).get("version", "")).lstrip("=")
            if version and re.match(r"^[0-9]", version):
                result.packages.append(Package(name=_normalize_pypi(name), version=version,
                                               ecosystem="PyPI", manifest=rel,
                                               scope=scope, parser="pipfile-lock"))
    return result


def _parse_uv_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = _toml.loads(text)
    except Exception as exc:  # noqa: BLE001
        result.issues.append(f"{rel}: invalid TOML ({exc})")
        return result
    parsed: List[Tuple[dict, Package]] = []
    by_name: Dict[str, Package] = {}
    for entry in data.get("package") or []:
        name, version = entry.get("name"), entry.get("version")
        if not name or not version:
            continue
        source = entry.get("source") or {}
        if source.get("editable") or source.get("directory"):
            continue
        package = Package(name=_normalize_pypi(name), version=str(version),
                          ecosystem="PyPI", manifest=rel, parser="uv-lock")
        sdist = entry.get("sdist")
        if isinstance(sdist, dict):
            package.hashes.update(_hash_from_entry(sdist.get("hash")))
        parsed.append((entry, package))
        by_name.setdefault(package.name, package)

    for entry, package in parsed:
        dependencies = entry.get("dependencies") or []
        names = []
        if isinstance(dependencies, list):
            names = [item.get("name") for item in dependencies if isinstance(item, dict)]
        elif isinstance(dependencies, dict):
            names = list(dependencies)
        for name in names:
            if not name:
                continue
            child = by_name.get(_normalize_pypi(str(name)))
            if child is not None and child.key != package.key:
                result.edges.append((package.key, child.key))
        result.packages.append(package)
    return result


# --------------------------------------------------------------------------- npm

_EXACT_SEMVER = re.compile(r"^v?=?\s*([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$")


def _parse_package_json(text: str, rel: str, policy: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                           ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            if spec.startswith(("file:", "link:", "workspace:", "npm:", "git", "http")):
                result.skipped.append(SkippedDep(name, "non-registry-dependency", rel))
                continue
            match = _EXACT_SEMVER.match(spec)
            if match and "lock" not in rel:
                result.packages.append(Package(name=name, version=match.group(1), ecosystem="npm",
                                               manifest=rel, scope=scope, parser="package.json"))
                continue
            if policy == "skip":
                result.skipped.append(SkippedDep(name, "range", rel))
                continue
            # Prefer an exact version mentioned in the range (e.g. "4.17.21") only
            # when the range is effectively pinned; otherwise record as unresolved.
            pinned = re.match(r"^[=~^]?\s*v?([0-9]+\.[0-9]+\.[0-9]+)$", spec)
            if pinned:
                result.packages.append(Package(name=name, version=pinned.group(1), ecosystem="npm",
                                               manifest=rel, scope=scope, parser="package.json",
                                               assumed=True))
            else:
                result.skipped.append(SkippedDep(name, "range", rel))
    return result


def _parse_package_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result

    packages = data.get("packages")
    if isinstance(packages, dict):
        entries: Dict[str, Package] = {}
        payloads: Dict[str, dict] = {}
        for path, payload in packages.items():
            if not isinstance(payload, dict) or not path:
                continue
            version = payload.get("version")
            name = payload.get("name")
            if not name:
                name = path.rsplit("node_modules/", 1)[-1]
            if not name or not version or payload.get("link"):
                continue
            scope = "dev" if payload.get("dev") else (
                "optional" if payload.get("optional") else "runtime")
            entries[path] = Package(name=name, version=str(version), ecosystem="npm",
                                    manifest=rel, scope=scope, parser="package-lock",
                                    licenses=_licenses_from_value(payload.get("license")),
                                    hashes=_hashes_from_integrity(payload.get("integrity")))
            payloads[path] = payload

        def resolve(path: str, name: str) -> Optional[Package]:
            """Node resolution: nearest ``node_modules`` walking up from ``path``."""
            base = path
            while True:
                candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
                if candidate in entries:
                    return entries[candidate]
                if not base:
                    return None
                index = base.rfind("/node_modules/")
                base = base[:index] if index != -1 else ""

        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        root_names = list((root.get("dependencies") or {}))
        for name in root_names:
            child = resolve("", name)
            if child is not None:
                child.direct = True
        if not root_names:
            for path, package in entries.items():
                if path.count("node_modules/") == 1:
                    package.direct = True

        for path, package in entries.items():
            for name in (payloads[path].get("dependencies") or {}):
                child = resolve(path, name)
                if child is not None and child.key != package.key:
                    result.edges.append((package.key, child.key))
        result.packages.extend(entries.values())
        return result

    # lockfileVersion 1: the nested ``dependencies`` objects are the resolved tree.
    def walk(deps: dict, parent: Optional[Package], top: bool) -> None:
        for name, payload in (deps or {}).items():
            if not isinstance(payload, dict):
                continue
            version = payload.get("version")
            package = parent
            if version and re.match(r"^[0-9]", str(version)):
                package = Package(name=name, version=str(version), ecosystem="npm",
                                  manifest=rel, scope="runtime", parser="package-lock",
                                  direct=top,
                                  licenses=_licenses_from_value(payload.get("license")),
                                  hashes=_hashes_from_integrity(payload.get("integrity")))
                result.packages.append(package)
                if parent is not None and parent.key != package.key:
                    result.edges.append((parent.key, package.key))
            walk(payload.get("dependencies") or {}, package, False)

    walk(data.get("dependencies") or {}, None, True)
    return result


_YARN_BLOCK_RE = re.compile(r'^("?[^\s#].*?"?):\s*$')
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _parse_yarn_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    current_specs: List[str] = []
    seen = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        header = _YARN_BLOCK_RE.match(line)
        if header and not line.startswith(" "):
            specs = header.group(1).strip('"').split(",")
            current_specs = [spec.strip().strip('"') for spec in specs]
            continue
        version_match = _YARN_VERSION_RE.match(line)
        if version_match and current_specs:
            version = version_match.group(1)
            name = _yarn_package_name(current_specs[0])
            if name and re.match(r"^[0-9]", version) and (name, version) not in seen:
                seen.add((name, version))
                result.packages.append(Package(name=name, version=version, ecosystem="npm",
                                               manifest=rel, parser="yarn.lock"))
            current_specs = []
    return result


def _yarn_package_name(spec: str) -> str:
    spec = spec.strip().strip('"')
    if spec.startswith("@"):
        parts = spec.split("@", 2)
        if len(parts) >= 2:
            return "@" + parts[1]
        return ""
    return spec.split("@", 1)[0]


_PNPM_V5_RE = re.compile(r"^\s{2}'?/((?:@[^/'\"]+/)?[^/'\"]+)/([^/:'\"_(]+)(?:\([^)]*\)|_[^(]*)?'?:\s*$")
_PNPM_V6_RE = re.compile(r"^\s{2}'?/((?:@[^/'\"]+/)?[^/'\"]+)@([^:'\"_(]+)(?:\([^)]*\))?'?:\s*$")
_PNPM_V9_RE = re.compile(r"^\s{2}'?((?:@[^/'\"]+/)?[^/'\"]+)@([^:'\"_(]+)(?:\([^)]*\))?'?:\s*$")


def _parse_pnpm_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    seen = set()
    for line in text.splitlines():
        if not line.startswith("  ") or line.startswith("    "):
            continue
        for pattern in (_PNPM_V5_RE, _PNPM_V6_RE, _PNPM_V9_RE):
            match = pattern.match(line)
            if match:
                name, version = match.group(1), match.group(2)
                if name == "lockfileVersion" or not re.match(r"^[0-9]", version):
                    break
                if (name, version) in seen:
                    break
                seen.add((name, version))
                result.packages.append(Package(name=name, version=version, ecosystem="npm",
                                               manifest=rel, parser="pnpm-lock"))
                break
    return result


# --------------------------------------------------------------------------- Go

def _parse_go_mod(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    in_require = False
    for raw_line in text.splitlines():
        indirect = "// indirect" in raw_line
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if not re.match(r"^v?[0-9]", version):
            result.skipped.append(SkippedDep(f"{module}@{version}", "non-semver-version", rel))
            continue
        result.packages.append(Package(name=module, version=version, ecosystem="Go",
                                       manifest=rel, parser="go.mod",
                                       direct=not indirect))
    return result


# --------------------------------------------------------------------------- PHP / Ruby / Rust

def _parse_composer_json(text: str, rel: str, policy: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, spec in (data.get(section) or {}).items():
            if name == "php" or "/" not in name:
                continue
            spec = str(spec)
            version, reason = _spec_to_version(spec.lstrip("^~"), policy if policy != "min" else "min")
            if not version:
                result.skipped.append(SkippedDep(name, reason or "range", rel))
                continue
            result.packages.append(Package(name=name, version=_clean_version(version),
                                           ecosystem="Packagist", manifest=rel, scope=scope,
                                           parser="composer.json", assumed=True))
    return result


def _parse_composer_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result
    parsed: List[Tuple[dict, Package]] = []
    by_name: Dict[str, Package] = {}
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for entry in data.get(section) or []:
            name, version = entry.get("name"), entry.get("version")
            if not name or not version:
                continue
            package = Package(name=name, version=_clean_version(version),
                              ecosystem="Packagist", manifest=rel,
                              scope=scope, parser="composer.lock",
                              licenses=_licenses_from_value(entry.get("license")))
            dist = entry.get("dist") if isinstance(entry.get("dist"), dict) else {}
            shasum = str(dist.get("shasum") or "")
            if re.fullmatch(r"[0-9a-fA-F]{40}", shasum):
                package.hashes["sha1"] = shasum.lower()
            parsed.append((entry, package))
            by_name.setdefault(name.lower(), package)

    for entry, package in parsed:
        for dependency in (entry.get("require") or {}):
            lowered = dependency.lower()
            if lowered == "php" or lowered.startswith(("ext-", "lib-", "composer-")):
                continue
            child = by_name.get(lowered)
            if child is not None and child.key != package.key:
                result.edges.append((package.key, child.key))
        result.packages.append(package)
    return result


_GEM_SPEC_RE = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$")


def _parse_gemfile_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    current_section = ""
    current_spec: Optional[str] = None
    specs: Dict[str, Package] = {}
    dependencies: Dict[str, List[str]] = {}
    direct_names = set()
    for line in text.splitlines():
        if line and not line.startswith(" "):
            current_section = line.strip()
            current_spec = None
            continue
        if current_section == "DEPENDENCIES":
            stripped = line.strip()
            if stripped:
                direct_names.add(re.split(r"[\s!(]", stripped, 1)[0].rstrip("!"))
            continue
        if current_section not in ("GEM", "GIT", "PATH"):
            continue
        match = _GEM_SPEC_RE.match(line)
        if match:
            name, version = match.group(1), match.group(2)
            current_spec = name
            dependencies.setdefault(name, [])
            if current_section == "GEM":
                specs[name] = Package(
                    name=name,
                    version=_clean_version(version.split("-")[0] if version[0].isdigit() else version),
                    ecosystem="RubyGems", manifest=rel, parser="Gemfile.lock",
                )
            continue
        # Indented dependency line below a spec: "      actionpack (= 5.2.0)".
        if current_spec and line.startswith("      "):
            dependency = line.strip().split(" ", 1)[0].rstrip("!")
            if dependency:
                dependencies[current_spec].append(dependency)

    for name, package in specs.items():
        if direct_names:
            package.direct = name in direct_names
        for dependency in dependencies.get(name, []):
            child = specs.get(dependency)
            if child is not None and child.key != package.key:
                result.edges.append((package.key, child.key))
        result.packages.append(package)
    return result


# --------------------------------------------------------------------------- Ruby (Gemfile / gemspec)
#
# ``Gemfile`` and ``*.gemspec`` are Ruby DSL files, not data files.  Both are
# read line by line: the parser keeps track of ``group ... do`` blocks for the
# Gemfile and of ``add_*_dependency`` calls for the gemspec.  Conditional
# dependencies (``unless java_p``) cannot be evaluated statically, so they are
# recorded as if the condition held.

_GEMFILE_GEM_RE = re.compile(
    r"""^\s*gem\s*\(?\s*['"](?P<name>[^'"]+)['"](?P<rest>.*)$"""
)
_GEMFILE_GROUP_RE = re.compile(r"""^\s*group\s+(?P<groups>.+?)\s+do\s*$""")
_GEMFILE_BLOCK_RE = re.compile(r"""\bdo\s*(?:\|[^|]*\|)?\s*$""")
_GEMSPEC_DEP_RE = re.compile(
    r"""(?P<call>add(?:_runtime|_development)?_dependency)\s*\(?\s*"""
    r"""['"](?P<name>[^'"]+)['"](?P<rest>[^)]*)"""
)
_RUBY_QUOTED_RE = re.compile(r"""['"]([^'"]+)['"]""")
_DEV_GROUPS = {"development", "test", "tests", "testing"}


def _strip_ruby_comment(line: str) -> str:
    """Drop a trailing ``# ...`` comment while respecting quoted strings."""
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char == "#":
            return line[:index]
    return line


def _ruby_version_spec(text: str) -> str:
    """Return the first version-like quoted string (``"~> 1.4"``) in ``text``."""
    for candidate in _RUBY_QUOTED_RE.findall(text or ""):
        value = candidate.strip()
        if re.search(r"\d", value):
            return value
    return ""


def _add_ruby_dep(result: ParseResult, rel: str, name: str, spec: str, policy: str,
                  scope: str, parser: str) -> None:
    version, reason = _spec_to_version(spec, policy) if spec else (None, "no-version")
    if not version:
        result.skipped.append(SkippedDep(name, reason or "no-version", rel))
        return
    result.packages.append(
        Package(name=name, version=version, ecosystem="RubyGems", manifest=rel,
                scope=scope, parser=parser, assumed=bool(reason))
    )


def _parse_gemfile(text: str, rel: str, policy: str) -> ParseResult:
    result = ParseResult()
    stack: List[Optional[str]] = []
    for raw_line in text.splitlines():
        line = _strip_ruby_comment(raw_line).rstrip()
        if not line.strip():
            continue
        group = _GEMFILE_GROUP_RE.match(line)
        if group:
            names = {item.strip().lstrip(":").lower() for item in group.group("groups").split(",")}
            stack.append("dev" if names & _DEV_GROUPS else "runtime")
            continue
        if line.strip() == "end":
            if stack:
                stack.pop()
            continue
        if _GEMFILE_BLOCK_RE.search(line):
            # ``platforms :mri do`` and friends: keep the stack balanced but do
            # not change the dependency scope.
            stack.append(None)
            continue
        match = _GEMFILE_GEM_RE.match(line)
        if not match:
            continue
        scope = next((item for item in reversed(stack) if item), "runtime")
        _add_ruby_dep(result, rel, match.group("name").strip(),
                      _ruby_version_spec(match.group("rest")), policy, scope, "gemfile")
    return result


def _parse_gemspec(text: str, rel: str, policy: str) -> ParseResult:
    result = ParseResult()
    for raw_line in text.splitlines():
        line = _strip_ruby_comment(raw_line)
        for match in _GEMSPEC_DEP_RE.finditer(line):
            scope = "dev" if "development" in match.group("call") else "runtime"
            spec = _ruby_version_spec(match.group("rest"))
            _add_ruby_dep(result, rel, match.group("name"), spec, policy, scope, "gemspec")
    return result


def _parse_cargo_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = _toml.loads(text)
    except Exception as exc:  # noqa: BLE001
        result.issues.append(f"{rel}: invalid TOML ({exc})")
        return result
    parsed: List[Tuple[dict, Package]] = []
    by_name: Dict[str, List[Package]] = {}
    for entry in data.get("package") or []:
        source = str(entry.get("source") or "")
        if source and "crates.io" not in source:
            continue
        name, version = entry.get("name"), entry.get("version")
        if not name or not version:
            continue
        # Workspace members have no ``source`` and are graph roots, not deps.
        package = Package(name=str(name), version=str(version),
                          ecosystem="crates.io", manifest=rel, parser="Cargo.lock",
                          direct=True if not source else None,
                          hashes=_hash_from_entry(entry.get("checksum")))
        parsed.append((entry, package))
        by_name.setdefault(str(name), []).append(package)

    for entry, package in parsed:
        for dependency in entry.get("dependencies") or []:
            parts = str(dependency).split()
            if not parts:
                continue
            candidates = by_name.get(parts[0]) or []
            child: Optional[Package] = None
            if len(parts) > 1:
                child = next((item for item in candidates if item.version == parts[1]), None)
            elif len(candidates) == 1:
                child = candidates[0]
            if child is not None and child.key != package.key:
                result.edges.append((package.key, child.key))
        result.packages.append(package)
    return result


# --------------------------------------------------------------------------- C/C++ / .NET

def _parse_conan_lock(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result

    refs: List[str] = []

    def collect(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "ref" and isinstance(value, str):
                    refs.append(value)
                else:
                    collect(value)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, str):
                    refs.append(item)
                else:
                    collect(item)

    collect(data.get("graph_lock") or data.get("requires") or data)

    for ref in refs:
        match = re.match(r"^([A-Za-z0-9_.\-]+)/([0-9][^#@]*)", ref)
        if not match:
            continue
        result.packages.append(Package(name=match.group(1), version=match.group(2).strip(),
                                       ecosystem="ConanCenter", manifest=rel, parser="conan.lock"))
    return result


def _parse_conanfile(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    in_requires = False
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_requires = stripped.lower() == "[requires]"
            continue
        if not in_requires or not stripped:
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)/([0-9][^@]*)", stripped)
        if match:
            result.packages.append(Package(name=match.group(1), version=match.group(2).strip(),
                                           ecosystem="ConanCenter", manifest=rel, parser="conanfile"))
    return result


def _parse_vcpkg(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.issues.append(f"{rel}: invalid JSON ({exc})")
        return result
    names = []
    for dep in data.get("dependencies") or []:
        if isinstance(dep, str):
            names.append(dep)
        elif isinstance(dep, dict) and dep.get("name"):
            names.append(dep["name"])
    if names:
        result.issues.append(
            f"{rel}: vcpkg is not indexed by OSV; {len(names)} dependencies were not checked "
            f"({', '.join(names[:5])}{'...' if len(names) > 5 else ''})"
        )
    return result


def _parse_nuget_packages(text: str, rel: str) -> ParseResult:
    result = ParseResult()
    if rel.endswith(".config"):
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            result.issues.append(f"{rel}: invalid XML ({exc})")
            return result
        for element in root.iter():
            if _localname(element.tag) != "package":
                continue
            name = element.attrib.get("id")
            version = element.attrib.get("version")
            if name and version:
                result.packages.append(Package(name=name, version=version, ecosystem="NuGet",
                                               manifest=rel, parser="packages.config"))
        return result

    # *.csproj
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        result.issues.append(f"{rel}: invalid XML ({exc})")
        return result
    for element in root.iter():
        if _localname(element.tag) != "PackageReference":
            continue
        name = element.attrib.get("Include") or element.attrib.get("Update")
        version = element.attrib.get("Version") or _child_text(element, "Version")
        if name and version and "$" not in version:
            result.packages.append(Package(name=name, version=version, ecosystem="NuGet",
                                           manifest=rel, parser="csproj"))
    return result


# --------------------------------------------------------------------------- dispatch

def parse_manifest(root: str, rel: str, range_policy: str = "min") -> ParseResult:
    """Parse a single manifest. Raises ``OSError`` if the file is unreadable."""
    kind = detect_parser(rel)
    if not kind:
        return ParseResult(issues=[f"{rel}: unsupported manifest type"])
    path = os.path.join(root, rel)
    try:
        text = _read(path)
    except (OSError, ValueError) as exc:
        return ParseResult(issues=[f"{rel}: {exc}"])

    if kind == "maven":
        return _parse_pom(text, rel)
    if kind == "gradle":
        return _parse_gradle(text, rel)
    if kind == "requirements":
        return _parse_requirements(text, rel, range_policy)
    if kind == "pyproject":
        return _parse_pyproject(text, rel, range_policy)
    if kind == "poetry-lock":
        return _parse_poetry_lock(text, rel)
    if kind == "uv-lock":
        return _parse_uv_lock(text, rel)
    if kind == "pipfile-lock":
        return _parse_pipfile_lock(text, rel)
    if kind == "pipfile":
        return ParseResult(skipped=[SkippedDep("Pipfile", "no-lock-file", rel)])
    if kind == "npm-package":
        return _parse_package_json(text, rel, range_policy)
    if kind == "npm-lock":
        return _parse_package_lock(text, rel)
    if kind == "yarn-lock":
        return _parse_yarn_lock(text, rel)
    if kind == "pnpm-lock":
        return _parse_pnpm_lock(text, rel)
    if kind == "go-mod":
        return _parse_go_mod(text, rel)
    if kind == "composer-json":
        return _parse_composer_json(text, rel, range_policy)
    if kind == "composer-lock":
        return _parse_composer_lock(text, rel)
    if kind == "gemfile-lock":
        return _parse_gemfile_lock(text, rel)
    if kind == "gemfile":
        return _parse_gemfile(text, rel, range_policy)
    if kind == "gemspec":
        return _parse_gemspec(text, rel, range_policy)
    if kind == "cargo-lock":
        return _parse_cargo_lock(text, rel)
    if kind == "conan-lock":
        return _parse_conan_lock(text, rel)
    if kind == "conanfile":
        return _parse_conanfile(text, rel)
    if kind == "vcpkg":
        return _parse_vcpkg(text, rel)
    if kind in ("nuget-packages", "nuget-project"):
        return _parse_nuget_packages(text, rel)
    if kind == "debian-control":
        from .debian import parse_control

        return parse_control(text, rel, range_policy)
    return ParseResult(issues=[f"{rel}: unsupported manifest type"])
