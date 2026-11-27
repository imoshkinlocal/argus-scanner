"""Debian package metadata: ``debian/control``, dpkg status and ``.deb`` files.

Debian has no manifest or lock file in the sense the other parsers expect: the
declared dependencies live in ``debian/control`` and the resolved ones in the
dpkg database.  This module covers both directions:

* :func:`parse_control` — build and runtime dependencies of a source package;
* :func:`parse_status` — installed binary packages from ``var/lib/dpkg/status``;
* :func:`parse_deb` — metadata of a single binary package.

Versions are Debian versions (``[epoch:]upstream[-revision]``) and are compared
with the dpkg algorithm from :mod:`argus.sca.versions`.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .parsers import Package, ParseResult, SkippedDep

#: Maximum size of a dpkg status file or ``debian/control`` we are willing to read.
MAX_DEBIAN_METADATA_BYTES = 64 * 1024 * 1024

#: Control fields that describe dependencies and the scope they map to.
DEPENDENCY_FIELDS = (
    ("build-depends", "build"),
    ("build-depends-arch", "build"),
    ("build-depends-indep", "build"),
    ("pre-depends", "runtime"),
    ("depends", "runtime"),
    ("recommends", "optional"),
    ("suggests", "dev"),
)

_SCOPE_ORDER = {"runtime": 0, "build": 1, "optional": 2, "peer": 3, "dev": 4}

_RELATION_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9+.-]*)"
    r"(?::[a-z0-9][a-z0-9-]*)?"
    r"\s*(?:\(\s*(?P<operator><<|<=|>=|>>|=|<|>)\s*(?P<version>[^)\s]+)\s*\))?$"
)
_PROFILE_RE = re.compile(r"<[^>]*>")
_ARCH_RESTRICTION_RE = re.compile(r"\[[^\]]*\]")
_SOURCE_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9+.-]*)(?:\s+\((?P<version>[^)]+)\))?$"
)
_CHANGELOG_RE = re.compile(
    r"^(?P<source>[a-z0-9][a-z0-9+.-]*)\s+\((?P<version>[^)]+)\)\s*"
    r"(?P<distribution>[^;]*);\s*urgency=(?P<urgency>\S+)"
)

#: Debian releases tracked by OSV, keyed by the numeric major version.
DEBIAN_RELEASES = {
    "9": "stretch",
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}
_CODENAME_RELEASES = {codename: major for major, codename in DEBIAN_RELEASES.items()}
_RELEASE_RE = re.compile(r"^(?P<major>\d+)(?:\.\d+)*$")


# --------------------------------------------------------------------------- suites

@dataclass(frozen=True)
class DebianSuite:
    """Debian release identity: codename plus the numeric major version.

    OSV publishes Debian advisories per release (``Debian:12``) and Debian
    packages only carry a suite, so both representations are kept together.
    """

    codename: str = ""
    major: str = ""

    @property
    def known(self) -> bool:
        """``True`` when the release maps to an OSV ecosystem."""
        return bool(self.major)

    @property
    def label(self) -> str:
        """Codename when known, otherwise the numeric release."""
        return self.codename or self.major

    @property
    def ecosystem(self) -> str:
        return f"Debian:{self.major}" if self.major else ""


def normalize_suite(value: str) -> DebianSuite:
    """Turn ``12``, ``12.5``, ``Debian:12`` or ``bookworm`` into a suite."""
    text = (value or "").strip().lower()
    if text.startswith("debian:"):
        text = text[7:]
    if not text:
        return DebianSuite()
    match = _RELEASE_RE.match(text)
    if match:
        major = match.group("major")
        return DebianSuite(DEBIAN_RELEASES.get(major, ""), major)
    if text in _CODENAME_RELEASES:
        return DebianSuite(text, _CODENAME_RELEASES[text])
    return DebianSuite(text, "")


def debian_ecosystem(distro: str) -> str:
    """Return the OSV ecosystem (``Debian:12``) for a suite, or ``""``."""
    return normalize_suite(distro).ecosystem


def _read_small(path: str) -> str:
    try:
        if os.path.getsize(path) > 1024 * 1024:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _os_release_fields(text: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if not separator:
            continue
        fields[name.strip().lower()] = value.strip().strip("\"'")
    return fields


def _suite_from_debian_version(text: str) -> DebianSuite:
    stripped = text.strip()
    if not stripped:
        return DebianSuite()
    first = stripped.splitlines()[0].strip()
    suite = normalize_suite(first)
    if suite.known:
        return suite
    # Unstable images report ``bookworm/sid`` or ``trixie/sid``.
    if "/" in first:
        return normalize_suite(first.split("/", 1)[0])
    return DebianSuite()


def _suite_from_os_release(fields: Dict[str, str]) -> DebianSuite:
    for key in ("debian_codename", "version_codename"):
        suite = normalize_suite(fields.get(key, ""))
        if suite.known:
            return suite
    suite = normalize_suite(fields.get("version_id", ""))
    if suite.known:
        return suite
    # A Debian derivative should still expose the base release in VERSION_ID.
    identifier = (fields.get("id", "") + " " + fields.get("id_like", "")).lower()
    if "debian" in identifier.split():
        return normalize_suite(fields.get("version_id", ""))
    return DebianSuite()


def detect_suite(root: Optional[str] = None) -> DebianSuite:
    """Detect the Debian release of ``root`` (a rootfs) or of the host.

    ``/etc/debian_version`` wins because it is authoritative on Debian itself;
    ``os-release`` is the fallback for minimal images.  An empty result means
    the release is unknown and Debian advisories cannot be matched safely.
    """
    base = os.path.abspath(root) if root else os.sep
    suite = _suite_from_debian_version(_read_small(os.path.join(base, "etc", "debian_version")))
    if suite.known:
        return suite
    for candidate in ("etc/os-release", "usr/lib/os-release"):
        fields = _os_release_fields(_read_small(os.path.join(base, candidate)))
        if not fields:
            continue
        suite = _suite_from_os_release(fields)
        if suite.known:
            return suite
    return DebianSuite()


# --------------------------------------------------------------------------- deb822

def stanzas(text: str) -> List[Dict[str, str]]:
    """Split a deb822 document into stanzas with lower-case field names."""
    result: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    field_name = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            if current:
                result.append(current)
                current = {}
            field_name = ""
            continue
        if line.startswith("#"):
            continue
        if line[0] in " \t":
            if field_name and current:
                current[field_name] = (current[field_name] + "\n" + line.strip()).strip()
            continue
        name, separator, value = line.partition(":")
        if not separator:
            continue
        field_name = name.strip().lower()
        current[field_name] = value.strip()
    if current:
        result.append(current)
    return result


def _split_relations(value: str) -> List[str]:
    """Split a relationship field into individual dependency items."""
    items: List[str] = []
    for group in value.replace("\n", " ").split(","):
        # "a | b" means one of the alternatives; the first one is the default.
        alternatives = [item.strip() for item in group.split("|") if item.strip()]
        if alternatives:
            items.append(alternatives[0])
    return items


def _parse_relation(item: str) -> Optional[Tuple[str, str, str]]:
    """Return ``(name, operator, version)`` or ``None`` for an unusable item."""
    text = _ARCH_RESTRICTION_RE.sub("", _PROFILE_RE.sub("", item)).strip()
    if not text or text.startswith("${"):
        return None
    match = _RELATION_RE.match(text)
    if not match:
        return None
    return match.group("name"), match.group("operator") or "", match.group("version") or ""


def _relation_version(operator: str, version: str, policy: str) -> Tuple[str, str]:
    """Resolve a Debian version constraint into ``(version, reason)``."""
    if not version:
        # Debian dependencies are usually unversioned: keep the name, the
        # exact version is only known from the dpkg database.
        return "", ""
    if operator == "=":
        return version, ""
    if policy == "skip":
        return "", "range"
    return version, "range-assumed"


def _dependency_package(rel: str, name: str, version: str, scope: str,
                        assumed: bool, parser: str) -> Package:
    return Package(name=name, version=version, ecosystem="Debian", manifest=rel,
                   scope=scope, parser=parser, assumed=assumed, direct=True)


def _append_dependencies(result: ParseResult, rel: str, value: str, scope: str,
                         policy: str, parser: str) -> None:
    for item in _split_relations(value):
        parsed = _parse_relation(item)
        if parsed is None:
            if item.strip() and not item.strip().startswith("${"):
                result.skipped.append(SkippedDep(item.strip()[:80], "unparsed-relation", rel))
            continue
        name, operator, constraint = parsed
        version, reason = _relation_version(operator, constraint, policy)
        if reason == "range":
            result.skipped.append(SkippedDep(name, "range", rel))
            continue
        result.packages.append(_dependency_package(
            rel, name, version, scope, bool(reason), parser))


def _merge_duplicates(packages: Iterable[Package]) -> List[Package]:
    merged: Dict[Tuple[str, str], Package] = {}
    for package in packages:
        key = (package.name.lower(), package.version)
        existing = merged.get(key)
        if existing is None:
            merged[key] = package
            continue
        if _SCOPE_ORDER.get(package.scope, 5) < _SCOPE_ORDER.get(existing.scope, 5):
            existing.scope = package.scope
        if package.arch and not existing.arch:
            existing.arch = package.arch
        if package.source_name and not existing.source_name:
            existing.source_name = package.source_name
            existing.source_version = package.source_version
    return list(merged.values())


# --------------------------------------------------------------------------- debian/control

def parse_control(text: str, rel: str = "debian/control",
                  range_policy: str = "min") -> ParseResult:
    """Parse a ``debian/control`` file into build and runtime dependencies."""
    result = ParseResult()
    for stanza in stanzas(text):
        if stanza.get("package"):
            # A binary package stanza declares its runtime dependencies only.
            for field_name, scope in DEPENDENCY_FIELDS[3:]:
                _append_dependencies(result, rel, stanza.get(field_name, ""), scope,
                                     range_policy, "debian-control")
        elif stanza.get("source"):
            for field_name, scope in DEPENDENCY_FIELDS[:3]:
                _append_dependencies(result, rel, stanza.get(field_name, ""), scope,
                                     range_policy, "debian-control")
    result.packages = _merge_duplicates(result.packages)
    return result


def parse_changelog(text: str) -> Optional[Dict[str, str]]:
    """Return the identity of the newest ``debian/changelog`` entry."""
    for line in text.splitlines():
        match = _CHANGELOG_RE.match(line.strip())
        if match:
            return {
                "source": match.group("source"),
                "version": match.group("version"),
                "distribution": match.group("distribution").strip(),
                "urgency": match.group("urgency"),
            }
        if line.strip():
            # The first non-empty line must be the version line.
            break
    return None


def source_identity(root: str) -> Dict[str, str]:
    """Read ``debian/changelog`` below ``root`` when it exists."""
    path = os.path.join(root, "debian", "changelog")
    try:
        if os.path.getsize(path) > MAX_DEBIAN_METADATA_BYTES:
            return {}
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            identity = parse_changelog(handle.read())
    except OSError:
        return {}
    return identity or {}


# --------------------------------------------------------------------------- dpkg status

def _read_text(path: str) -> str:
    if os.path.getsize(path) > MAX_DEBIAN_METADATA_BYTES:
        raise ValueError("metadata file is larger than %d bytes" % MAX_DEBIAN_METADATA_BYTES)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def parse_status(text: str, rel: str = "var/lib/dpkg/status",
                 distro: str = "") -> ParseResult:
    """Parse a dpkg status file and keep the installed binary packages."""
    result = ParseResult()
    packages: List[Package] = []
    for stanza in stanzas(text):
        name = stanza.get("package", "")
        version = stanza.get("version", "")
        status = stanza.get("status", "")
        if not name or not version:
            continue
        if status and not status.startswith("install ok installed"):
            continue
        source_name = ""
        source_version = ""
        source_match = _SOURCE_RE.match(stanza.get("source", "").strip())
        if source_match:
            source_name = source_match.group("name")
            source_version = source_match.group("version") or ""
            if source_name == name:
                source_name = ""
        packages.append(Package(
            name=name,
            version=version,
            ecosystem="Debian",
            manifest=rel,
            scope="runtime",
            parser="dpkg-status",
            direct=True,
            arch=stanza.get("architecture", ""),
            distro=distro,
            source_name=source_name,
            source_version=source_version,
        ))
    result.packages = packages
    return result


def parse_status_file(path: str, distro: str = "") -> ParseResult:
    """Read and parse a dpkg status file; returns an issue on failure."""
    try:
        text = _read_text(path)
    except (OSError, ValueError) as exc:
        return ParseResult(issues=[f"{path}: {exc}"])
    return parse_status(text, rel=path, distro=distro)


# --------------------------------------------------------------------------- .deb files

def _ar_members(path: str) -> Iterable[Tuple[str, bytes]]:
    """Yield ``(name, data)`` pairs of an ``ar`` archive (a Debian package)."""
    with open(path, "rb") as handle:
        if handle.read(8) != b"!<arch>\n":
            raise ValueError("not a Debian package: missing ar magic")
        while True:
            header = handle.read(60)
            if len(header) < 60:
                return
            if header[58:60] != b"`\n":
                raise ValueError("corrupt ar member header")
            name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
            try:
                size = int(header[48:58].decode("ascii", "replace").strip() or "0")
            except ValueError as exc:
                raise ValueError("corrupt ar member size") from exc
            data = handle.read(size)
            if size % 2:
                handle.read(1)
            yield name, data


def _control_from_tar(member: str, data: bytes) -> str:
    if member.endswith(".zst"):
        raise ValueError("zstd-compressed control archive needs dpkg-deb")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for entry in archive.getmembers():
                if os.path.basename(entry.name) == "control" and entry.isfile():
                    handle = archive.extractfile(entry)
                    if handle is not None:
                        return handle.read().decode("utf-8", "replace")
    except tarfile.TarError as exc:
        raise ValueError(f"cannot read {member}: {exc}") from exc
    raise ValueError("control file not found in control.tar")


def _control_pure(path: str) -> str:
    for name, data in _ar_members(path):
        if name.startswith("control.tar"):
            return _control_from_tar(name, data)
    raise ValueError("control.tar member not found")


def _control_via_dpkg(path: str) -> str:
    binary = shutil.which("dpkg-deb")
    if not binary:
        return ""
    try:
        completed = subprocess.run([binary, "-f", path], capture_output=True, text=True,
                                   timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def read_deb_control(path: str) -> str:
    """Return the control file of a ``.deb``, using dpkg-deb when available."""
    text = _control_via_dpkg(path)
    return text or _control_pure(path)


def parse_deb(path: str, distro: str = "") -> ParseResult:
    """Parse a binary ``.deb``: the package itself plus its declared dependencies."""
    rel = path
    try:
        text = read_deb_control(path)
    except (OSError, ValueError) as exc:
        return ParseResult(issues=[f"{path}: {exc}"])
    entries = stanzas(text)
    if not entries:
        return ParseResult(issues=[f"{path}: empty control file"])
    stanza = entries[0]
    name = stanza.get("package", "")
    version = stanza.get("version", "")
    if not name or not version:
        return ParseResult(issues=[f"{path}: control file has no Package or Version"])
    arch = stanza.get("architecture", "")
    package = Package(name=name, version=version, ecosystem="Debian", manifest=rel,
                      scope="runtime", parser="deb", direct=True, arch=arch,
                      distro=distro)
    result = ParseResult(packages=[package])
    dependencies: List[Package] = []
    for field_name, scope in DEPENDENCY_FIELDS[3:]:
        before = len(result.packages)
        _append_dependencies(result, rel, stanza.get(field_name, ""), scope,
                             "min", "deb")
        dependencies.extend(result.packages[before:])
    for dependency in dependencies:
        dependency.direct = False
        dependency.distro = distro
    result.packages = _merge_duplicates(result.packages)
    known = {item.key for item in result.packages}
    for dependency in dependencies:
        if dependency.key in known and dependency.key != package.key:
            result.edges.append((package.key, dependency.key))
    return result


# --------------------------------------------------------------------------- inventory

@dataclass
class DebianInventory:
    """Packages collected from dpkg databases and ``.deb`` files."""

    packages: List[Package] = field(default_factory=list)
    skipped: List[SkippedDep] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    edges: List[Tuple[Tuple[str, str, str], Tuple[str, str, str]]] = field(default_factory=list)
    manifests: List[str] = field(default_factory=list)

    def add(self, result: ParseResult, manifest: str) -> None:
        self.packages.extend(result.packages)
        self.skipped.extend(result.skipped)
        self.issues.extend(result.issues)
        self.edges.extend(result.edges)
        if result.packages and manifest not in self.manifests:
            self.manifests.append(manifest)


def _status_root(path: str) -> str:
    """Return the rootfs that owns ``<root>/var/lib/dpkg/status``, if any."""
    parts = os.path.abspath(path).split(os.sep)
    if parts[-4:] == ["var", "lib", "dpkg", "status"]:
        return os.sep.join(parts[:-4]) or os.sep
    return ""


def collect(deb_roots: Sequence[str] = (), status_files: Sequence[str] = (),
            deb_files: Sequence[str] = (), suite: str = "") -> DebianInventory:
    """Collect Debian packages from roots, status files and ``.deb`` archives.

    The suite is detected per rootfs; an explicit ``suite`` (``--deb-suite``)
    overrides detection.  A standalone status file or a ``.deb`` archive has no
    rootfs of its own, so only an explicit suite is trusted there: guessing the
    host release could match advisories of the wrong Debian release.
    """
    inventory = DebianInventory()
    explicit = normalize_suite(suite)

    for root in deb_roots:
        status = os.path.join(os.path.abspath(root), "var", "lib", "dpkg", "status")
        if not os.path.isfile(status):
            inventory.issues.append(f"{root}: no dpkg status file at {status}")
            continue
        root_suite = detect_suite(root)
        if not root_suite.known:
            root_suite = explicit
        if not root_suite.known:
            inventory.issues.append(
                f"{root}: cannot determine the Debian suite for {status}; "
                "use --deb-suite (for example --deb-suite bookworm)"
            )
        inventory.add(parse_status_file(status, distro=root_suite.label), status)
    for path in status_files:
        suite_for_file = explicit
        if not suite_for_file.known:
            root = _status_root(path)
            if root:
                suite_for_file = detect_suite(root)
        if not suite_for_file.known:
            inventory.issues.append(
                f"{path}: cannot determine the Debian suite; use --deb-suite"
            )
        inventory.add(parse_status_file(path, distro=suite_for_file.label), path)
    for path in deb_files:
        if not explicit.known:
            inventory.issues.append(
                f"{path}: cannot determine the Debian suite; use --deb-suite"
            )
        inventory.add(parse_deb(path, distro=explicit.label), path)
    return inventory
