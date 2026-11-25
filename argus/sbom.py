"""Software Bill of Materials (SBOM) generation.

The SBOM writers reuse the dependency inventory that the SCA engine builds from
manifests, so a project gets one consistent view of its components whether it is
scanned for vulnerabilities or exported as a bill of materials.

Two machine-readable formats are supported:

* **CycloneDX 1.5** (OWASP) — JSON with ``components[]`` and ``purl`` refs;
* **SPDX 2.3** (ISO/IEC 5962:2021) — JSON with ``packages[]`` and ``externalRefs``.

A third, human-readable Markdown inventory is produced for review and CI
artifacts (``argus sbom -f md`` or ``--summary``).

The output is intentionally manifest-level: components come from declared
dependency versions.  Hashes and licences are not invented when the manifests
do not contain them.  The dependency graph is only emitted when a lock file
records the resolved relations; bare manifests yield direct dependencies only.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from .models import TOOL_NAME, TOOL_URL, TOOL_VERSION
from .sca.graph import render_tree_from_data
from .sca.parsers import Package
from .sca.scanner import Inventory, SCAOptions, collect_inventory

CYCLONEDX_SPEC_VERSION = "1.5"
SPDX_VERSION = "SPDX-2.3"
SPDX_DATA_LICENSE = "CC0-1.0"

#: Lock-file digest names mapped to CycloneDX/SPDX algorithm identifiers.
_HASH_NAMES = {
    "md5": ("MD5", "MD5"),
    "sha1": ("SHA-1", "SHA1"),
    "sha256": ("SHA-256", "SHA256"),
    "sha384": ("SHA-384", "SHA384"),
    "sha512": ("SHA-512", "SHA512"),
}

_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9.+-]+$")


@dataclass
class SBOMOptions:
    """Project metadata for the SBOM document itself."""

    name: str = ""
    component_version: str = ""
    #: Optional HMAC key used to sign the document (``--sign-key``/env).
    sign_key: str = ""
    sign_key_id: str = ""


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _project_name(root: str, options: SBOMOptions) -> str:
    if options.name:
        return options.name
    name = os.path.basename(os.path.abspath(root).rstrip(os.sep))
    return name or "project"


def _components(inventory: Inventory) -> List[Package]:
    """Stable component order: ecosystem, name, version."""
    return sorted(inventory.unique.values(),
                  key=lambda package: (package.ecosystem.lower(), package.name.lower(),
                                       package.version))


def _scope(package: Package) -> str:
    return "required" if package.scope in ("runtime", "build") else "optional"


def _properties(package: Package) -> List[Dict[str, str]]:
    properties = [
        {"name": "argus:ecosystem", "value": package.ecosystem},
        {"name": "argus:scope", "value": package.scope},
        {"name": "argus:manifest", "value": package.manifest},
        {"name": "argus:parser", "value": package.parser},
        {"name": "argus:version-assumed", "value": str(bool(package.assumed)).lower()},
        {"name": "argus:direct",
         "value": "unknown" if package.direct is None else str(package.direct).lower()},
    ]
    if package.depth is not None:
        properties.append({"name": "argus:depth", "value": str(package.depth)})
    return properties


def _cyclonedx_licenses(package: Package) -> List[Dict[str, Any]]:
    """CycloneDX licence entries; SPDX ids are used when the name looks like one."""
    entries: List[Dict[str, Any]] = []
    for license_name in package.licenses:
        value = license_name.strip()
        if not value:
            continue
        if _SPDX_ID_RE.match(value) and any(char.isalpha() for char in value):
            entries.append({"license": {"id": value}})
        else:
            entries.append({"license": {"name": value}})
    return entries


def _cyclonedx_hashes(package: Package) -> List[Dict[str, str]]:
    hashes: List[Dict[str, str]] = []
    for algorithm, digest in package.hashes.items():
        names = _HASH_NAMES.get(algorithm.lower())
        if names and digest:
            hashes.append({"alg": names[0], "content": digest})
    return hashes


def _canonical(document: Dict[str, Any]) -> bytes:
    """Stable byte representation used for hashing and signing."""
    payload = {key: value for key, value in document.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_document(document: Dict[str, Any], options: SBOMOptions) -> Dict[str, Any]:
    """Attach an integrity block to a finished SBOM document.

    A SHA-256 digest is always recorded.  When ``options.sign_key`` is set the
    digest is also authenticated with HMAC-SHA256 (``HS256``), which detects
    tampering without requiring a private key distribution channel.
    """
    canonical = _canonical(document)
    digest = hashlib.sha256(canonical).hexdigest()
    signature: Dict[str, Any] = {
        "algorithm": "SHA-256",
        "created": _timestamp(),
        "sha256": digest,
        "value": "",
    }
    if options.sign_key:
        mac = hmac.new(options.sign_key.encode("utf-8"), canonical,
                       hashlib.sha256).digest()
        signature["algorithm"] = "HS256"
        signature["value"] = base64.b64encode(mac).decode("ascii")
        if options.sign_key_id:
            signature["keyId"] = options.sign_key_id
    document["signature"] = signature
    return document


def verify_document(document: Dict[str, Any], key: str = "") -> bool:
    """Return ``True`` when the embedded digest (and HMAC, when given) matches."""
    signature = document.get("signature")
    if not isinstance(signature, dict):
        return False
    canonical = _canonical(document)
    if hashlib.sha256(canonical).hexdigest() != signature.get("sha256"):
        return False
    if signature.get("algorithm") == "HS256":
        if not key:
            return False
        mac = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).digest()
        return hmac.compare_digest(base64.b64encode(mac).decode("ascii"),
                                   str(signature.get("value") or ""))
    return signature.get("algorithm") == "SHA-256"


# --------------------------------------------------------------------------- CycloneDX

def cyclonedx_document(root: str, inventory: Inventory, options: SBOMOptions) -> Dict[str, Any]:
    """Build a CycloneDX 1.5 JSON document from the inventory."""
    name = _project_name(root, options)
    project: Dict[str, Any] = {"type": "application", "name": name}
    if options.component_version:
        project["version"] = options.component_version
    components = _components(inventory)
    graph = inventory.graph
    dependencies = []
    for package in components:
        children = sorted(graph.nodes[child].purl()
                          for child in graph.children.get(package.key, []))
        dependencies.append({"ref": package.purl(), "dependsOn": children})
    document: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [
                {"vendor": TOOL_NAME, "name": TOOL_NAME, "version": TOOL_VERSION,
                 "externalReferences": [{"type": "website", "url": TOOL_URL}]}
            ],
            "component": project,
        },
        "components": [
            {
                "type": "library",
                "bom-ref": package.purl(),
                "name": package.name,
                "version": package.version,
                "purl": package.purl(),
                "scope": _scope(package),
                **({"licenses": _cyclonedx_licenses(package)}
                   if package.licenses else {}),
                **({"hashes": _cyclonedx_hashes(package)}
                   if package.hashes else {}),
                "properties": _properties(package),
            }
            for package in components
        ],
        "dependencies": dependencies,
    }
    return sign_document(document, options)


# --------------------------------------------------------------------------- SPDX

_SPDX_INVALID = re.compile(r"[^A-Za-z0-9.]+")


def _spdx_ids(packages: Sequence[Package]) -> Dict[tuple, str]:
    """Assign unique, spec-compliant SPDX identifiers to every package."""
    identifiers: Dict[tuple, str] = {}
    used = set()
    for package in packages:
        slug = _SPDX_INVALID.sub("-", package.name).strip("-.") or "package"
        candidate = f"SPDXRef-Package-{slug}"
        suffix = 2
        while candidate in used:
            candidate = f"SPDXRef-Package-{slug}-{suffix}"
            suffix += 1
        used.add(candidate)
        identifiers[package.key] = candidate
    return identifiers


def spdx_document(root: str, inventory: Inventory, options: SBOMOptions) -> Dict[str, Any]:
    """Build an SPDX 2.3 JSON document from the inventory."""
    name = _project_name(root, options)
    packages = _components(inventory)
    identifiers = _spdx_ids(packages)
    document_id = "SPDXRef-DOCUMENT"
    package_entries: List[Dict[str, Any]] = []
    for package in packages:
        declared = " AND ".join(package.licenses) if package.licenses else "NOASSERTION"
        entry: Dict[str, Any] = {
            "SPDXID": identifiers[package.key],
            "name": package.name,
            "versionInfo": package.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": declared,
            "licenseDeclared": declared,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": package.purl(),
                }
            ],
            "comment": (
                f"ecosystem={package.ecosystem}; scope={package.scope}; "
                f"manifest={package.manifest}; parser={package.parser}; "
                f"version-assumed={str(bool(package.assumed)).lower()}; "
                f"direct={'unknown' if package.direct is None else str(package.direct).lower()}; "
                f"depth={'' if package.depth is None else package.depth}"
            ),
        }
        checksums = []
        for algorithm, digest in package.hashes.items():
            names = _HASH_NAMES.get(algorithm.lower())
            if names and digest:
                checksums.append({"algorithm": names[1], "checksumValue": digest})
        if checksums:
            entry["checksums"] = checksums
        package_entries.append(entry)

    relationships: List[Dict[str, str]] = [
        {
            "spdxElementId": document_id,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": identifiers[package.key],
        }
        for package in packages
    ]
    for parent, children in inventory.graph.children.items():
        if parent not in identifiers:
            continue
        for child in children:
            if child not in identifiers:
                continue
            relationships.append({
                "spdxElementId": identifiers[parent],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": identifiers[child],
            })

    document: Dict[str, Any] = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": SPDX_DATA_LICENSE,
        "SPDXID": document_id,
        "name": f"{name}-sbom",
        "documentNamespace": f"https://argus.local/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": _timestamp(),
            "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}"],
        },
        "documentDescribes": [identifiers[package.key] for package in packages],
        "packages": package_entries,
        "relationships": relationships,
    }
    return sign_document(document, options)


# --------------------------------------------------------------------------- Markdown

def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def markdown_inventory(root: str, inventory: Inventory, options: SBOMOptions) -> str:
    """Human-readable SBOM: component table plus provenance notes."""
    name = _project_name(root, options)
    packages = _components(inventory)
    ecosystems: Dict[str, int] = {}
    assumed = 0
    licensed = 0
    for package in packages:
        ecosystems[package.ecosystem] = ecosystems.get(package.ecosystem, 0) + 1
        assumed += int(package.assumed)
        licensed += int(bool(package.licenses))
    graph = inventory.graph
    lines: List[str] = [
        f"# SBOM — {name}",
        "",
        f"* Generated: {_timestamp()}",
        f"* Tool: {TOOL_NAME} {TOOL_VERSION}",
        f"* Target: `{os.path.abspath(root)}`",
        f"* Components: **{len(packages)}**",
        f"* Direct / transitive / unknown: **{graph.direct_count} / "
        f"{graph.transitive_count} / {graph.unknown_count}**",
        f"* Dependency graph resolved from lock files: "
        f"**{'yes' if graph.resolved else 'no'}**",
        f"* Ecosystems: "
        + (", ".join(f"{key}: {value}" for key, value in sorted(ecosystems.items())) or "-"),
        f"* Versions resolved from ranges (`assumed`): **{assumed}**",
        f"* Licences: components with a declared licence: "
        f"**{licensed} / {len(packages)}**",
        f"* Integrity: **SHA-256"
        f"{' + HMAC-SHA256' if options.sign_key else ''}**",
        "",
        "## Components",
        "",
        "| Package | Version | Ecosystem | Scope | Direct | Depth | License | Hashes | Manifest | PURL | Version source |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for package in packages:
        source = "range lower bound" if package.assumed else "pinned"
        direct = "unknown" if package.direct is None else (
            "direct" if package.direct else "transitive")
        depth = "-" if package.depth is None else str(package.depth)
        license_text = ", ".join(package.licenses) or "-"
        hashes = ", ".join(f"{algorithm}:{digest[:12]}…"
                           for algorithm, digest in package.hashes.items()) or "-"
        lines.append(
            f"| {_cell(package.name)} | {_cell(package.version)} | {_cell(package.ecosystem)} | "
            f"{_cell(package.scope)} | {direct} | {depth} | {_cell(license_text)} | "
            f"{_cell(hashes)} | `{_cell(package.manifest)}` | "
            f"`{_cell(package.purl())}` | {source} |"
        )
    if not packages:
        lines.append("| _no supported manifests found_ | - | - | - | - | - | - | - | - | - | - |")

    tree = render_tree_from_data(graph.as_dict())
    if tree:
        lines.extend([
            "",
            "## Dependency tree",
            "",
            "```text",
            tree,
            "```",
        ])

    lines.extend([
        "",
        "## Notes",
        "",
        "* Direct dependencies come from manifests; edges and depths are recovered",
        "  only from lock files that record the resolved tree (Gemfile.lock,",
        "  package-lock.json, poetry.lock, uv.lock, composer.lock, Cargo.lock).",
        "* When no lock file provides relations, `Direct` is derived from the",
        "  manifest and `Depth` stays empty instead of inventing a graph.",
        "* Hashes and licences are copied from lock files only (npm `integrity`,",
        "  Composer `shasum`, Poetry/uv `hash`, Cargo `checksum`, `license` fields).",
        "  Components whose manifests do not declare them stay `NOASSERTION` / empty",
        "  rather than being filled with guesses.",
        "* Every document carries a SHA-256 `signature` block; `--sign-key`",
        "  (or `ARGUS_SBOM_KEY`) adds an HMAC-SHA256 value that can be verified with",
        "  `argus sbom verify`.",
        "* `range lower bound` means the version came from a constraint such as",
        "  `~> 1.4` (SCA `--range-policy min`); pin the dependency or use a lock file",
        "  for an exact component version.",
        "",
    ])
    if inventory.skipped:
        lines.extend(["## Skipped dependencies", ""])
        for item in inventory.skipped:
            lines.append(f"* `{_cell(item.name)}` — {_cell(item.reason)} "
                         f"(`{_cell(item.manifest)}`)")
        lines.append("")
    if inventory.issues:
        lines.extend(["## Parser issues", ""])
        for issue in inventory.issues:
            lines.append(f"* {_cell(issue)}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- helpers

def build_inventory(root: str, include_dev: bool = False, range_policy: str = "min",
                    exclude: Sequence[str] = (), ecosystems: Sequence[str] = ()) -> Inventory:
    """Convenience wrapper used by the CLI and tests."""
    options = SCAOptions(include_dev=include_dev, range_policy=range_policy,
                         exclude=tuple(exclude), ecosystems=tuple(ecosystems))
    return collect_inventory(root, options)


def dumps(document: Dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
