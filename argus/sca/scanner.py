"""High level SCA scan: discover manifests, resolve dependencies, match OSV data."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import Finding, Severity, parse_severity
from . import osv as osv_module
from .graph import DependencyGraph, build_graph
from .osv import LocalOSVDB, OSVClient, OSVError, VulnMatch, canonical_id, osv_ecosystem, osv_name, vulnerability_cwes, vulnerability_severity
from .parsers import LOCK_PARSERS, Package, SkippedDep, detect_parser, discover, parse_manifest


@dataclass
class SCAOptions:
    include_dev: bool = False
    range_policy: str = "min"  # min | skip
    offline: bool = False
    no_cache: bool = False
    db_dir: Optional[str] = None
    exclude: Sequence[str] = ()
    ecosystems: Sequence[str] = ()
    verbose: bool = False
    #: Debian package roots whose ``var/lib/dpkg/status`` should be read.
    deb_roots: Sequence[str] = ()
    #: Explicit dpkg status files to read.
    deb_status: Sequence[str] = ()
    #: Binary ``.deb`` archives to inspect.
    deb_files: Sequence[str] = ()
    #: Debian suite/codename used for packages without a detectable rootfs.
    deb_suite: str = ""


def _dedupe_packages(packages: Iterable[Package]) -> Dict[Tuple[str, str, str], Package]:
    packages = list(packages)
    # A lock file pins exact versions; manifest ranges resolved to their lower
    # bound are only an approximation.  When both describe the same package,
    # keep the pinned one instead of querying a version that may not be used.
    pinned = {(p.ecosystem, p.name.lower()) for p in packages
              if not p.assumed and p.version}
    unique: Dict[Tuple[str, str, str], Package] = {}
    order = {"runtime": 0, "build": 1, "optional": 2, "peer": 3, "dev": 4}
    for package in packages:
        if package.assumed and (package.ecosystem, package.name.lower()) in pinned:
            continue
        key = (package.ecosystem, package.name.lower(), package.version)
        existing = unique.get(key)
        if existing is None:
            unique[key] = package
            continue
        # Keep the strongest scope (runtime wins over dev/optional).
        if order.get(package.scope, 5) < order.get(existing.scope, 5):
            existing.scope = package.scope
        # A dependency declared by a manifest stays direct even when the pinned
        # instance from the lock file is the one kept in the inventory.
        if package.direct is True:
            existing.direct = True
        elif existing.direct is None and package.direct is not None:
            existing.direct = package.direct
        # Prefer the record that knows the Debian suite and source package.
        if not existing.distro and package.distro:
            existing.distro = package.distro
        if not existing.source_name and package.source_name:
            existing.source_name = package.source_name
            existing.source_version = package.source_version
        if not existing.arch and package.arch:
            existing.arch = package.arch
    return unique


@dataclass
class Inventory:
    """Dependency inventory shared by the SCA scan and SBOM generation."""

    manifests: List[str]
    packages: List[Package]
    unique: Dict[Tuple[str, str, str], Package]
    skipped: List[SkippedDep]
    issues: List[str]
    graph: DependencyGraph


def collect_inventory(root: str, options: SCAOptions, progress=None) -> Inventory:
    """Discover and parse every supported manifest under ``root``.

    The result contains the filtered package list (ecosystem and dev-scope
    filters applied) and the de-duplicated mapping used by the OSV lookup and
    by the SBOM writers.  ``graph`` links the packages using edges recovered
    from lock files; bare manifests only contribute direct dependencies.
    """
    root = os.path.abspath(root)
    manifests = discover(root, exclude=options.exclude)
    packages: List[Package] = []
    skipped: List[SkippedDep] = []
    issues: List[str] = []
    edges: List[Tuple[Tuple[str, str, str], Tuple[str, str, str]]] = []
    parsed = []
    for rel in manifests:
        result = parse_manifest(root, rel, range_policy=options.range_policy)
        packages.extend(result.packages)
        skipped.extend(result.skipped)
        issues.extend(issue for issue in result.issues if issue)
        edges.extend(result.edges)
        parsed.append((rel, result))

    if options.deb_roots or options.deb_status or options.deb_files:
        from .debian import collect as collect_debian

        debian = collect_debian(options.deb_roots, options.deb_status, options.deb_files,
                                suite=options.deb_suite)
        packages.extend(debian.packages)
        skipped.extend(debian.skipped)
        issues.extend(debian.issues)
        edges.extend(debian.edges)
        for manifest in debian.manifests:
            if manifest not in manifests:
                manifests.append(manifest)

    # An explicit suite (or the changelog target) also annotates packages
    # parsed from ``debian/control``; dpkg and ``.deb`` packages already carry
    # their own suite and keep it.
    from .debian import normalize_suite, source_identity

    suite = normalize_suite(options.deb_suite)
    if not suite.known:
        suite = normalize_suite(source_identity(root).get("distribution", ""))
    if suite.known:
        for package in packages:
            if package.ecosystem in ("Debian", "Ubuntu") and not package.distro:
                package.distro = suite.label
                package.ecosystem = suite.package_ecosystem

    # A lock file may not record which packages are direct (poetry.lock,
    # uv.lock, composer.lock, Cargo.lock).  When a sibling manifest declares a
    # package from the same directory, mark the locked instance as direct.
    declared = set()
    for rel, result in parsed:
        directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
        for package in result.packages:
            if package.parser not in LOCK_PARSERS:
                declared.add((directory, package.ecosystem, package.name.lower()))
    for rel, result in parsed:
        directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
        for package in result.packages:
            if package.parser in LOCK_PARSERS and (
                directory, package.ecosystem, package.name.lower()
            ) in declared:
                package.direct = True

    if options.ecosystems:
        allowed = {name.lower() for name in options.ecosystems}
        packages = [p for p in packages if p.ecosystem.lower() in allowed]
    if not options.include_dev:
        packages = [p for p in packages if p.scope not in ("dev", "optional", "peer")]

    unique = _dedupe_packages(packages)
    graph = build_graph(unique.values(), edges)
    if progress:
        progress(f"[sca] {len(manifests)} manifests, {len(unique)} unique packages")
    return Inventory(manifests=manifests, packages=packages, unique=unique,
                     skipped=skipped, issues=issues, graph=graph)


def _finding_from_match(match: VulnMatch) -> Finding:
    document = match.vuln
    package = match.package
    severity_name, cvss_score = vulnerability_severity(document)
    severity = parse_severity(severity_name)
    cwes = vulnerability_cwes(document)
    references = [str(ref.get("url")) for ref in document.get("references") or [] if ref.get("url")]
    summary = (document.get("summary") or "").strip() or f"Known vulnerability in {package.name}"
    details = (document.get("details") or "").strip()
    if len(details) > 4000:
        details = details[:4000] + "..."
    aliases = [str(alias) for alias in document.get("aliases") or []]
    vuln_id = str(document.get("id", ""))
    primary = canonical_id(document)
    affected_versions = []
    for affected in document.get("affected") or []:
        if (affected.get("package") or {}).get("name") == package.name:
            affected_versions.extend(str(v) for v in affected.get("versions") or [])

    message = f"{package.name} {package.version} is affected by {vuln_id}"
    if match.fixed_version:
        message += f"; fixed in {match.fixed_version}"

    return Finding(
        rule_id=primary or vuln_id,
        title=summary,
        severity=severity,
        kind="sca",
        engine="osv",
        file=package.manifest,
        message=message,
        description=details,
        cwe=cwes[0] if cwes else "",
        confidence="high",
        package=package.name,
        version=package.version,
        fixed_version=match.fixed_version,
        purl=package.purl(),
        licenses=list(package.licenses),
        aliases=sorted({vuln_id, primary, *aliases} - {""}),
        references=references[:10],
        metadata={
            "ecosystem": package.ecosystem,
            "scope": package.scope,
            "cvss_score": cvss_score,
            "cwes": cwes,
            "version_assumed": package.assumed,
            "direct": package.direct,
            "depth": package.depth,
            "published": document.get("published"),
            "modified": document.get("modified"),
            "osv_id": vuln_id,
            "affected_versions_sample": affected_versions[:20],
        },
    )


def _merge_alias_duplicates(findings: List[Finding]) -> List[Finding]:
    """Collapse advisories that describe the same CVE for the same package."""
    groups: Dict[Tuple[str, str, str], Finding] = {}
    order: List[Tuple[str, str, str]] = []
    for finding in findings:
        canonical = next((alias for alias in finding.aliases if alias.startswith("CVE-")), finding.rule_id)
        key = (finding.package.lower(), finding.version, canonical)
        existing = groups.get(key)
        if existing is None:
            groups[key] = finding
            order.append(key)
            continue
        # Prefer the record with an actual fixed version and a known severity.
        if (bool(finding.fixed_version), finding.severity.rank) > (
            bool(existing.fixed_version), existing.severity.rank
        ):
            merged_aliases = sorted(set(existing.aliases) | set(finding.aliases))
            merged_refs = list(dict.fromkeys(existing.references + finding.references))
            finding.aliases = merged_aliases
            finding.references = merged_refs[:10]
            groups[key] = finding
    return [groups[key] for key in order]


def scan(root: str, options: SCAOptions, progress=None) -> Tuple[List[Finding], Dict[str, object], List[str]]:
    """Run the SCA engine. Returns ``(findings, stats, errors)``."""
    root = os.path.abspath(root)
    errors: List[str] = []
    stats: Dict[str, object] = {}
    inventory = collect_inventory(root, options, progress=progress)
    if not inventory.manifests and not inventory.packages:
        stats.update({"manifests_scanned": 0, "packages_total": 0, "packages_unique": 0,
                      "packages_direct": 0, "packages_transitive": 0, "packages_unknown": 0,
                      "dependency_graph": inventory.graph.as_dict(),
                      "vulnerabilities": 0})
        return [], stats, errors

    errors.extend(inventory.issues)
    unique = inventory.unique

    unknown_suite = sorted({
        package.name for package in unique.values()
        if package.ecosystem in ("Debian", "Ubuntu") and not osv_ecosystem(package)
    })
    if unknown_suite:
        errors.append(
            "Debian/Ubuntu advisories need a release (OSV ecosystem "
            "Debian:<release> or Ubuntu:<YY.MM>); skipped "
            + ", ".join(unknown_suite[:10])
            + ("…" if len(unknown_suite) > 10 else "")
            + ". Pass --deb-suite (for example --deb-suite bookworm or jammy)"
        )

    matches: List[VulnMatch] = []
    database_used = None
    if unique:
        if options.offline:
            database = LocalOSVDB(directory=options.db_dir, verbose=options.verbose)
            database_used = database
            missing = sorted({p.ecosystem for p in unique.values() if not database.available(p.ecosystem)})
            if missing:
                errors.append(
                    "offline database is missing for: " + ", ".join(missing)
                    + "; run `argus db update "
                    + " ".join(f"--ecosystem {name}" for name in missing) + "`"
                )
            if len(missing) < len({p.ecosystem for p in unique.values()}):
                matches.extend(database.query(list(unique.values())))
        else:
            client = OSVClient(use_cache=not options.no_cache, verbose=options.verbose)
            try:
                matches.extend(client.query(list(unique.values())))
            except OSVError as exc:
                errors.append(str(exc))
                database = LocalOSVDB(directory=options.db_dir, verbose=options.verbose)
                database_used = database
                fallback = [p for p in unique.values() if database.available(p.ecosystem)]
                if fallback:
                    errors.append(
                        f"fell back to the offline database for {len(fallback)} package versions"
                    )
                    matches.extend(database.query(fallback))
            finally:
                client.close()

    findings = _merge_alias_duplicates([_finding_from_match(match) for match in matches])
    by_ecosystem: Dict[str, int] = {}
    licenses: Dict[str, int] = {}
    license_unknown = 0
    for package in unique.values():
        by_ecosystem[package.ecosystem] = by_ecosystem.get(package.ecosystem, 0) + 1
        if not package.licenses:
            license_unknown += 1
        for license_name in package.licenses:
            licenses[license_name] = licenses.get(license_name, 0) + 1
    graph = inventory.graph
    stats.update(
        {
            "manifests_scanned": len(inventory.manifests),
            "manifests_supported": len(inventory.manifests),
            "packages_total": len(inventory.packages),
            "packages_unique": len(unique),
            "packages_direct": graph.direct_count,
            "packages_transitive": graph.transitive_count,
            "packages_unknown": graph.unknown_count,
            "dependency_graph": graph.as_dict(),
            "vulnerabilities": len(findings),
            "by_ecosystem": by_ecosystem,
            "licenses": dict(sorted(licenses.items())),
            "license_unknown": license_unknown,
            "license_packages": {
                package.purl(): list(package.licenses)
                for package in unique.values() if package.licenses
            },
            "skipped_dependencies": len(inventory.skipped),
            "skipped_sample": [
                {"name": item.name, "reason": item.reason, "manifest": item.manifest}
                for item in inventory.skipped[:25]
            ],
            "offline": options.offline,
        }
    )
    if database_used is not None:
        stats["offline_db"] = database_used.snapshots()
    return findings, stats, errors
