"""Debian metadata: deb822 parsing, dpkg versions, suites and OSV mapping."""

from __future__ import annotations

import io
import json
import os
import tarfile
import zipfile

import pytest

from argus.sca import versions
from argus.sca.debian import (
    _control_pure,
    collect,
    debian_ecosystem,
    detect_suite,
    normalize_suite,
    parse_changelog,
    parse_control,
    parse_deb,
    parse_status,
    source_identity,
    stanzas,
)
from argus.sca.osv import (
    LocalOSVDB,
    OSVClient,
    build_matches,
    osv_archive,
    osv_ecosystem,
)
from argus.sca.parsers import Package
from argus.sca.scanner import SCAOptions, collect_inventory
from argus.sbom import SBOMOptions, cyclonedx_document

CONTROL = """\
Source: demo
Maintainer: Demo <demo@example.org>
Build-Depends: debhelper-compat (= 13),
 python3 (>= 3.10),
 libc6-dev:native
Build-Depends-Indep: graphviz <!nocheck>

Package: demo
Architecture: any
Depends: libc6 (>= 2.31), libfoo | libbar
Recommends: extra-tool
Suggests: demo-doc
Description: demo package
 long description
"""

STATUS = """\
Package: openssl
Status: install ok installed
Architecture: amd64
Version: 1.1.1n-0+deb11u5
Source: openssl (1.1.1n-0+deb11u5)
Description: toolkit

Package: libssl1.1
Status: install ok installed
Architecture: amd64
Version: 1.1.1n-0+deb11u5
Source: openssl (1.1.1n-0+deb11u5)
Description: shared libraries

Package: removed
Status: deinstall ok config-files
Architecture: all
Version: 1.0
Description: gone
"""


def write_deb(path, control):
    """Build a minimal binary package in pure Python (no dpkg needed)."""
    control_tar = io.BytesIO()
    with tarfile.open(fileobj=control_tar, mode="w:gz") as archive:
        data = control.encode("utf-8")
        info = tarfile.TarInfo("control")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    members = [("debian-binary", b"2.0\n"), ("control.tar.gz", control_tar.getvalue())]
    with open(path, "wb") as handle:
        handle.write(b"!<arch>\n")
        for name, data in members:
            header = (f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}"
                      f"{len(data):<10}`\n").encode("ascii")
            assert len(header) == 60
            handle.write(header)
            handle.write(data)
            if len(data) % 2:
                handle.write(b"\n")
    return path


# --------------------------------------------------------------------------- deb822

def test_stanzas_lowercase_and_continuations():
    parsed = stanzas(CONTROL)
    assert parsed[0]["source"] == "demo"
    assert "debhelper-compat" in parsed[0]["build-depends"]
    assert "\n" in parsed[0]["build-depends"]
    assert parsed[1]["package"] == "demo"


# --------------------------------------------------------------------------- control

def test_parse_control_build_and_runtime_dependencies():
    result = parse_control(CONTROL)
    by_name = {package.name: package for package in result.packages}

    assert by_name["debhelper-compat"].version == "13"
    assert by_name["debhelper-compat"].scope == "build"
    assert not by_name["debhelper-compat"].assumed

    assert by_name["python3"].version == "3.10"
    assert by_name["python3"].assumed

    assert by_name["libc6-dev"].version == ""
    assert by_name["libc6-dev"].scope == "build"

    assert by_name["graphviz"].version == ""
    assert by_name["graphviz"].scope == "build"

    assert by_name["libc6"].version == "2.31"
    assert by_name["libc6"].scope == "runtime"

    # "libfoo | libbar" keeps the first alternative only.
    assert "libfoo" in by_name
    assert "libbar" not in by_name
    assert by_name["extra-tool"].scope == "optional"
    assert by_name["demo-doc"].scope == "dev"
    assert all(package.ecosystem == "Debian" for package in result.packages)
    assert all(package.parser == "debian-control" for package in result.packages)


def test_parse_control_skip_policy_drops_ranges():
    result = parse_control(CONTROL, range_policy="skip")
    names = {package.name for package in result.packages}
    assert "python3" not in names
    assert "libc6" not in names
    assert "debhelper-compat" in names  # exact "=" is still resolved
    skipped = {(item.name, item.reason) for item in result.skipped}
    assert ("python3", "range") in skipped
    assert ("libc6", "range") in skipped


def test_parse_control_ignores_substitution_variables():
    result = parse_control("Source: demo\nBuild-Depends: ${misc:Depends}, libc6\n")
    assert [package.name for package in result.packages] == ["libc6"]


# --------------------------------------------------------------------------- changelog

def test_parse_changelog():
    text = ("demo (1.2.0-1) unstable; urgency=medium\n\n"
            "  * fix\n\n -- Demo <demo@example.org>  today\n")
    identity = parse_changelog(text)
    assert identity == {"source": "demo", "version": "1.2.0-1",
                        "distribution": "unstable", "urgency": "medium"}


def test_source_identity_from_tree(tmp_path):
    changelog = tmp_path / "debian" / "changelog"
    changelog.parent.mkdir()
    changelog.write_text("demo (2.0-1) bookworm; urgency=high\n")
    assert source_identity(str(tmp_path))["version"] == "2.0-1"
    assert source_identity(str(tmp_path / "missing")) == {}


# --------------------------------------------------------------------------- dpkg status

def test_parse_status_keeps_installed_and_maps_source():
    result = parse_status(STATUS, distro="bullseye")
    by_name = {package.name: package for package in result.packages}
    assert set(by_name) == {"openssl", "libssl1.1"}

    assert by_name["openssl"].source_name == ""  # source equals binary name
    assert by_name["libssl1.1"].source_name == "openssl"
    assert by_name["libssl1.1"].source_version == "1.1.1n-0+deb11u5"
    assert by_name["openssl"].arch == "amd64"
    assert by_name["openssl"].distro == "bullseye"
    assert by_name["openssl"].parser == "dpkg-status"


def test_parse_status_reports_missing_version():
    result = parse_status("Package: broken\nStatus: install ok installed\n")
    assert result.packages == []


# --------------------------------------------------------------------------- .deb

def test_parse_deb_pure_python(tmp_path, monkeypatch):
    path = write_deb(tmp_path / "demo.deb", (
        "Package: demo\nVersion: 1.2.3-1\nArchitecture: amd64\n"
        "Depends: libc6 (>= 2.31), libfoo\n"
    ))
    monkeypatch.setattr("argus.sca.debian.shutil.which", lambda name: None)
    assert "Package: demo" in _control_pure(str(path))

    result = parse_deb(str(path), distro="bookworm")
    by_name = {package.name: package for package in result.packages}
    assert by_name["demo"].version == "1.2.3-1"
    assert by_name["demo"].arch == "amd64"
    assert by_name["demo"].distro == "bookworm"
    assert by_name["libc6"].version == "2.31"
    assert by_name["libc6"].direct is False
    assert by_name["libc6"].distro == "bookworm"
    assert by_name["libfoo"].version == ""
    assert (by_name["demo"].key, by_name["libc6"].key) in result.edges


def test_parse_deb_rejects_garbage(tmp_path):
    path = tmp_path / "broken.deb"
    path.write_bytes(b"not an archive")
    result = parse_deb(str(path))
    assert result.packages == []
    assert result.issues


# --------------------------------------------------------------------------- suites

def test_normalize_suite():
    assert normalize_suite("12") == normalize_suite("bookworm")
    assert normalize_suite("12.5").major == "12"
    assert normalize_suite("Debian:11").codename == "bullseye"
    assert normalize_suite("trixie").major == "13"
    assert normalize_suite("unstable").known is False
    assert debian_ecosystem("bookworm") == "Debian:12"
    assert debian_ecosystem("") == ""


def test_normalize_future_release_keeps_major():
    suite = normalize_suite("15")
    assert suite.codename == ""
    assert suite.label == "15"
    assert suite.ecosystem == "Debian:15"


def test_detect_suite_from_debian_version(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "debian_version").write_text("11.7\n")
    suite = detect_suite(str(tmp_path))
    assert (suite.codename, suite.major) == ("bullseye", "11")


def test_detect_suite_unstable_codename(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "debian_version").write_text("trixie/sid\n")
    assert detect_suite(str(tmp_path)).major == "13"


def test_detect_suite_from_os_release(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(
        'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
    suite = detect_suite(str(tmp_path))
    assert (suite.codename, suite.major) == ("bookworm", "12")


def test_detect_suite_unknown(tmp_path):
    assert detect_suite(str(tmp_path)).known is False


# --------------------------------------------------------------------------- versions

@pytest.mark.parametrize("left,right,expected", [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1),
    ("1:1.0", "2.0", 1),
    ("1.0~rc1", "1.0", -1),
    ("1.0-1", "1.0-1+b1", -1),
    ("2.30-1", "2.9-1", 1),
    ("1.0", "1.0.0", -1),
])
def test_debian_version_compare(left, right, expected):
    assert versions.compare(left, right, "Debian") == expected


def test_debian_range_and_fixed_version():
    events = [{"introduced": "0"}, {"fixed": "1.1.1n-0+deb11u6"}]
    assert versions.range_contains("1.1.1n-0+deb11u5", events, "Debian")
    fixed = versions.fixed_version_for(
        "1.1.1n-0+deb11u5",
        {"ranges": [{"type": "ECOSYSTEM", "events": events}]},
        "Debian",
    )
    assert fixed == "1.1.1n-0+deb11u6"


# --------------------------------------------------------------------------- purl / OSV

def test_debian_purl_with_arch_and_distro():
    package = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                      manifest="status", arch="amd64", distro="bullseye")
    assert package.purl() == (
        "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u5?arch=amd64&distro=bullseye")


def test_debian_purl_unversioned():
    package = Package(name="python3", version="", ecosystem="Debian",
                      manifest="debian/control", arch="amd64")
    assert package.purl() == "pkg:deb/debian/python3?arch=amd64"


def test_osv_ecosystem_requires_suite():
    known = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                    manifest="status", distro="bullseye")
    unknown = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                      manifest="status")
    assert osv_ecosystem(known) == "Debian:11"
    assert osv_archive(known) == "Debian"
    assert osv_ecosystem(unknown) == ""
    assert OSVClient(use_cache=False).query([unknown]) == []


def test_build_matches_selects_the_debian_suite():
    package = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                      manifest="status", distro="bullseye")
    document = {
        "id": "DLA-1",
        "affected": [
            {"package": {"name": "openssl", "ecosystem": "Debian:12"},
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"}, {"fixed": "3.0.15-1"}]}]},
            {"package": {"name": "openssl", "ecosystem": "Debian:11"},
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"},
                                    {"fixed": "1.1.1n-0+deb11u6"}]}]},
        ],
    }
    key = ("Debian:11", "openssl", "1.1.1n-0+deb11u5")
    matches = build_matches({key: package}, {key: ["DLA-1"]}, {"DLA-1": document})
    assert [match.fixed_version for match in matches] == ["1.1.1n-0+deb11u6"]


def test_offline_database_filters_debian_suite(tmp_path):
    document = {
        "id": "DLA-1",
        "affected": [
            {"package": {"name": "openssl", "ecosystem": "Debian:11"},
             "versions": ["1.1.1n-0+deb11u5"],
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"},
                                    {"fixed": "1.1.1n-0+deb11u6"}]}]},
            {"package": {"name": "openssl", "ecosystem": "Debian:12"},
             "versions": ["1.1.1n-0+deb11u5"],
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"}, {"fixed": "3.0.15-1"}]}]},
        ],
    }
    archive = tmp_path / "Debian" / "all.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("DLA-1.json", json.dumps(document))

    database = LocalOSVDB(directory=str(tmp_path))
    bullseye = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                       manifest="status", distro="bullseye")
    bookworm = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                       manifest="status", distro="bookworm")
    assert [m.fixed_version for m in database.query([bullseye])] == ["1.1.1n-0+deb11u6"]
    assert [m.fixed_version for m in database.query([bookworm])] == ["3.0.15-1"]


def test_offline_database_skips_withdrawn(tmp_path):
    document = {
        "id": "CVE-2010-0928",
        "withdrawn": "2024-06-05T12:44:47Z",
        "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:11"},
                      "versions": ["1.1.1n-0+deb11u5"]}],
    }
    archive = tmp_path / "Debian" / "all.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("CVE-2010-0928.json", json.dumps(document))
    database = LocalOSVDB(directory=str(tmp_path))
    package = Package(name="openssl", version="1.1.1n-0+deb11u5", ecosystem="Debian",
                      manifest="status", distro="bullseye")
    assert database.query([package]) == []


# --------------------------------------------------------------------------- collection

def test_collect_status_file_uses_explicit_suite(tmp_path):
    path = tmp_path / "status"
    path.write_text(STATUS)
    inventory = collect(status_files=[str(path)], suite="bullseye")
    assert {package.distro for package in inventory.packages} == {"bullseye"}
    assert inventory.issues == []


def test_collect_status_file_without_suite_is_flagged(tmp_path):
    path = tmp_path / "status"
    path.write_text(STATUS)
    inventory = collect(status_files=[str(path)])
    assert {package.distro for package in inventory.packages} == {""}
    assert any("--deb-suite" in issue for issue in inventory.issues)


def test_collect_deb_root_detects_suite(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "debian_version").write_text("12.3\n")
    (root / "var" / "lib" / "dpkg").mkdir(parents=True)
    (root / "var" / "lib" / "dpkg" / "status").write_text(STATUS)
    inventory = collect(deb_roots=[str(root)])
    assert {package.distro for package in inventory.packages} == {"bookworm"}
    assert inventory.issues == []


def test_collect_deb_and_status_ignore_host_suite(tmp_path):
    path = write_deb(tmp_path / "demo.deb",
                     "Package: demo\nVersion: 1.0-1\nArchitecture: all\n")
    inventory = collect(deb_files=[str(path)])
    assert inventory.packages[0].distro == ""
    assert any("--deb-suite" in issue for issue in inventory.issues)
    resolved = collect(deb_files=[str(path)], suite="12")
    assert resolved.packages[0].distro == "bookworm"


def test_status_path_root_is_used_for_suite(tmp_path):
    chroot = tmp_path / "chroot"
    (chroot / "etc").mkdir(parents=True)
    (chroot / "etc" / "debian_version").write_text("11.7\n")
    status = chroot / "var" / "lib" / "dpkg" / "status"
    status.parent.mkdir(parents=True)
    status.write_text(STATUS)
    inventory = collect(status_files=[str(status)])
    assert {package.distro for package in inventory.packages} == {"bullseye"}


# --------------------------------------------------------------------------- SBOM

def test_sbom_uses_changelog_and_suite_properties(tmp_path):
    (tmp_path / "debian").mkdir()
    (tmp_path / "debian" / "control").write_text(
        "Source: demo\nBuild-Depends: debhelper-compat (= 13)\n")
    (tmp_path / "debian" / "changelog").write_text(
        "demo (2.0-1) bookworm; urgency=medium\n")
    inventory = collect_inventory(
        str(tmp_path), SCAOptions(deb_suite="bookworm"))
    document = cyclonedx_document(str(tmp_path), inventory, SBOMOptions())

    assert document["metadata"]["component"]["name"] == "demo"
    assert document["metadata"]["component"]["version"] == "2.0-1"
    component = next(c for c in document["components"] if c["name"] == "debhelper-compat")
    assert component["purl"] == (
        "pkg:deb/debian/debhelper-compat@13?distro=bookworm")
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties["argus:deb-distro"] == "bookworm"


def test_control_packages_inherit_changelog_distribution(tmp_path):
    (tmp_path / "debian").mkdir()
    (tmp_path / "debian" / "control").write_text(
        "Source: demo\nBuild-Depends: debhelper-compat (= 13)\n")
    (tmp_path / "debian" / "changelog").write_text(
        "demo (2.0-1) trixie; urgency=medium\n")
    inventory = collect_inventory(str(tmp_path), SCAOptions())
    package = next(iter(inventory.unique.values()))
    assert package.distro == "trixie"
    assert package.purl() == "pkg:deb/debian/debhelper-compat@13?distro=trixie"


# --------------------------------------------------------------------------- Ubuntu

UBUNTU_OS_RELEASE = """\
PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy
"""


def test_normalize_ubuntu_suite():
    jammy = normalize_suite("jammy", "ubuntu")
    assert (jammy.codename, jammy.major, jammy.vendor) == ("jammy", "22.04", "ubuntu")
    assert jammy.package_ecosystem == "Ubuntu"
    assert jammy.ecosystem == "Ubuntu:22.04:LTS"
    # A numeric release and an explicit prefix both carry the vendor.
    assert normalize_suite("22.04").ecosystem == "Ubuntu:22.04:LTS"
    assert normalize_suite("ubuntu:noble").ecosystem == "Ubuntu:24.04:LTS"
    # Interim releases are not LTS and must not grow the suffix.
    assert normalize_suite("24.10").ecosystem == "Ubuntu:24.10"
    assert debian_ecosystem("jammy", "Ubuntu") == "Ubuntu:22.04:LTS"
    # Debian codenames must not be mistaken for Ubuntu ones.
    assert normalize_suite("bookworm").ecosystem == "Debian:12"


def test_detect_ubuntu_suite_from_os_release(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text(UBUNTU_OS_RELEASE)
    # Ubuntu also ships a Debian base release; os-release must win.
    (tmp_path / "etc" / "debian_version").write_text("bookworm/sid\n")
    suite = detect_suite(str(tmp_path))
    assert (suite.codename, suite.major, suite.vendor) == ("jammy", "22.04", "ubuntu")
    assert suite.ecosystem == "Ubuntu:22.04:LTS"


def test_parse_status_and_purl_for_ubuntu():
    result = parse_status(STATUS, distro="jammy", ecosystem="Ubuntu")
    package = result.packages[0]
    assert package.ecosystem == "Ubuntu"
    assert package.purl() == (
        "pkg:deb/ubuntu/openssl@1.1.1n-0%2Bdeb11u5?arch=amd64&distro=jammy")


def test_osv_ecosystem_and_archive_for_ubuntu():
    known = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu",
                    manifest="status", distro="jammy")
    unknown = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu",
                      manifest="status")
    assert osv_ecosystem(known) == "Ubuntu:22.04:LTS"
    assert osv_archive(known) == "Ubuntu"
    assert osv_ecosystem(unknown) == ""
    assert OSVClient(use_cache=False).query([unknown]) == []


def test_ubuntu_versions_use_dpkg_ordering():
    assert versions.compare("3.0.2-0ubuntu1.16", "3.0.2-0ubuntu1.10", "Ubuntu") > 0
    events = [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.16"}]
    assert versions.range_contains("3.0.2-0ubuntu1.10", events, "Ubuntu")
    assert not versions.range_contains("3.0.2-0ubuntu1.16", events, "Ubuntu")


def test_offline_database_filters_ubuntu_release(tmp_path):
    document = {
        "id": "UBUNTU-CVE-2023-0001",
        "affected": [
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"},
             "versions": ["3.0.2-0ubuntu1.10"],
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"},
                                    {"fixed": "3.0.2-0ubuntu1.16"}]}]},
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"},
             "versions": ["3.0.2-0ubuntu1.10"],
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"},
                                    {"fixed": "3.0.4-1ubuntu1"}]}]},
        ],
    }
    archive = tmp_path / "Ubuntu" / "all.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("UBUNTU-CVE-2023-0001.json", json.dumps(document))

    database = LocalOSVDB(directory=str(tmp_path))
    jammy = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu",
                    manifest="status", distro="jammy")
    noble = Package(name="openssl", version="3.0.2-0ubuntu1.10", ecosystem="Ubuntu",
                    manifest="status", distro="noble")
    assert [m.fixed_version for m in database.query([jammy])] == ["3.0.2-0ubuntu1.16"]
    assert [m.fixed_version for m in database.query([noble])] == ["3.0.4-1ubuntu1"]


def test_collect_ubuntu_root_detects_vendor(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text(UBUNTU_OS_RELEASE)
    (root / "var" / "lib" / "dpkg").mkdir(parents=True)
    (root / "var" / "lib" / "dpkg" / "status").write_text(STATUS)
    inventory = collect(deb_roots=[str(root)])
    package = inventory.packages[0]
    assert (package.ecosystem, package.distro) == ("Ubuntu", "jammy")
    assert inventory.issues == []
    assert osv_ecosystem(package) == "Ubuntu:22.04:LTS"


def test_collect_ubuntu_deb_uses_explicit_suite(tmp_path):
    path = write_deb(tmp_path / "demo.deb",
                     "Package: demo\nVersion: 1.0-1\nArchitecture: all\n"
                     "Depends: libc6 (>= 2.35)\n")
    inventory = collect(deb_files=[str(path)], suite="jammy")
    assert {package.ecosystem for package in inventory.packages} == {"Ubuntu"}
    assert {package.distro for package in inventory.packages} == {"jammy"}
    assert inventory.packages[0].purl() == (
        "pkg:deb/ubuntu/demo@1.0-1?arch=all&distro=jammy")


def test_control_packages_inherit_ubuntu_changelog(tmp_path):
    (tmp_path / "debian").mkdir()
    (tmp_path / "debian" / "control").write_text(
        "Source: demo\nBuild-Depends: debhelper-compat (= 13)\n")
    (tmp_path / "debian" / "changelog").write_text(
        "demo (2.0-1) jammy; urgency=medium\n")
    inventory = collect_inventory(str(tmp_path), SCAOptions())
    package = next(iter(inventory.unique.values()))
    assert (package.ecosystem, package.distro) == ("Ubuntu", "jammy")
    assert package.purl() == "pkg:deb/ubuntu/debhelper-compat@13?distro=jammy"


def test_ubuntu_ecosystem_filter_keeps_packages(tmp_path):
    (tmp_path / "debian").mkdir()
    (tmp_path / "debian" / "control").write_text(
        "Source: demo\nBuild-Depends: debhelper-compat (= 13)\n")
    (tmp_path / "debian" / "changelog").write_text(
        "demo (2.0-1) jammy; urgency=medium\n")
    inventory = collect_inventory(
        str(tmp_path), SCAOptions(ecosystems=("Ubuntu",)))
    assert [package.name for package in inventory.unique.values()] == ["debhelper-compat"]
