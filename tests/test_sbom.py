"""SBOM writers: CycloneDX, SPDX and the Markdown inventory."""

from __future__ import annotations

import json

import pytest

from argus.cli import EXIT_OK, main
from argus.sbom import (
    SBOMOptions,
    build_inventory,
    cyclonedx_document,
    dumps,
    markdown_inventory,
    spdx_document,
)

GEMFILE = """\
source "https://rubygems.org"

gem "rack", "2.0.6"
gem "rake", "~> 13.0"

group :development do
  gem "rspec", "3.12.0"
end
"""


@pytest.fixture()
def ruby_project(tmp_path):
    (tmp_path / "Gemfile").write_text(GEMFILE)
    return str(tmp_path)


@pytest.fixture()
def inventory(ruby_project):
    return build_inventory(ruby_project)


@pytest.fixture()
def metadata():
    return SBOMOptions(name="demo", component_version="1.2.3")


# --------------------------------------------------------------------------- CycloneDX

def test_cyclonedx_document_shape(ruby_project, inventory, metadata):
    document = cyclonedx_document(ruby_project, inventory, metadata)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"].startswith("urn:uuid:")
    assert document["version"] == 1
    tool = document["metadata"]["tools"][0]
    assert tool["name"] == "argus"
    assert tool["version"]
    project = document["metadata"]["component"]
    assert project == {"type": "application", "name": "demo", "version": "1.2.3"}


def test_cyclonedx_components_are_sorted_with_purls(ruby_project, inventory, metadata):
    document = cyclonedx_document(ruby_project, inventory, metadata)
    components = document["components"]
    assert [item["name"] for item in components] == ["rack", "rake"]
    rack = components[0]
    assert rack["type"] == "library"
    assert rack["version"] == "2.0.6"
    assert rack["purl"] == "pkg:gem/rack@2.0.6"
    assert rack["bom-ref"] == rack["purl"]
    assert rack["scope"] == "required"
    properties = {entry["name"]: entry["value"] for entry in rack["properties"]}
    assert properties["argus:ecosystem"] == "RubyGems"
    assert properties["argus:manifest"] == "Gemfile"
    assert properties["argus:parser"] == "gemfile"
    assert properties["argus:version-assumed"] == "false"


def test_cyclonedx_range_version_is_marked_assumed(ruby_project, inventory, metadata):
    document = cyclonedx_document(ruby_project, inventory, metadata)
    rake = next(item for item in document["components"] if item["name"] == "rake")
    assert rake["version"] == "13.0"
    properties = {entry["name"]: entry["value"] for entry in rake["properties"]}
    assert properties["argus:version-assumed"] == "true"


# --------------------------------------------------------------------------- SPDX

def test_spdx_document_shape(ruby_project, inventory, metadata):
    document = spdx_document(ruby_project, inventory, metadata)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["SPDXID"] == "SPDXRef-DOCUMENT"
    assert document["name"] == "demo-sbom"
    assert document["documentNamespace"].startswith("https://argus.local/spdx/")
    assert document["creationInfo"]["creators"] == ["Tool: argus-1.4.0"]


def test_spdx_packages_use_purl_external_refs(ruby_project, inventory, metadata):
    document = spdx_document(ruby_project, inventory, metadata)
    packages = document["packages"]
    assert [item["name"] for item in packages] == ["rack", "rake"]
    rack = packages[0]
    assert rack["SPDXID"] == "SPDXRef-Package-rack"
    assert rack["versionInfo"] == "2.0.6"
    assert rack["downloadLocation"] == "NOASSERTION"
    assert rack["licenseConcluded"] == "NOASSERTION"
    assert rack["filesAnalyzed"] is False
    assert rack["externalRefs"] == [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:gem/rack@2.0.6",
        }
    ]
    assert "ecosystem=RubyGems" in rack["comment"]
    assert "version-assumed=false" in rack["comment"]


def test_spdx_relationships_describe_every_package(ruby_project, inventory, metadata):
    document = spdx_document(ruby_project, inventory, metadata)
    ids = [item["SPDXID"] for item in document["packages"]]
    assert document["documentDescribes"] == ids
    assert [(rel["spdxElementId"], rel["relationshipType"], rel["relatedSpdxElement"])
            for rel in document["relationships"]] == [
        ("SPDXRef-DOCUMENT", "DESCRIBES", identifier) for identifier in ids
    ]


def test_spdx_ids_are_unique_for_duplicate_names(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "Gemfile").write_text('gem "rack", "2.0.6"\n')
    (tmp_path / "b" / "Gemfile").write_text('gem "rack", "3.0.0"\n')
    inventory = build_inventory(str(tmp_path))
    document = spdx_document(str(tmp_path), inventory, SBOMOptions(name="dup"))
    ids = [item["SPDXID"] for item in document["packages"]]
    assert len(ids) == len(set(ids)) == 2


# --------------------------------------------------------------------------- inventory / filters

def test_dev_dependencies_are_excluded_by_default(ruby_project):
    inventory = build_inventory(ruby_project)
    assert "rspec" not in {package.name for package in inventory.unique.values()}
    assert {package.name for package in inventory.unique.values()} == {"rack", "rake"}


def test_include_dev_keeps_dev_dependencies(ruby_project):
    inventory = build_inventory(ruby_project, include_dev=True)
    assert {package.name for package in inventory.unique.values()} == {"rack", "rake", "rspec"}
    rspec = next(package for package in inventory.unique.values() if package.name == "rspec")
    assert rspec.scope == "dev"


def test_range_policy_skip_drops_unbounded_versions(ruby_project):
    inventory = build_inventory(ruby_project, range_policy="skip")
    names = {package.name for package in inventory.unique.values()}
    assert "rake" not in names
    assert any(item.name == "rake" for item in inventory.skipped)


def test_empty_project_produces_empty_documents(tmp_path):
    inventory = build_inventory(str(tmp_path))
    assert inventory.unique == {}
    cyclonedx = cyclonedx_document(str(tmp_path), inventory, SBOMOptions(name="empty"))
    spdx = spdx_document(str(tmp_path), inventory, SBOMOptions(name="empty"))
    assert cyclonedx["components"] == []
    assert spdx["packages"] == []
    assert "no supported manifests found" in markdown_inventory(
        str(tmp_path), inventory, SBOMOptions(name="empty"))


# --------------------------------------------------------------------------- Markdown

def test_markdown_inventory_lists_components(ruby_project, inventory, metadata):
    markdown = markdown_inventory(ruby_project, inventory, metadata)
    assert markdown.startswith("# SBOM — demo")
    assert "* Components: **2**" in markdown
    assert "* Ecosystems: RubyGems: 2" in markdown
    assert ("| rack | 2.0.6 | RubyGems | runtime | direct | 0 | - | - | `Gemfile` | "
            "`pkg:gem/rack@2.0.6` | pinned |") in markdown
    assert "range lower bound" in markdown
    assert "## Notes" in markdown


def test_dumps_is_valid_json(ruby_project, inventory, metadata):
    payload = json.loads(dumps(cyclonedx_document(ruby_project, inventory, metadata)))
    assert payload["bomFormat"] == "CycloneDX"


# --------------------------------------------------------------------------- CLI

def test_cli_sbom_cyclonedx_with_summary(ruby_project, tmp_path):
    output = tmp_path / "out" / "bom.json"
    summary = tmp_path / "out" / "bom.md"
    code = main(["sbom", ruby_project, "-f", "cyclonedx", "--name", "demo",
                 "-o", str(output), "--summary", str(summary), "-q"])
    assert code == EXIT_OK
    document = json.loads(output.read_text())
    assert document["bomFormat"] == "CycloneDX"
    assert [item["name"] for item in document["components"]] == ["rack", "rake"]
    assert summary.read_text().startswith("# SBOM — demo")


def test_cli_sbom_spdx_to_stdout(ruby_project, capsys):
    code = main(["sbom", ruby_project, "-f", "spdx", "--name", "demo", "-q"])
    assert code == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["documentDescribes"] == ["SPDXRef-Package-rack", "SPDXRef-Package-rake"]


def test_cli_sbom_markdown_format(ruby_project, capsys):
    code = main(["sbom", ruby_project, "-f", "md", "--name", "demo", "-q"])
    assert code == EXIT_OK
    assert capsys.readouterr().out.startswith("# SBOM — demo")


def test_cli_sbom_missing_target_is_exit_2(tmp_path, capsys):
    code = main(["sbom", str(tmp_path / "nope"), "-q"])
    assert code == 2
    assert "does not exist" in capsys.readouterr().err


# --------------------------------------------------------------------------- dependency graph

@pytest.fixture()
def npm_locked_project(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "dependencies": {"a": "^1.0.0"},
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "demo", "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
            "node_modules/b": {"version": "2.0.0", "dependencies": {"c": "^3.0.0"}},
            "node_modules/c": {"version": "3.0.0"},
        },
    }))
    return str(tmp_path)


def test_cyclonedx_exports_dependencies_and_graph_properties(npm_locked_project, metadata):
    inventory = build_inventory(npm_locked_project)
    document = cyclonedx_document(npm_locked_project, inventory, metadata)
    assert inventory.graph.resolved is True
    by_name = {item["name"]: item for item in document["components"]}
    assert by_name["c"]["properties"]
    properties = {entry["name"]: entry["value"] for entry in by_name["c"]["properties"]}
    assert properties["argus:direct"] == "false"
    assert properties["argus:depth"] == "2"
    dependencies = {item["ref"]: item["dependsOn"] for item in document["dependencies"]}
    assert dependencies["pkg:npm/a@1.0.0"] == ["pkg:npm/b@2.0.0"]
    assert dependencies["pkg:npm/b@2.0.0"] == ["pkg:npm/c@3.0.0"]
    assert dependencies["pkg:npm/c@3.0.0"] == []


def test_spdx_exports_depends_on_relationships(npm_locked_project, metadata):
    inventory = build_inventory(npm_locked_project)
    document = spdx_document(npm_locked_project, inventory, metadata)
    depends = {(rel["spdxElementId"], rel["relatedSpdxElement"])
               for rel in document["relationships"] if rel["relationshipType"] == "DEPENDS_ON"}
    assert depends == {
        ("SPDXRef-Package-a", "SPDXRef-Package-b"),
        ("SPDXRef-Package-b", "SPDXRef-Package-c"),
    }


def test_markdown_inventory_contains_tree_and_direct_columns(npm_locked_project, metadata):
    inventory = build_inventory(npm_locked_project)
    markdown = markdown_inventory(npm_locked_project, inventory, metadata)
    assert "## Dependency tree" in markdown
    assert "└─ b 2.0.0" in markdown
    assert "| a | 1.0.0 | npm | runtime | direct | 0 |" in markdown
    assert "| c | 3.0.0 | npm | runtime | transitive | 2 |" in markdown
    assert "Dependency graph resolved from lock files: **yes**" in markdown



# --------------------------------------------------------------------------- licences, hashes, signatures

import base64 as _base64

from argus.sbom import verify_document


@pytest.fixture()
def licensed_project(tmp_path):
    digest = _base64.b64encode(b"component-bytes").decode()
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "dependencies": {"a": "^1.0.0"},
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "demo", "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "license": "MIT",
                               "integrity": f"sha512-{digest}"},
        },
    }))
    return str(tmp_path)


def test_cyclonedx_emits_licences_and_hashes(licensed_project, metadata):
    inventory = build_inventory(licensed_project)
    document = cyclonedx_document(licensed_project, inventory, metadata)
    component = document["components"][0]
    assert component["licenses"] == [{"license": {"id": "MIT"}}]
    assert component["hashes"] == [{
        "alg": "SHA-512", "content": b"component-bytes".hex()}]


def test_spdx_emits_licences_and_checksums(licensed_project, metadata):
    inventory = build_inventory(licensed_project)
    document = spdx_document(licensed_project, inventory, metadata)
    package = document["packages"][0]
    assert package["licenseDeclared"] == "MIT"
    assert package["licenseConcluded"] == "MIT"
    assert package["checksums"] == [{
        "algorithm": "SHA512", "checksumValue": b"component-bytes".hex()}]


def test_unsigned_document_has_sha256_integrity(licensed_project, metadata):
    inventory = build_inventory(licensed_project)
    document = cyclonedx_document(licensed_project, inventory, metadata)
    signature = document["signature"]
    assert signature["algorithm"] == "SHA-256"
    assert len(signature["sha256"]) == 64
    assert verify_document(document) is True


def test_signed_document_roundtrip(licensed_project):
    metadata = SBOMOptions(name="demo", sign_key="hunter2", sign_key_id="ci")
    inventory = build_inventory(licensed_project)
    document = spdx_document(licensed_project, inventory, metadata)
    signature = document["signature"]
    assert signature["algorithm"] == "HS256"
    assert signature["keyId"] == "ci"
    assert verify_document(document, "hunter2") is True
    assert verify_document(document, "wrong") is False
    assert verify_document(document) is False


def test_tampered_document_fails_verification(licensed_project, metadata):
    inventory = build_inventory(licensed_project)
    document = cyclonedx_document(licensed_project, inventory, metadata)
    document["components"][0]["name"] = "evil"
    assert verify_document(document) is False


def test_cli_sbom_sign_and_verify(licensed_project, tmp_path, capsys):
    path = tmp_path / "bom.json"
    assert main(["sbom", licensed_project, "-o", str(path), "--sign-key", "k",
                 "--sign-key-id", "ci", "-q"]) == EXIT_OK
    assert main(["sbom", "--verify", str(path), "--sign-key", "k", "-q"]) == EXIT_OK
    assert main(["sbom", "--verify", str(path), "--sign-key", "bad", "-q"]) == 2
    assert main(["sbom", "--verify", str(path), "-q"]) == 2
