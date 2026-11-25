"""Manifest parsing and package discovery."""

from __future__ import annotations

import json

import pytest

from argus.sca.parsers import Package, detect_parser, discover, parse_manifest


def write(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_detect_parser_by_basename():
    assert detect_parser("pom.xml") == "maven"
    assert detect_parser("requirements.txt") == "requirements"
    assert detect_parser("requirements-dev.txt") == "requirements"
    assert detect_parser("package-lock.json") == "npm-lock"
    assert detect_parser("Cargo.lock") == "cargo-lock"
    assert detect_parser("Gemfile") == "gemfile"
    assert detect_parser("gems.rb") == "gemfile"
    assert detect_parser("nokogiri.gemspec") == "gemspec"
    assert detect_parser("unknown.txt") is None


def test_maven_pom(tmp_path):
    write(tmp_path, "pom.xml", """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
""")
    result = parse_manifest(str(tmp_path), "pom.xml")
    names = {package.name for package in result.packages}
    assert "org.apache.logging.log4j:log4j-core" in names
    junit = next(p for p in result.packages if p.name == "junit:junit")
    assert junit.scope == "dev"
    assert junit.purl().startswith("pkg:maven/")


def test_requirements_comments_and_pins(tmp_path):
    write(tmp_path, "requirements.txt", """# comment
flask==1.0
requests>=2.0,<3.0
-e git+https://example.invalid/pkg.git#egg=thing
""")
    result = parse_manifest(str(tmp_path), "requirements.txt")
    versions = {package.name: package.version for package in result.packages}
    assert versions["flask"] == "1.0"
    assert versions["requests"] == "2.0"  # lower bound policy
    assumed = {package.name: package.assumed for package in result.packages}
    assert assumed["requests"] is True


def test_requirements_skip_policy(tmp_path):
    write(tmp_path, "requirements.txt", "requests>=2.0\nflask==1.0\n")
    result = parse_manifest(str(tmp_path), "requirements.txt", range_policy="skip")
    assert {package.name for package in result.packages} == {"flask"}
    assert any(dep.name == "requests" for dep in result.skipped)


def test_npm_lock(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"lodash": "4.17.15"}},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/fsevents": {"version": "2.3.3", "dev": True},
        },
    }))
    result = parse_manifest(str(tmp_path), "package-lock.json")
    names = {package.name: package for package in result.packages}
    assert names["lodash"].version == "4.17.15"
    assert names["fsevents"].scope == "dev"


def test_go_mod(tmp_path):
    write(tmp_path, "go.mod", """module example.com/demo

go 1.21

require (
    github.com/dgrijalva/jwt-go v3.2.0
    golang.org/x/text v0.3.0 // indirect
)
""")
    result = parse_manifest(str(tmp_path), "go.mod")
    names = {package.name for package in result.packages}
    assert "github.com/dgrijalva/jwt-go" in names


def test_gemfile_scopes_and_constraints(tmp_path):
    write(tmp_path, "Gemfile", """source "https://rubygems.org"

gem "rack", "2.0.6"
gem "nokogiri", "~> 1.13"
gem "libxml-ruby", :platform => :mri, :require => false

group :development, :test do
  gem "rake", "~> 13.0"
  platforms :mri do
    gem "rubocop", "1.30.1"   # comment after code
  end
end

group :production do
  gem "puma", ">= 5.0"
end
""")
    result = parse_manifest(str(tmp_path), "Gemfile")
    packages = {package.name: package for package in result.packages}
    assert packages["rack"].version == "2.0.6"
    assert packages["rack"].scope == "runtime"
    assert packages["rack"].assumed is False
    assert packages["nokogiri"].version == "1.13"
    assert packages["nokogiri"].assumed is True
    assert "libxml-ruby" not in packages
    assert packages["rake"].scope == "dev"
    assert packages["rubocop"].scope == "dev"
    assert packages["rubocop"].version == "1.30.1"
    assert packages["puma"].scope == "runtime"
    assert packages["puma"].version == "5.0"
    assert {dep.name for dep in result.skipped} == {"libxml-ruby"}


def test_gemspec_runtime_and_development_dependencies(tmp_path):
    write(tmp_path, "demo.gemspec", """Gem::Specification.new do |spec|
  spec.name = "demo"
  spec.add_runtime_dependency("mini_portile2", "~> 2.8.0") unless java_p
  spec.add_runtime_dependency("racc", "~> 1.4")
  spec.add_dependency("psych", ">= 4.0", "< 5.0")
  spec.add_development_dependency("rake-compiler", "= 1.1.7")
  spec.add_development_dependency("minitest", "~> 5.15") # comment
end
""")
    result = parse_manifest(str(tmp_path), "demo.gemspec")
    packages = {package.name: package for package in result.packages}
    assert packages["mini_portile2"].version == "2.8.0"
    assert packages["mini_portile2"].scope == "runtime"
    assert packages["racc"].version == "1.4"
    assert packages["psych"].version == "4.0"
    assert packages["rake-compiler"].version == "1.1.7"
    assert packages["rake-compiler"].assumed is False
    assert packages["minitest"].scope == "dev"
    assert all(package.ecosystem == "RubyGems" for package in result.packages)


def test_gemfile_skip_policy_keeps_exact_pins(tmp_path):
    write(tmp_path, "Gemfile", 'gem "rack", "2.0.6"\ngem "nokogiri", "~> 1.13"\n')
    result = parse_manifest(str(tmp_path), "Gemfile", range_policy="skip")
    assert {package.name for package in result.packages} == {"rack"}
    assert [dep.name for dep in result.skipped] == ["nokogiri"]


def test_composer_lock(tmp_path):
    write(tmp_path, "composer.lock", json.dumps({
        "packages": [{"name": "phpmailer/phpmailer", "version": "v5.2.17"}],
        "packages-dev": [],
    }))
    result = parse_manifest(str(tmp_path), "composer.lock")
    package = result.packages[0]
    assert package.name == "phpmailer/phpmailer"
    assert package.version == "5.2.17"


def test_gemfile_lock(tmp_path):
    write(tmp_path, "Gemfile.lock", """GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.6)

PLATFORMS
  ruby

DEPENDENCIES
  rack (= 2.0.6)
""")
    result = parse_manifest(str(tmp_path), "Gemfile.lock")
    assert [(p.name, p.version) for p in result.packages] == [("rack", "2.0.6")]


def test_discover_skips_excluded_directories(tmp_path):
    write(tmp_path, "requirements.txt", "flask==1.0\n")
    write(tmp_path, "node_modules/x/package.json", "{}")
    write(tmp_path, ".venv/lib/requirements.txt", "flask==1.0\n")
    found = discover(str(tmp_path))
    assert found == ["requirements.txt"]


def test_purl_for_scoped_npm():
    package = Package(name="@scope/pkg", version="1.0.0", ecosystem="npm", manifest="package.json")
    assert package.purl() == "pkg:npm/%40scope%2Fpkg@1.0.0"


# --------------------------------------------------------------------------- dependency edges

def test_gemfile_lock_records_direct_and_edges(tmp_path):
    write(tmp_path, "Gemfile.lock", """GEM
  remote: https://rubygems.org/
  specs:
    actionpack (5.2.0)
      rack (~> 2.0)
    rack (2.0.6)
    rake (13.0.1)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack
  rack (= 2.0.6)
""")
    result = parse_manifest(str(tmp_path), "Gemfile.lock")
    packages = {package.name: package for package in result.packages}
    assert packages["actionpack"].direct is True
    assert packages["rack"].direct is True
    assert packages["rake"].direct is False
    edges = {(parent[1], child[1]) for parent, child in result.edges}
    assert edges == {("actionpack", "rack")}


def test_package_lock_v3_resolves_nested_edges(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
            "node_modules/a/node_modules/b": {"version": "2.0.0"},
            "node_modules/c": {"version": "3.0.0"},
        },
    }))
    result = parse_manifest(str(tmp_path), "package-lock.json")
    packages = {package.name: package for package in result.packages}
    assert packages["a"].direct is True
    assert packages["b"].direct is not True
    assert packages["c"].direct is not True
    edges = {(parent[1], child[1]) for parent, child in result.edges}
    assert ("a", "b") in edges
    assert ("a", "c") not in edges


def test_package_lock_v1_walks_nested_tree(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "c": {"version": "3.0.0"},
        },
    }))
    result = parse_manifest(str(tmp_path), "package-lock.json")
    packages = {package.name: package for package in result.packages}
    assert packages["a"].direct is True and packages["c"].direct is True
    assert packages["b"].direct is False
    assert {(parent[1], child[1]) for parent, child in result.edges} == {("a", "b")}


def test_poetry_lock_records_edges(tmp_path):
    write(tmp_path, "poetry.lock", """\
[[package]]
name = "requests"
version = "2.31.0"
[package.dependencies]
urllib3 = ">=1.21.1"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
""")
    result = parse_manifest(str(tmp_path), "poetry.lock")
    packages = {package.name: package for package in result.packages}
    assert packages["pytest"].scope == "dev"
    assert {(parent[1], child[1]) for parent, child in result.edges} == {("requests", "urllib3")}


def test_uv_lock_records_edges(tmp_path):
    write(tmp_path, "uv.lock", """\
[[package]]
name = "demo"
version = "0.1.0"
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.0.7"
""")
    result = parse_manifest(str(tmp_path), "uv.lock")
    assert {(parent[1], child[1]) for parent, child in result.edges} == {
        ("demo", "requests"), ("requests", "urllib3")}


def test_composer_lock_records_edges(tmp_path):
    write(tmp_path, "composer.lock", json.dumps({
        "packages": [
            {"name": "monolog/monolog", "version": "2.9.1",
             "require": {"php": ">=7.2", "psr/log": "^1.0.1"}},
            {"name": "psr/log", "version": "1.1.4"},
        ],
        "packages-dev": [],
    }))
    result = parse_manifest(str(tmp_path), "composer.lock")
    assert {(parent[1], child[1]) for parent, child in result.edges} == {
        ("monolog/monolog", "psr/log")}


def test_cargo_lock_records_edges_and_workspace_roots(tmp_path):
    write(tmp_path, "Cargo.lock", """\
[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
""")
    result = parse_manifest(str(tmp_path), "Cargo.lock")
    packages = {package.name: package for package in result.packages}
    assert packages["demo"].direct is True
    assert packages["serde"].direct is None
    assert {(parent[1], child[1]) for parent, child in result.edges} == {("demo", "serde")}


def test_go_mod_marks_indirect_dependencies(tmp_path):
    write(tmp_path, "go.mod", """module example.com/demo

go 1.21

require (
    github.com/direct v1.0.0
    github.com/indirect v2.0.0 // indirect
)
""")
    result = parse_manifest(str(tmp_path), "go.mod")
    packages = {package.name: package for package in result.packages}
    assert packages["github.com/direct"].direct is True
    assert packages["github.com/indirect"].direct is False



# --------------------------------------------------------------------------- licences and digests

def test_package_lock_collects_licences_and_integrity(tmp_path):
    import base64
    digest = base64.b64encode(b"hello").decode()
    write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "license": "MIT",
                               "integrity": f"sha512-{digest}"},
        },
    }))
    result = parse_manifest(str(tmp_path), "package-lock.json")
    package = next(item for item in result.packages if item.name == "a")
    assert package.licenses == ["MIT"]
    assert package.hashes["sha512"] == b"hello".hex()


def test_composer_lock_collects_licence_and_shasum(tmp_path):
    write(tmp_path, "composer.lock", json.dumps({
        "packages": [{
            "name": "vendor/lib", "version": "1.2.3",
            "license": ["MIT", "Apache-2.0"],
            "dist": {"shasum": "a" * 40},
        }],
    }))
    result = parse_manifest(str(tmp_path), "composer.lock")
    package = result.packages[0]
    assert package.licenses == ["MIT", "Apache-2.0"]
    assert package.hashes["sha1"] == "a" * 40


def test_poetry_lock_collects_file_hashes(tmp_path):
    write(tmp_path, "poetry.lock", """\
[[package]]
name = "requests"
version = "2.31.0"
files = [
    {file = "requests-2.31.0.tar.gz", hash = "sha256:""" + "b" * 64 + """\"},
]
""")
    result = parse_manifest(str(tmp_path), "poetry.lock")
    package = result.packages[0]
    assert package.hashes["sha256"] == "b" * 64


def test_cargo_lock_collects_checksum(tmp_path):
    write(tmp_path, "Cargo.lock", """\
[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
""")
    result = parse_manifest(str(tmp_path), "Cargo.lock")
    assert result.packages[0].hashes["sha256"].startswith("cdef")
