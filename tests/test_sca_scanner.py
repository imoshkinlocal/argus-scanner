"""SCA orchestration helpers (package de-duplication)."""

from __future__ import annotations

from argus.sca.parsers import Package
from argus.sca.scanner import _dedupe_packages


def package(name, version, scope="runtime", assumed=False, parser="gemfile"):
    return Package(name=name, version=version, ecosystem="RubyGems", manifest="Gemfile",
                   scope=scope, parser=parser, assumed=assumed)


def test_pinned_lock_version_wins_over_resolved_range():
    packages = [
        package("racc", "1.4", assumed=True),
        package("racc", "1.7.1", assumed=False, parser="Gemfile.lock"),
    ]
    unique = _dedupe_packages(packages)
    assert [(p.name, p.version) for p in unique.values()] == [("racc", "1.7.1")]


def test_assumed_versions_survive_without_a_lock_entry():
    unique = _dedupe_packages([package("racc", "1.4", assumed=True)])
    assert [p.version for p in unique.values()] == ["1.4"]


def test_duplicate_scope_keeps_runtime():
    packages = [package("rake", "13.0", scope="dev"), package("rake", "13.0", scope="runtime")]
    assert [p.scope for p in _dedupe_packages(packages).values()] == ["runtime"]
