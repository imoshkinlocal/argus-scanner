"""Dependency graph reconstruction from lock files."""

from __future__ import annotations

import json

from argus.models import Finding, ScanResult, Severity
from argus.output import markdown_report, text_report
from argus.sca.graph import build_graph, render_tree_from_data
from argus.sca.parsers import Package
from argus.sca.scanner import SCAOptions, collect_inventory


def package(name, version, parser="test", direct=None, assumed=False):
    return Package(name=name, version=version, ecosystem="npm", manifest="package-lock.json",
                   parser=parser, direct=direct, assumed=assumed)


def test_build_graph_computes_roots_edges_and_depths():
    a = package("a", "1.0.0", "package-lock", direct=True)
    b = package("b", "2.0.0", "package-lock")
    c = package("c", "3.0.0", "package-lock")
    graph = build_graph([a, b, c], [(a.key, b.key), (b.key, c.key)])
    assert graph.resolved is True
    assert graph.roots == [a.key]
    assert (a.depth, b.depth, c.depth) == (0, 1, 2)
    assert a.direct is True and b.direct is False and c.direct is False
    assert graph.direct_count == 1
    assert graph.transitive_count == 2


def test_build_graph_ignores_edges_with_missing_endpoints():
    a = package("a", "1.0.0", "package-lock", direct=True)
    missing = package("gone", "9.9.9", "package-lock")
    graph = build_graph([a], [(a.key, missing.key)])
    assert graph.resolved is False
    assert graph.edges == []
    assert a.depth == 0


def test_build_graph_without_edges_marks_manifest_packages_direct():
    a = package("a", "1.0.0", "gemfile")
    b = package("b", "2.0.0", "yarn.lock")
    graph = build_graph([a, b])
    assert graph.resolved is False
    assert a.direct is True and b.direct is None
    assert a.depth == 0 and b.depth is None
    assert graph.roots == [a.key]


def test_render_tree_from_data_marks_direct_and_severity():
    a = package("a", "1.0.0", "package-lock", direct=True)
    b = package("b", "2.0.0", "package-lock")
    graph = build_graph([a, b], [(a.key, b.key)])
    data = graph.as_dict()
    text = render_tree_from_data(data, severity_by_purl={b.purl(): "high"})
    assert "a 1.0.0  [direct]" in text
    assert "b 2.0.0  [high]" in text


def test_collect_inventory_uses_sibling_manifest_for_direct_status(tmp_path):
    (tmp_path / "pyproject.toml").write_text("""\
[project]
name = "demo"
dependencies = ["requests==2.31.0"]
""")
    (tmp_path / "poetry.lock").write_text("""\
[[package]]
name = "requests"
version = "2.31.0"
[package.dependencies]
urllib3 = ">=1.21.1"

[[package]]
name = "urllib3"
version = "2.0.7"
""")
    inventory = collect_inventory(str(tmp_path), SCAOptions())
    packages = {package.name: package for package in inventory.unique.values()}
    assert packages["requests"].direct is True
    assert packages["urllib3"].direct is False
    assert packages["requests"].depth == 0
    assert packages["urllib3"].depth == 1
    assert inventory.graph.resolved is True


def test_collect_inventory_filters_edges_to_filtered_dev_packages(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"dev-only": "^1.0.0"}},
            "node_modules/dev-only": {"version": "1.0.0", "dev": True},
        },
    }))
    inventory = collect_inventory(str(tmp_path), SCAOptions(include_dev=False))
    assert "dev-only" not in {package.name for package in inventory.unique.values()}
    assert inventory.graph.edges == []
    assert inventory.graph.resolved is False


def test_markdown_and_text_reports_include_dependency_tree():
    a = package("a", "1.0.0", "package-lock", direct=True)
    b = package("b", "2.0.0", "package-lock")
    graph = build_graph([a, b], [(a.key, b.key)])
    finding = Finding(
        rule_id="CVE-2024-0001", title="bad b", severity=Severity.HIGH, kind="sca",
        engine="osv", package="b", version="2.0.0", purl=b.purl(),
        metadata={"direct": b.direct, "depth": b.depth},
    )
    result = ScanResult(
        target="/tmp/demo", findings=[finding],
        stats={
            "manifests_scanned": 1, "packages_total": 2, "packages_unique": 2,
            "packages_direct": graph.direct_count,
            "packages_transitive": graph.transitive_count,
            "packages_unknown": graph.unknown_count,
            "dependency_graph": graph.as_dict(),
        },
    )
    markdown = markdown_report(result)
    assert "## Dependency tree" in markdown
    assert "a 1.0.0  [direct]" in markdown
    assert "b 2.0.0  [high]" in markdown
    assert "Direct / transitive / unknown | 1 / 1 / 0" in markdown
    text = text_report(result)
    assert "Dependency tree:" in text
    assert "└─ b 2.0.0  [high]" in text
    payload = finding.to_dict()
    assert payload["package"]["direct"] is False
    assert payload["package"]["depth"] == 1
