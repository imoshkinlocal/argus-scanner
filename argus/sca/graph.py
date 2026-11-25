"""Transitive dependency graph reconstructed from lock files.

Only lock files carry enough information to rebuild the resolved graph: they
list every installed package plus the relations between them.  Bare manifests
(``package.json``, ``Gemfile``, ``pyproject.toml``, ``pom.xml``, ...) declare
direct dependencies and constraints only, so a full resolver would need the
ecosystem registry and conflict resolution.  This module therefore stays
honest: edges come exclusively from lock files, and ``resolved`` is false when
no such data exists.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .parsers import LOCK_PARSERS, Package

Key = Tuple[str, str, str]


@dataclass
class DependencyGraph:
    """Resolved package graph with direct roots, edges and BFS depths."""

    nodes: Dict[Key, Package]
    children: Dict[Key, List[Key]]
    parents: Dict[Key, List[Key]]
    roots: List[Key] = field(default_factory=list)
    resolved: bool = False

    @property
    def edges(self) -> List[Tuple[Key, Key]]:
        return [(parent, child) for parent, items in self.children.items() for child in items]

    def count(self, direct: Optional[bool]) -> int:
        return sum(1 for package in self.nodes.values() if package.direct is direct)

    @property
    def direct_count(self) -> int:
        return self.count(True)

    @property
    def transitive_count(self) -> int:
        return self.count(False)

    @property
    def unknown_count(self) -> int:
        return self.count(None)

    def _ordered_keys(self) -> List[Key]:
        return sorted(self.nodes, key=lambda key: (
            self.nodes[key].ecosystem.lower(), self.nodes[key].name.lower(),
            self.nodes[key].version))

    def as_dict(self) -> Dict[str, object]:
        """JSON-friendly view used by reports, SBOM writers and the GUI."""
        nodes = []
        for key in self._ordered_keys():
            package = self.nodes[key]
            nodes.append({
                "ref": package.purl(),
                "name": package.name,
                "version": package.version,
                "ecosystem": package.ecosystem,
                "direct": package.direct,
                "depth": package.depth,
            })
        dependencies = []
        for key in self._ordered_keys():
            dependencies.append({
                "ref": self.nodes[key].purl(),
                "dependsOn": sorted(self.nodes[child].purl()
                                    for child in self.children.get(key, [])),
            })
        return {
            "resolved": self.resolved,
            "roots": [self.nodes[key].purl() for key in self.roots],
            "nodes": nodes,
            "dependencies": dependencies,
        }

    def render_tree(self, max_lines: int = 200,
                    severity_by_purl: Optional[Dict[str, str]] = None) -> str:
        """ASCII tree for Markdown/text reports; empty when nothing to show."""
        if not self.nodes:
            return ""
        severity_by_purl = severity_by_purl or {}
        roots = list(self.roots)
        if not roots:
            if self.resolved:
                roots = [key for key in self._ordered_keys() if not self.parents.get(key)]
            else:
                roots = self._ordered_keys()

        lines: List[str] = []
        truncated = False

        def label(key: Key) -> str:
            package = self.nodes[key]
            text = f"{package.name} {package.version}"
            marks = []
            if package.direct is True and package.depth == 0:
                marks.append("direct")
            severity = severity_by_purl.get(package.purl())
            if severity:
                marks.append(severity)
            return text + (f"  [{', '.join(marks)}]" if marks else "")

        def walk(key: Key, prefix: str, connector: str, ancestors: set) -> None:
            nonlocal truncated
            if len(lines) >= max_lines:
                truncated = True
                return
            lines.append(prefix + connector + label(key))
            if key in ancestors:
                lines.append(prefix + "    (cycle)")
                return
            children = sorted(self.children.get(key, []), key=lambda child: (
                self.nodes[child].name.lower(), self.nodes[child].version))
            for index, child in enumerate(children):
                last = index == len(children) - 1
                extension = "    " if last else "│   "
                walk(child, prefix + extension, "└─ " if last else "├─ ",
                     ancestors | {key})

        for key in roots:
            walk(key, "", "", set())

        if self.resolved:
            reachable = {key for key in self.nodes if self.nodes[key].depth is not None}
            leftovers = [key for key in self._ordered_keys() if key not in reachable]
            if leftovers and len(lines) < max_lines:
                lines.append("…")
                for key in leftovers:
                    if len(lines) >= max_lines:
                        truncated = True
                        break
                    lines.append(label(key))
        if truncated:
            lines.append("… (дерево обрезано)")
        return "\n".join(lines)


def render_tree_from_data(data: Dict[str, object], max_lines: int = 200,
                          severity_by_purl: Optional[Dict[str, str]] = None) -> str:
    """Render a tree from :meth:`DependencyGraph.as_dict` output.

    Reports receive the graph as JSON-friendly data (``stats.dependency_graph``),
    so this helper rebuilds the printable tree without recreating ``Package``
    objects.
    """
    nodes = {str(node["ref"]): node for node in data.get("nodes") or [] if "ref" in node}
    if not nodes:
        return ""
    severity_by_purl = severity_by_purl or {}

    children: Dict[str, List[str]] = {ref: [] for ref in nodes}
    parents: Dict[str, List[str]] = {ref: [] for ref in nodes}
    for dependency in data.get("dependencies") or []:
        parent = str(dependency.get("ref"))
        if parent not in nodes:
            continue
        for child in dependency.get("dependsOn") or []:
            child = str(child)
            if child not in nodes or child == parent or child in children[parent]:
                continue
            children[parent].append(child)
            parents[child].append(parent)

    resolved = bool(data.get("resolved"))
    ordered = sorted(nodes, key=lambda ref: (str(nodes[ref].get("ecosystem") or "").lower(),
                                             str(nodes[ref].get("name") or "").lower(),
                                             str(nodes[ref].get("version") or "")))
    roots = [str(ref) for ref in data.get("roots") or [] if str(ref) in nodes]
    if not roots:
        if resolved:
            roots = [ref for ref in ordered if not parents[ref]]
        else:
            roots = ordered

    def label(ref: str) -> str:
        node = nodes[ref]
        text = f"{node.get('name', '')} {node.get('version', '')}".strip()
        if node.get("direct") is True and node.get("depth") == 0:
            text += "  [direct]"
        severity = severity_by_purl.get(ref)
        if severity:
            text += f"  [{severity}]"
        return text

    lines: List[str] = []
    truncated = False

    def walk(ref: str, prefix: str, connector: str, ancestors: set) -> None:
        nonlocal truncated
        if len(lines) >= max_lines:
            truncated = True
            return
        lines.append(prefix + connector + label(ref))
        if ref in ancestors:
            lines.append(prefix + "    (cycle)")
            return
        items = sorted(children.get(ref, []), key=lambda child: (
            str(nodes[child].get("name") or "").lower(),
            str(nodes[child].get("version") or "")))
        for index, child in enumerate(items):
            last = index == len(items) - 1
            walk(child, prefix + ("    " if last else "│   "),
                 "└─ " if last else "├─ ", ancestors | {ref})

    for ref in roots:
        walk(ref, "", "", set())

    if resolved:
        reachable = {ref for ref in nodes if nodes[ref].get("depth") is not None}
        leftovers = [ref for ref in ordered if ref not in reachable]
        if leftovers and len(lines) < max_lines:
            lines.append("…")
            for ref in leftovers:
                if len(lines) >= max_lines:
                    truncated = True
                    break
                lines.append(label(ref))
    if truncated:
        lines.append("… (дерево обрезано)")
    return "\n".join(lines)


def build_graph(packages: Iterable[Package],
                edges: Iterable[Tuple[Key, Key]] = (),
                resolved: Optional[bool] = None) -> DependencyGraph:
    """Build a graph, compute roots/depths and normalise ``direct`` flags.

    Edges whose endpoints are absent (filtered dev dependency, dropped assumed
    version, package from another manifest) are ignored.
    """
    nodes: Dict[Key, Package] = {}
    for package in packages:
        nodes.setdefault(package.key, package)

    children: Dict[Key, List[Key]] = {key: [] for key in nodes}
    parents: Dict[Key, List[Key]] = {key: [] for key in nodes}
    valid_edges = 0
    for parent, child in edges:
        if parent not in nodes or child not in nodes or parent == child:
            continue
        if child in children[parent]:
            continue
        children[parent].append(child)
        parents[child].append(parent)
        valid_edges += 1

    is_resolved = bool(valid_edges) if resolved is None else bool(resolved and valid_edges)

    for package in nodes.values():
        if package.direct is None and package.parser not in LOCK_PARSERS:
            package.direct = True

    # When the lock file records relations, a package without parents is a
    # graph root.  Do this before computing roots so depths stay consistent.
    if is_resolved:
        for key, package in nodes.items():
            if package.direct is None:
                package.direct = not parents[key]

    explicit = sorted(key for key, package in nodes.items() if package.direct is True)
    if explicit:
        roots = explicit
    elif is_resolved:
        roots = sorted(key for key in nodes if not parents[key])
    else:
        roots = []

    for package in nodes.values():
        package.depth = None
    queue: deque = deque()
    for key in roots:
        nodes[key].depth = 0
        queue.append(key)
    while queue:
        key = queue.popleft()
        depth = nodes[key].depth or 0
        for child in children[key]:
            candidate = depth + 1
            if nodes[child].depth is None or candidate < nodes[child].depth:
                nodes[child].depth = candidate
                queue.append(child)

    return DependencyGraph(nodes=nodes, children=children, parents=parents,
                           roots=roots, resolved=is_resolved)
