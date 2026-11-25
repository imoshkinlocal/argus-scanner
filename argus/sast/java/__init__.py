"""Java taint analysis engine (tree-sitter)."""

from .engine import JavaEngine, analyze_file, load_properties

__all__ = ["JavaEngine", "analyze_file", "load_properties"]
