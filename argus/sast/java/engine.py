"""Java taint analysis engine built on tree-sitter.

The engine is intentionally self contained (no build system, no classpath) and
performs a per-file, flow-insensitive-but-branch-aware taint propagation:

* sources are servlet request accessors (plus a few framework equivalents);
* taint flows through assignments, string concatenation, collections, arrays,
  fields, ternary expressions and calls to methods declared in the same file;
* constant conditions are folded, so dead branches do not produce findings;
* sanitizers (ESAPI encoders, numeric parsers, ...) kill the taint;
* sinks are catalogued per CWE with the argument index that must be tainted.
"""

from __future__ import annotations

import os
import re
import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from tree_sitter import Language, Node, Parser

try:
    import tree_sitter_java
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ImportError(
        "the Java engine requires the 'tree-sitter' and 'tree-sitter-java' packages"
    ) from exc

from ...models import Finding, Severity
from . import catalog

_MAX_DEPTH = 8
_UNSET = object()

_LANGUAGE: Optional[Language] = None


def _language() -> Language:
    global _LANGUAGE
    if _LANGUAGE is None:
        _LANGUAGE = Language(tree_sitter_java.language())
    return _LANGUAGE


def parse_java(source: bytes) -> Node:
    parser = Parser(_language())
    return parser.parse(source).root_node


def text(node: Optional[Node]) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8", "replace")


def field(node: Optional[Node], name: str) -> Optional[Node]:
    if node is None:
        return None
    return node.child_by_field_name(name)


def named(node: Optional[Node]) -> List[Node]:
    if node is None:
        return []
    return [child for child in node.children if child.is_named]


def simple_type(type_text: str) -> str:
    """``java.util.Map<String, Foo>`` -> ``Map``."""
    value = type_text.strip()
    value = value.split("<", 1)[0]
    value = value.replace("[]", "").strip()
    if "." in value:
        value = value.rsplit(".", 1)[-1]
    return value.strip()


_JAVA_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
    '"': '"', "'": "'", "\\": "\\", "0": "\0",
}


def decode_java_string(literal: str) -> str:
    value = literal.strip()
    if value.startswith('"""'):
        body = value[3:-3]
        body = body.replace("\r\n", "\n")
        lines = body.split("\n")
        if lines:
            lines[0] = lines[0].strip()
        return "\n".join(lines).strip("\n")
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        value = value[1:-1]
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            escape = value[index + 1]
            if escape == "u" and index + 5 < len(value):
                try:
                    result.append(chr(int(value[index + 2:index + 6], 16)))
                    index += 6
                    continue
                except ValueError:
                    pass
            result.append(_JAVA_ESCAPES.get(escape, escape))
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


@dataclass
class Value:
    """Abstract value: taint state, source tags, constants and containers."""

    tainted: bool = False
    tags: Tuple[str, ...] = ()
    const: object = _UNSET
    const_type: Optional[str] = None  # "str" | "int" | "float" | "bool"
    origin: str = ""  # provenance marker, e.g. "local_cookie"
    #: CWEs the value has been neutralised for (per-context sanitisation).
    clean: frozenset = frozenset()
    #: Modelled list contents (immutable tuple of Values).
    elements: Optional[Tuple["Value", ...]] = None
    #: Modelled map contents (immutable tuple of (key, Value) pairs).
    entries: Optional[Tuple[Tuple[str, "Value"], ...]] = None

    @property
    def is_const(self) -> bool:
        return self.const is not _UNSET

    @property
    def bool_value(self) -> Optional[bool]:
        return self.const if isinstance(self.const, bool) else None

    def is_hot(self, cwe: str) -> bool:
        """True when the value carries taint that is not sanitised for ``cwe``."""
        return self.tainted and cwe not in self.clean


def value_of_const(const: object) -> Value:
    if isinstance(const, bool):
        return Value(const=const, const_type="bool")
    if isinstance(const, int):
        return Value(const=const, const_type="int")
    if isinstance(const, float):
        return Value(const=const, const_type="float")
    if isinstance(const, str):
        return Value(const=const, const_type="str")
    return Value(const=const, const_type=None)


def _is_neutral(value: "Value") -> bool:
    """True for a value that carries no information (used when merging branches)."""
    return (not value.tainted and not value.tags and not value.is_const
            and value.elements is None and value.entries is None)


def merge(*values: Value) -> Value:
    if not values:
        return Value()
    tainted_values = [value for value in values if value.tainted]
    tainted_any = bool(tainted_values)
    tags: List[str] = []
    for value in tainted_values:
        for tag in value.tags:
            if tag not in tags:
                tags.append(tag)
    const: object = _UNSET
    const_type = None
    if all(value.is_const for value in values):
        first = values[0]
        if all(_equal_const(first, other) for other in values[1:]):
            const = first.const
            const_type = first.const_type
    clean = frozenset(catalog.ALL_CWES)
    for value in tainted_values:
        clean = clean & value.clean
    origin = values[0].origin if all(value.origin == values[0].origin for value in values) else ""
    elements: Optional[Tuple[Value, ...]] = None
    shaped = [value for value in values if value.elements is not None]
    if shaped and all(value.elements is not None or _is_neutral(value) for value in values):
        lengths = {len(value.elements) for value in shaped}
        if len(lengths) == 1:
            elements = tuple(merge(*items) for items in zip(*(value.elements for value in shaped)))
    entries: Optional[Tuple[Tuple[str, Value], ...]] = None
    shaped_entries = [value for value in values if value.entries is not None]
    if shaped_entries and all(value.entries is not None or _is_neutral(value) for value in values):
        keys = [[key for key, _ in value.entries] for value in shaped_entries]
        if all(key_list == keys[0] for key_list in keys):
            entries = tuple(
                (key, merge(*(dict(value.entries)[key] for value in shaped_entries)))
                for key in keys[0]
            )
    return Value(tainted=tainted_any, tags=tuple(tags), const=const, const_type=const_type,
                 origin=origin, clean=clean, elements=elements, entries=entries)


def _equal_const(left: Value, right: Value) -> bool:
    if left.const_type != right.const_type:
        # int/float comparison is still useful for folded conditions
        if {left.const_type, right.const_type} <= {"int", "float"}:
            return float(left.const) == float(right.const)
        return False
    try:
        return bool(left.const == right.const)
    except Exception:  # noqa: BLE001
        return False


def tainted(tag: str) -> Value:
    return Value(tainted=True, tags=(tag,))


def derive(value: Value, **overrides: Any) -> Value:
    """Copy taint bookkeeping (tags, per-CWE cleanliness, origin) from ``value``."""
    params: Dict[str, Any] = {
        "tainted": value.tainted,
        "tags": value.tags,
        "clean": value.clean,
        "origin": value.origin,
    }
    params.update(overrides)
    return Value(**params)


def expand(value: Value) -> List[Value]:
    """Flatten containers so that element taint is visible to sink checks."""
    members: List[Value] = [value]
    if value.elements is not None:
        members.extend(value.elements)
    if value.entries is not None:
        members.extend(entry for _, entry in value.entries)
    return members


@dataclass
class Env:
    vars: Dict[str, Value] = dataclasses.field(default_factory=dict)
    types: Dict[str, str] = dataclasses.field(default_factory=dict)
    returns: List[Value] = dataclasses.field(default_factory=list)
    broken: bool = False

    def get(self, name: str) -> Value:
        return self.vars.get(name, Value())

    def set(self, name: str, value: Value) -> None:
        self.vars[name] = value

    def copy(self) -> "Env":
        return Env(vars=dict(self.vars), types=dict(self.types))

    def absorb(self, other: "Env") -> None:
        for name, value in other.vars.items():
            self.vars[name] = merge(self.vars.get(name, Value()), value)
        for name, type_name in other.types.items():
            self.types.setdefault(name, type_name)
        self.returns.extend(other.returns)


@dataclass
class MethodInfo:
    name: str
    owner: str
    params: List[Tuple[str, str]]  # (type, name)
    body: Optional[Node]
    node: Node
    is_constructor: bool = False


@dataclass
class ClassInfo:
    name: str
    methods: Dict[str, List[MethodInfo]] = dataclasses.field(default_factory=dict)
    fields: Dict[str, str] = dataclasses.field(default_factory=dict)

    def add_method(self, method: MethodInfo) -> None:
        self.methods.setdefault(method.name, []).append(method)


StatementHandler = Iterator[None]


class JavaEngine:
    """Analyse a single Java compilation unit."""

    def __init__(self, path: str, source: bytes, properties: Optional[Dict[str, str]] = None,
                 max_depth: int = _MAX_DEPTH) -> None:
        self.path = path
        self.source = source
        self.properties = properties or {}
        self.max_depth = max_depth
        self.classes: Dict[str, ClassInfo] = {}
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, int]] = set()
        self._active: Set[Tuple[str, str, Tuple[str, ...]]] = set()
        self._field_values: Dict[Tuple[str, str], Value] = {}
        self.root = parse_java(source)
        self._index_types(self.root)

    # ------------------------------------------------------------------ indexing

    def _index_types(self, node: Node) -> None:
        for child in node.children:
            if child.type in ("class_declaration", "interface_declaration",
                              "enum_declaration", "record_declaration"):
                self._index_class(child)
            elif child.type in ("program", "block"):
                self._index_types(child)

    def _index_class(self, node: Node) -> None:
        name_node = field(node, "name")
        if name_node is None:
            return
        class_name = text(name_node)
        info = self.classes.setdefault(class_name, ClassInfo(name=class_name))
        body = field(node, "body")
        if body is None:
            return
        for member in body.children:
            if member.type in ("method_declaration", "constructor_declaration"):
                method = self._method_info(member, class_name)
                if method:
                    info.add_method(method)
            elif member.type == "field_declaration":
                type_text = text(field(member, "type"))
                for declarator in member.children_by_field_name("declarator"):
                    declarator_name = field(declarator, "name")
                    if declarator_name is not None:
                        info.fields[text(declarator_name)] = type_text
            elif member.type in ("class_declaration", "interface_declaration",
                                 "enum_declaration", "record_declaration"):
                self._index_class(member)

    def _method_info(self, node: Node, owner: str) -> Optional[MethodInfo]:
        name_node = field(node, "name")
        if name_node is None:
            return None
        params: List[Tuple[str, str]] = []
        params_node = field(node, "parameters")
        for child in named(params_node):
            if child.type in ("formal_parameter", "spread_parameter", "receiver_parameter"):
                param_name = field(child, "name")
                param_type = field(child, "type")
                if param_name is not None:
                    params.append((text(param_type), text(param_name)))
        return MethodInfo(
            name=text(name_node),
            owner=owner,
            params=params,
            body=field(node, "body"),
            node=node,
            is_constructor=node.type == "constructor_declaration",
        )

    # ------------------------------------------------------------------ entrypoint

    def _spring_sources(self, method_node: Node) -> Dict[str, str]:
        """Map controller parameters annotated with ``@RequestParam`` and friends."""
        found: Dict[str, str] = {}
        params_node = field(method_node, "parameters")
        for param in named(params_node):
            if param.type != "formal_parameter":
                continue
            name_node = field(param, "name")
            type_node = field(param, "type")
            if name_node is None:
                continue
            type_text = simple_type(text(type_node))
            if type_text.lower() in catalog.SPRING_SAFE_PARAM_TYPES:
                continue
            modifiers = field(param, "modifiers")
            if modifiers is None:
                modifiers = next((child for child in param.children
                                  if child.type == "modifiers"), None)
            if name_node is None or modifiers is None:
                continue
            for annotation in modifiers.children:
                if annotation.type not in ("annotation", "marker_annotation"):
                    continue
                annotation_name = field(annotation, "name")
                if annotation_name is None:
                    continue
                label = catalog.SPRING_PARAM_ANNOTATIONS.get(text(annotation_name).lower())
                if label:
                    found[text(name_node)] = label
                    break
        return found

    def run(self) -> List[Finding]:
        for class_info in list(self.classes.values()):
            for method in [m for methods in class_info.methods.values() for m in methods]:
                if method.body is None:
                    continue
                self._field_values = {}
                env = Env()
                for param_type, param_name in method.params:
                    env.types[param_name] = param_type
                for param_name, label in self._spring_sources(method.node).items():
                    env.set(param_name, tainted(label))
                self._active = set()
                self.exec_block(method.body, class_info, env)
        return self._dedupe()

    def _dedupe(self) -> List[Finding]:
        ordered = sorted(self.findings, key=lambda f: (f.start_line, f.rule_id))
        result: List[Finding] = []
        seen = set()
        for finding in ordered:
            key = (finding.rule_id, finding.start_line, finding.message)
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
        return result

    # ------------------------------------------------------------------ reporting

    def _report(self, rule_id: str, cwe: str, severity: Severity, title: str,
                node: Node, detail: str, tags: Sequence[str] = (), confidence: str = "medium",
                extra: Optional[Dict[str, object]] = None) -> None:
        line = node.start_point[0] + 1
        if (rule_id, line) in self._seen:
            return
        self._seen.add((rule_id, line))
        sources = sorted({tag for tag in tags if tag})
        message = detail
        if sources:
            message = f"{detail} Data originates from {', '.join(sources)}."
        metadata: Dict[str, object] = {"engine": "argus-java", "line_text": text(node)[:300]}
        if sources:
            metadata["sources"] = sources
        if extra:
            metadata.update(extra)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                kind="sast",
                engine="argus-java",
                file=self.path,
                start_line=line,
                start_col=node.start_point[1] + 1,
                end_line=node.end_point[0] + 1,
                end_col=node.end_point[1] + 1,
                message=message.strip(),
                description=title,
                cwe=cwe,
                confidence=confidence,
                metadata=metadata,
            )
        )

    # ------------------------------------------------------------------ statements

    def exec_block(self, node: Optional[Node], cls: ClassInfo, env: Env) -> None:
        if node is None:
            return
        for child in node.children:
            if env.broken:
                break
            self.exec_stmt(child, cls, env)

    def exec_stmt(self, node: Node, cls: ClassInfo, env: Env) -> None:
        kind = node.type
        if kind in ("block", "constructor_body", "program"):
            self.exec_block(node, cls, env)
        elif kind == "local_variable_declaration":
            self._exec_declaration(node, cls, env)
        elif kind == "expression_statement":
            for child in named(node):
                self.eval(child, cls, env)
        elif kind == "if_statement":
            self._exec_if(node, cls, env)
        elif kind == "for_statement":
            self._exec_for(node, cls, env)
        elif kind == "enhanced_for_statement":
            self._exec_enhanced_for(node, cls, env)
        elif kind in ("while_statement", "do_statement"):
            self._exec_loop(node, cls, env)
        elif kind in ("try_statement", "try_with_resources_statement"):
            self._exec_try(node, cls, env)
        elif kind in ("switch_expression", "switch_statement"):
            self._exec_switch(node, cls, env)
        elif kind == "return_statement":
            values = [self.eval(child, cls, env) for child in named(node)]
            env.returns.append(merge(*values) if values else Value())
        elif kind == "throw_statement":
            for child in named(node):
                self.eval(child, cls, env)
        elif kind == "synchronized_statement":
            for child in named(node):
                self.exec_stmt(child, cls, env)
        elif kind in ("switch_block_statement_group", "switch_group", "switch_rule"):
            for child in named(node):
                if env.broken:
                    break
                if child.type == "switch_label":
                    continue
                self.exec_stmt(child, cls, env)
        elif kind == "labeled_statement":
            for child in named(node):
                self.exec_stmt(child, cls, env)
        elif kind in ("break_statement", "continue_statement", "yield_statement"):
            if kind == "yield_statement":
                for child in named(node):
                    self.eval(child, cls, env)
            env.broken = True
        elif kind in ("class_declaration", "local_class_declaration", "method_declaration",
                      "constructor_declaration", "field_declaration", "import_declaration",
                      "package_declaration", "annotation_type_declaration"):
            return
        else:
            for child in named(node):
                self.eval(child, cls, env)

    def _exec_declaration(self, node: Node, cls: ClassInfo, env: Env) -> None:
        type_text = text(field(node, "type"))
        for declarator in node.children_by_field_name("declarator"):
            name_node = field(declarator, "name")
            if name_node is None:
                continue
            name = text(name_node)
            value_node = field(declarator, "value")
            value = self.eval(value_node, cls, env) if value_node is not None else Value()
            env.set(name, value)
            env.types[name] = type_text
            self._check_secret(name, value, declarator)

    def _exec_if(self, node: Node, cls: ClassInfo, env: Env) -> None:
        condition = self.eval(field(node, "condition"), cls, env)
        consequence = field(node, "consequence")
        alternative = field(node, "alternative")
        decision = condition.bool_value
        if decision is True:
            self.exec_stmt(consequence, cls, env) if consequence is not None else None
            return
        if decision is False:
            if alternative is not None:
                self.exec_stmt(alternative, cls, env)
            return
        then_env = env.copy()
        if consequence is not None:
            self.exec_stmt(consequence, cls, then_env)
        else_env = env.copy()
        if alternative is not None:
            self.exec_stmt(alternative, cls, else_env)
        env.absorb(then_env)
        env.absorb(else_env)

    def _exec_for(self, node: Node, cls: ClassInfo, env: Env) -> None:
        init = field(node, "init")
        if init is not None:
            self.exec_stmt(init, cls, env) if init.type != "expression_statement" else self.exec_stmt(init, cls, env)
        condition = field(node, "condition")
        decision = self.eval(condition, cls, env).bool_value if condition is not None else None
        if decision is False:
            return
        body_env = env.copy()
        body_env.broken = False
        self.exec_stmt(field(node, "body"), cls, body_env) if field(node, "body") is not None else None
        body_env.broken = False
        update = field(node, "update")
        if update is not None:
            self.eval(update, cls, body_env)
        env.absorb(body_env)

    def _exec_enhanced_for(self, node: Node, cls: ClassInfo, env: Env) -> None:
        iterable = self.eval(field(node, "value"), cls, env)
        name_node = field(node, "name")
        body_env = env.copy()
        if name_node is not None:
            if iterable.elements is not None:
                element = merge(*iterable.elements) if iterable.elements else Value()
            else:
                element = derive(iterable)
            body_env.set(text(name_node), element)
            body_env.types[text(name_node)] = text(field(node, "type"))
        body_env.broken = False
        self.exec_stmt(field(node, "body"), cls, body_env)
        body_env.broken = False
        env.absorb(body_env)

    def _exec_loop(self, node: Node, cls: ClassInfo, env: Env) -> None:
        condition = field(node, "condition")
        decision = self.eval(condition, cls, env).bool_value if condition is not None else None
        if decision is False:
            return
        body_env = env.copy()
        body_env.broken = False
        self.exec_stmt(field(node, "body"), cls, body_env)
        body_env.broken = False
        env.absorb(body_env)

    def _exec_try(self, node: Node, cls: ClassInfo, env: Env) -> None:
        for child in node.children:
            if child.type in ("block", "resource_specification"):
                self.exec_stmt(child, cls, env)
            elif child.type == "catch_clause":
                catch_env = env.copy()
                for param in named(child):
                    if param.type == "catch_formal_parameter":
                        for sub in named(param):
                            if sub.type == "identifier":
                                catch_env.set(text(sub), Value())
                            elif sub.type == "catch_type":
                                pass
                body = field(child, "body")
                if body is not None:
                    self.exec_stmt(body, cls, catch_env)
                env.absorb(catch_env)
            elif child.type == "finally_clause":
                self.exec_stmt(child, cls, env)

    def _exec_switch(self, node: Node, cls: ClassInfo, env: Env) -> None:
        condition = self.eval(field(node, "condition"), cls, env)
        body = field(node, "body")
        if body is None:
            return
        groups = [child for child in body.children if child.is_named]
        selected: Optional[int] = None
        if condition.is_const:
            for index, group in enumerate(groups):
                labels = [child for child in group.children if child.type in ("switch_label", "switch_rule")]
                for label in labels:
                    label_text = text(label).strip()
                    if label_text.startswith("default"):
                        if selected is None:
                            selected = index
                        continue
                    if label_text.startswith("case") and self._case_matches(label_text, condition):
                        selected = index
                        break
                if selected is not None:
                    break
        branch_env = env.copy()
        branch_env.broken = False
        if selected is None:
            # Unknown selector: every group may run, so merge all of them.
            for group in groups:
                group_env = env.copy()
                group_env.broken = False
                self.exec_stmt(group, cls, group_env)
                group_env.broken = False
                env.absorb(group_env)
            return
        for group in groups[selected:]:
            self.exec_stmt(group, cls, branch_env)
            if branch_env.broken:
                branch_env.broken = False
                break
        branch_env.broken = False
        env.absorb(branch_env)

    @staticmethod
    def _case_matches(label_text: str, condition: Value) -> bool:
        expr = label_text[len("case"):].strip().rstrip(":").strip()
        if expr.startswith('"') and expr.endswith('"'):
            return condition.const_type == "str" and condition.const == decode_java_string(expr)
        if expr.startswith("'") and expr.endswith("'"):
            return condition.const_type == "str" and condition.const == decode_java_string(expr)
        if re.fullmatch(r"-?\d+[lL]?", expr):
            number = int(expr.rstrip("lL"))
            return condition.const_type == "int" and int(condition.const) == number
        return False

    # ------------------------------------------------------------------ expressions

    def eval(self, node: Optional[Node], cls: ClassInfo, env: Env) -> Value:  # noqa: C901
        if node is None:
            return Value()
        kind = node.type
        if kind == "identifier":
            return self._eval_identifier(node, cls, env)
        if kind in ("this", "super"):
            return Value()
        if kind in ("string_literal", "text_block"):
            return value_of_const(decode_java_string(text(node)))
        if kind == "character_literal":
            return value_of_const(decode_java_string(text(node)))
        if kind.endswith("_integer_literal"):
            raw = text(node).replace("_", "").rstrip("lL")
            try:
                return value_of_const(int(raw, 0) if not re.fullmatch(r"0[0-7]+", raw) else int(raw, 8))
            except ValueError:
                return Value()
        if kind == "decimal_floating_point_literal":
            raw = text(node).replace("_", "").rstrip("fFdD")
            try:
                return value_of_const(float(raw))
            except ValueError:
                return Value()
        if kind in ("true", "false"):
            return value_of_const(kind == "true")
        if kind == "null_literal":
            return value_of_const(None)
        if kind == "parenthesized_expression":
            children = named(node)
            return self.eval(children[0], cls, env) if children else Value()
        if kind == "binary_expression":
            return self._eval_binary(node, cls, env)
        if kind == "unary_expression":
            operator = text(field(node, "operator"))
            operand = self.eval(field(node, "operand"), cls, env)
            if operator == "!":
                decision = operand.bool_value
                return value_of_const(not decision) if decision is not None else Value()
            if operator in ("-", "+") and operand.is_const and operand.const_type in ("int", "float"):
                return value_of_const(-operand.const if operator == "-" else operand.const)
            return derive(operand)
        if kind == "assignment_expression":
            return self._eval_assignment(node, cls, env)
        if kind == "update_expression":
            inner = named(node)
            if inner:
                target = inner[0]
                current = self.eval(target, cls, env)
                if isinstance(current.const, int):
                    updated = current.const + 1
                    value = value_of_const(updated)
                    if target.type == "identifier":
                        env.set(text(target), value)
                    return value
            return Value()
        if kind == "ternary_expression":
            return self._eval_ternary(node, cls, env)
        if kind == "cast_expression":
            value = self.eval(field(node, "value"), cls, env)
            target_type = simple_type(text(field(node, "type")))
            const = value.const
            if value.is_const:
                if target_type in ("int", "long", "short", "byte") and isinstance(const, (int, float)):
                    return derive(value, const=int(const), const_type="int")
                if target_type in ("float", "double") and isinstance(const, (int, float)):
                    return derive(value, const=float(const), const_type="float")
                if target_type in ("String", "CharSequence") and not isinstance(const, str):
                    return derive(value, const=str(const), const_type="str")
            return derive(value)
        if kind == "method_invocation":
            return self._eval_call(node, cls, env)
        if kind == "object_creation_expression":
            return self._eval_new(node, cls, env)
        if kind == "array_creation_expression":
            return self._eval_array_new(node, cls, env)
        if kind == "array_initializer":
            values = [self.eval(child, cls, env) for child in named(node)]
            merged = merge(*values) if values else Value()
            return derive(merged, elements=tuple(values) if values else None)
        if kind == "array_access":
            base = self.eval(field(node, "array"), cls, env)
            index = self.eval(field(node, "index"), cls, env)
            if base.elements is not None:
                if index.is_const and isinstance(index.const, int) and 0 <= index.const < len(base.elements):
                    return base.elements[index.const]
                return merge(*base.elements) if base.elements else Value()
            return derive(base)
        if kind == "field_access":
            return self._eval_field_access(node, cls, env)
        if kind == "instanceof_expression":
            return Value()
        if kind in ("method_reference", "lambda_expression", "class_literal"):
            return Value()
        if kind in ("switch_expression", "switch_statement"):
            self._exec_switch(node, cls, env)
            return Value()
        # Unknown construct: propagate taint conservatively from the children.
        values = [self.eval(child, cls, env) for child in named(node)
                  if child.type not in ("block", "class_body")]
        return merge(*values) if values else Value()

    def _eval_identifier(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        name = text(node)
        if name in env.vars:
            return env.get(name)
        field_value = self._field_values.get((cls.name, name))
        if field_value is not None:
            return field_value
        if name in cls.fields:
            return Value()
        if name == "this":
            return Value()
        return Value()

    def _eval_binary(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        operator = text(field(node, "operator"))
        left = self.eval(field(node, "left"), cls, env)
        right = self.eval(field(node, "right"), cls, env)
        if operator == "+":
            if left.is_const and right.is_const:
                if left.const_type == "str" or right.const_type == "str":
                    return value_of_const(str(left.const) + str(right.const))
                if left.const_type in ("int", "float") and right.const_type in ("int", "float"):
                    return value_of_const(left.const + right.const)
            return merge(left, right)
        if operator in ("-", "*", "/", "%", "<<", ">>", ">>>", "&", "|", "^"):
            if left.is_const and right.is_const and isinstance(left.const, (int, float)) \
                    and isinstance(right.const, (int, float)):
                try:
                    if operator == "-":
                        return value_of_const(left.const - right.const)
                    if operator == "*":
                        return value_of_const(left.const * right.const)
                    if operator == "/":
                        return value_of_const(left.const // right.const if isinstance(left.const, int) else left.const / right.const)
                    if operator == "%":
                        return value_of_const(left.const % right.const)
                    if operator == "<<":
                        return value_of_const(int(left.const) << int(right.const))
                    if operator == ">>":
                        return value_of_const(int(left.const) >> int(right.const))
                    if operator == ">>>":
                        return value_of_const((int(left.const) & 0xFFFFFFFF) >> int(right.const))
                    if operator == "&":
                        return value_of_const(int(left.const) & int(right.const))
                    if operator == "|":
                        return value_of_const(int(left.const) | int(right.const))
                    if operator == "^":
                        return value_of_const(int(left.const) ^ int(right.const))
                except (ZeroDivisionError, ValueError):
                    return Value()
            return Value()
        if operator in ("==", "!="):
            if left.is_const and right.is_const:
                equal = _equal_const(left, right) or (left.const is None and right.const is None)
                return value_of_const(equal if operator == "==" else not equal)
            return Value()
        if operator in ("<", ">", "<=", ">="):
            if left.is_const and right.is_const and left.const_type in ("int", "float") \
                    and right.const_type in ("int", "float"):
                if operator == "<":
                    return value_of_const(left.const < right.const)
                if operator == ">":
                    return value_of_const(left.const > right.const)
                if operator == "<=":
                    return value_of_const(left.const <= right.const)
                return value_of_const(left.const >= right.const)
            return Value()
        if operator in ("&&", "||"):
            if left.is_const and right.is_const:
                left_bool, right_bool = bool(left.const), bool(right.const)
                return value_of_const(left_bool and right_bool if operator == "&&" else left_bool or right_bool)
            return Value()
        return merge(left, right)

    def _eval_assignment(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        operator = text(field(node, "operator"))
        target = field(node, "left")
        right = self.eval(field(node, "right"), cls, env)
        if operator == "=":
            value = right
        elif operator == "+=":
            current = self.eval(target, cls, env)
            if current.is_const and right.is_const and (current.const_type == "str" or right.const_type == "str"):
                value = value_of_const(str(current.const) + str(right.const))
            elif current.is_const and right.is_const and current.const_type in ("int", "float") \
                    and right.const_type in ("int", "float"):
                value = value_of_const(current.const + right.const)
            else:
                value = merge(current, right)
        else:
            current = self.eval(target, cls, env)
            if current.is_const and right.is_const and isinstance(current.const, (int, float)) \
                    and isinstance(right.const, (int, float)):
                try:
                    operations = {"-=": lambda a, b: a - b, "*=": lambda a, b: a * b,
                                  "/=": lambda a, b: a // b if isinstance(a, int) else a / b}
                    value = value_of_const(operations[operator](current.const, right.const)) \
                        if operator in operations else merge(current, right)
                except (KeyError, ZeroDivisionError):
                    value = merge(current, right)
            else:
                value = merge(current, right)

        if target is None:
            return value
        if target.type == "identifier":
            env.set(text(target), value)
            self._check_secret(text(target), value, target)
        elif target.type == "field_access":
            object_node = field(target, "object")
            field_name = text(field(target, "field"))
            owner = cls.name
            if object_node is not None and object_node.type == "identifier":
                candidate = simple_type(env.types.get(text(object_node), ""))
                if candidate in self.classes:
                    owner = candidate
            self._field_values[(owner, field_name)] = value
            if object_node is None or object_node.type == "this":
                env.set(field_name, value)
        elif target.type == "array_access":
            base = field(target, "array")
            if base is not None and base.type == "identifier":
                env.set(text(base), merge(env.get(text(base)), value))
        return value

    def _eval_ternary(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        condition = self.eval(field(node, "condition"), cls, env)
        decision = condition.bool_value
        if decision is True:
            return self.eval(field(node, "consequence"), cls, env)
        if decision is False:
            return self.eval(field(node, "alternative"), cls, env)
        consequence_env = env.copy()
        consequence = self.eval(field(node, "consequence"), cls, consequence_env)
        alternative = self.eval(field(node, "alternative"), cls, env)
        env.absorb(consequence_env)
        return merge(consequence, alternative)

    def _eval_field_access(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        object_node = field(node, "object")
        field_name = text(field(node, "field"))
        if field_name == "length":
            return Value()
        if object_node is None or object_node.type == "this" or (
            object_node.type == "identifier" and text(object_node) == "this"
        ):
            stored = self._field_values.get((cls.name, field_name))
            return stored if stored is not None else Value()
        base = self.eval(object_node, cls, env)
        return derive(base)

    def _eval_array_new(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        values: List[Value] = []
        elements: Optional[Tuple[Value, ...]] = None
        for child in named(node):
            if child.type == "array_initializer":
                initializer = self.eval(child, cls, env)
                values.append(initializer)
                elements = initializer.elements
            else:
                values.append(self.eval(child, cls, env))
        merged = merge(*values) if values else Value()
        return derive(merged, elements=elements)

    # ------------------------------------------------------------------ calls

    def _eval_call(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        name_node = field(node, "name")
        if name_node is None:
            return Value()
        name = text(name_node)
        object_node = field(node, "object")
        args = [self.eval(arg, cls, env) for arg in named(field(node, "arguments"))]
        receiver = self.eval(object_node, cls, env) if object_node is not None else Value()
        receiver_type = self._resolve_receiver_type(object_node, cls, env)
        receiver_text = (text(object_node) + " " + (receiver_type or "")).lower()

        self._check_call_patterns(node, name, args, receiver_text, receiver)

        for sink in catalog.CALL_SINKS:
            if not sink.matches(name.lower(), receiver_text):
                continue
            if sink.rule_id == "java-open-redirect" and name.lower() in ("setheader", "addheader"):
                if not args or not (args[0].is_const and str(args[0].const).lower() == "location"):
                    continue
            values = args if sink.arg is None else (
                [receiver] if sink.arg == -1 else [args[sink.arg]] if sink.arg < len(args) else []
            )
            hot = [member for value in values for member in expand(value) if member.is_hot(sink.cwe)]
            if hot:
                tags: List[str] = []
                for value in hot:
                    tags.extend(value.tags)
                self._report(
                    sink.rule_id, sink.cwe, sink.severity, sink.title, node,
                    f"Untrusted data reaches `{text(node)[:160]}`.", tags,
                    confidence="high" if sink.arg is not None else "medium",
                    extra={"sink": name},
                )
            break

        if object_node is not None and object_node.type == "identifier":
            container = env.get(text(object_node))
            if container.elements is not None or container.entries is not None:
                mutation = self._mutate_container(container, name, args)
                if mutation is not None:
                    new_container, expression_value = mutation
                    env.set(text(object_node), new_container)
                    return expression_value

        callee = self._resolve_method(object_node, name, cls, env)
        if callee is not None:
            result = self._call_method(callee, args, env, depth=1)
        else:
            result = self._library_model(name, args, receiver, receiver_text, env, object_node)

        if name.lower() in catalog.MUTATOR_METHODS and object_node is not None \
                and object_node.type == "identifier":
            mutated = merge(receiver, *([value for value in args if value.tainted] or [Value()]))
            if mutated.tainted:
                env.set(text(object_node), merge(env.get(text(object_node)), mutated))
        return result

    def _mutate_container(self, container: Value, name: str,
                          args: List[Value]) -> Optional[Tuple[Value, Value]]:
        """Model list/map operations precisely enough for clone-and-read idioms."""
        lowered = name.lower()
        if container.elements is not None:
            elements = list(container.elements)
            if lowered in ("add", "offer", "push", "addlast", "addfirst", "addall"):
                if lowered == "addall" and args:
                    items = list(args[0].elements) if args[0].elements is not None else [args[0]]
                    elements.extend(items)
                    return Value(elements=tuple(elements[:64])), args[0]
                value = args[-1] if args else Value()
                if len(args) == 2 and args[0].is_const and isinstance(args[0].const, int):
                    index = max(0, min(int(args[0].const), len(elements)))
                    elements.insert(index, value)
                elif lowered == "addfirst":
                    elements.insert(0, value)
                else:
                    elements.append(value)
                return Value(elements=tuple(elements[:64])), value
            if lowered == "remove":
                if args and args[0].is_const and isinstance(args[0].const, int) \
                        and not isinstance(args[0].const, bool):
                    index = int(args[0].const)
                    if 0 <= index < len(elements):
                        removed = elements.pop(index)
                        return Value(elements=tuple(elements)), removed
                    return Value(elements=tuple(elements)), Value()
                if args and args[0].is_const and isinstance(args[0].const, str):
                    for index, element in enumerate(elements):
                        if element.is_const and element.const == args[0].const:
                            removed = elements.pop(index)
                            return Value(elements=tuple(elements)), removed
                # Unknown element: keep the shape but carry the container taint.
                return derive(container, elements=tuple(elements)), derive(container)
            if lowered == "get":
                if args and args[0].is_const and isinstance(args[0].const, int):
                    index = int(args[0].const)
                    if 0 <= index < len(elements):
                        return Value(elements=tuple(elements)), elements[index]
                    return Value(elements=tuple(elements)), Value()
                return Value(elements=tuple(elements)), (merge(*elements) if elements else Value())
            if lowered == "set" and len(args) == 2 and args[0].is_const and isinstance(args[0].const, int):
                index = int(args[0].const)
                if 0 <= index < len(elements):
                    elements[index] = args[1]
                return Value(elements=tuple(elements)), args[1]
            if lowered == "size":
                return Value(elements=tuple(elements)), value_of_const(len(elements))
            if lowered == "isempty":
                return Value(elements=tuple(elements)), value_of_const(len(elements) == 0)
            if lowered == "clear":
                return Value(elements=()), Value()
            if lowered in ("iterator", "stream", "toarray", "values", "listiterator"):
                merged = merge(*elements) if elements else Value()
                return Value(elements=tuple(elements)), derive(merged)
            return None
        if container.entries is not None:
            entries = dict(container.entries)
            if lowered in ("put", "putall", "set") and args:
                if len(args) >= 2:
                    key = args[0].const if args[0].is_const else "<dynamic>"
                    entries[key] = args[1]
                    item: Any = args[1]
                else:
                    for key, value in (args[0].entries or ()):
                        entries[key] = value
                    item = args[0]
                return Value(entries=tuple(entries.items())), item
            if lowered in ("get", "getordefault"):
                key = args[0].const if args and args[0].is_const else None
                if key is not None and key in entries:
                    return Value(entries=tuple(entries.items())), entries[key]
                if key is None and entries:
                    merged = merge(*entries.values())
                    return Value(entries=tuple(entries.items())), merged
                if lowered == "getordefault" and len(args) > 1:
                    return Value(entries=tuple(entries.items())), args[1]
                return Value(entries=tuple(entries.items())), Value()
            if lowered == "containskey":
                key = args[0].const if args and args[0].is_const else None
                return Value(entries=tuple(entries.items())), value_of_const(key in entries)
            if lowered in ("values",):
                merged = merge(*entries.values()) if entries else Value()
                return Value(entries=tuple(entries.items())), derive(merged, elements=tuple(entries.values()))
            if lowered in ("keyset", "entryset"):
                merged = merge(*entries.values()) if entries else Value()
                return (Value(entries=tuple(entries.items())),
                        derive(merged, elements=tuple(value_of_const(k) for k in entries)))
            if lowered == "size":
                return Value(entries=tuple(entries.items())), value_of_const(len(entries))
            if lowered == "isempty":
                return Value(entries=tuple(entries.items())), value_of_const(len(entries) == 0)
            if lowered == "remove":
                key = args[0].const if args and args[0].is_const else None
                removed = entries.pop(key, Value())
                return Value(entries=tuple(entries.items())), removed
            return None
        return None

    def _eval_new(self, node: Node, cls: ClassInfo, env: Env) -> Value:
        type_node = field(node, "type")
        type_text = text(type_node)
        type_name = simple_type(type_text)
        args = [self.eval(arg, cls, env) for arg in named(field(node, "arguments"))]

        if type_name.lower() == "random" and "secure" not in type_text.lower():
            self._report(
                "java-weak-random", "CWE-330", Severity.MEDIUM,
                "Insecure random number generator",
                node, f"`new {type_text}()` uses a predictable PRNG for security sensitive values.",
                confidence="high", extra={"algorithm": type_text},
            )

        for sink in catalog.NEW_SINKS:
            if not sink.matches(type_name):
                continue
            values = args if sink.arg is None else (
                [args[sink.arg]] if sink.arg < len(args) else []
            )
            hot = [member for value in values for member in expand(value) if member.is_hot(sink.cwe)]
            if hot:
                tags: List[str] = []
                for value in hot:
                    tags.extend(value.tags)
                self._report(sink.rule_id, sink.cwe, sink.severity, sink.title, node,
                             f"Untrusted data reaches `new {type_text}(...)`.", tags,
                             confidence="high", extra={"sink": type_text})
            break

        if type_name in ("SecretKeySpec", "DESKeySpec", "DESedeKeySpec") and len(args) >= 2:
            algorithm = args[1].const if args[1].is_const else None
            if catalog.is_weak_cipher(algorithm):
                self._report("java-weak-cipher", "CWE-327", Severity.HIGH,
                             "Weak cryptographic key algorithm", node,
                             f"`new {type_text}(..., \"{algorithm}\")` uses a weak algorithm.",
                             confidence="high", extra={"algorithm": algorithm})

        if type_name == "Cookie":
            return Value(origin="local_cookie")
        if type_name.lower() in catalog.LIST_TYPES:
            return Value(elements=())
        if type_name.lower() in catalog.MAP_TYPES:
            return Value(entries=())

        constructed = Value()
        if type_name in ("String", "StringBuilder", "StringBuffer", "URL", "URI", "File", "Path"):
            constructed = merge(*args) if args else Value()
            if type_name == "String" and args and args[0].is_const:
                constructed = Value(const=str(args[0].const), const_type="str")
        return constructed

    # ------------------------------------------------------------------ library model

    def _library_model(self, name: str, args: List[Value], receiver: Value,
                       receiver_text: str, env: Env, object_node: Optional[Node]) -> Value:
        lowered = name.lower()

        if lowered == "getproperty" or lowered == "getclientproperty":
            key = args[0].const if args and args[0].is_const else None
            if isinstance(key, str):
                if key in self.properties:
                    return value_of_const(self.properties[key])
                if len(args) > 1:
                    return args[1]
            return Value()

        if lowered == "getvalue" and any(hint in receiver_text for hint in catalog.COOKIE_TYPE_HINTS):
            if receiver.origin == "local_cookie":
                return Value(origin="local_cookie")
            return tainted(catalog.COOKIE_VALUE_SOURCE)

        if lowered in catalog.SOURCE_METHODS:
            hints = catalog.SOURCE_RECEIVER_HINTS.get(lowered)
            if not hints or not receiver_text or any(hint in receiver_text for hint in hints):
                return tainted(catalog.SOURCE_METHODS[lowered])

        if lowered in ("readobject", "readunshared"):
            return tainted("ObjectInputStream.readObject")

        if lowered in catalog.SANITIZER_CWES:
            neutralised = catalog.SANITIZER_CWES[lowered]
            base = merge(receiver, *args)
            if not any(value.tainted for value in args) and not receiver.tainted:
                return Value()
            if lowered.startswith("parse"):
                if args and args[0].is_const and isinstance(args[0].const, str):
                    try:
                        if lowered == "parseboolean":
                            return value_of_const(args[0].const.strip().lower() == "true")
                        if lowered in ("parseint", "parselong"):
                            return value_of_const(int(args[0].const.strip()))
                        return value_of_const(float(args[0].const.strip()))
                    except ValueError:
                        pass
                return Value()
            return Value(tainted=True, tags=base.tags, clean=base.clean | neutralised,
                         origin=base.origin)

        if lowered in ("parseint", "parselong", "parsedouble", "parsefloat", "parseboolean"):
            if args and args[0].is_const and isinstance(args[0].const, str):
                try:
                    if lowered == "parseboolean":
                        return value_of_const(args[0].const.strip().lower() == "true")
                    if lowered in ("parseint", "parselong"):
                        return value_of_const(int(args[0].const.strip()))
                    return value_of_const(float(args[0].const.strip()))
                except ValueError:
                    pass
            return Value()

        if lowered == "charat" and args and receiver.is_const and isinstance(receiver.const, str) \
                and args[0].is_const and isinstance(args[0].const, int) \
                and not isinstance(args[0].const, bool):
            index = int(args[0].const)
            if 0 <= index < len(receiver.const):
                return value_of_const(receiver.const[index])

        if lowered in ("valueof", "tostring", "format", "concat", "join"):
            if lowered in ("valueof", "tostring") and len(args) == 1 and args[0].is_const:
                if args[0].const_type == "str":
                    return value_of_const(args[0].const)
                if isinstance(args[0].const, (int, float)):
                    return value_of_const(str(args[0].const))
            if lowered == "tostring" and not args:
                return derive(receiver)
            return merge(receiver, *args) if args else derive(receiver)

        if lowered in catalog.PROPAGATOR_METHODS:
            if not args:
                return derive(receiver)
            return merge(receiver, *args)

        if lowered in catalog.BOOLEAN_METHODS:
            if lowered in ("length", "size") and not receiver.tainted:
                return Value()
            return Value()

        if lowered in catalog.MUTATOR_METHODS:
            return receiver

        return Value()

    # ------------------------------------------------------------------ resolution

    def _resolve_method(self, object_node: Optional[Node], name: str,
                        cls: ClassInfo, env: Env) -> Optional[MethodInfo]:
        lowered = name.lower()
        if object_node is None:
            methods = cls.methods.get(name)
            if methods:
                return methods[0]
            found: List[MethodInfo] = []
            for class_info in self.classes.values():
                found.extend(class_info.methods.get(name, []))
            return found[0] if len(found) == 1 else None
        if object_node.type == "this":
            methods = cls.methods.get(name)
            return methods[0] if methods else None
        target_class: Optional[ClassInfo] = None
        if object_node.type == "object_creation_expression":
            target_class = self.classes.get(simple_type(text(field(object_node, "type"))))
        elif object_node.type == "identifier":
            declared = simple_type(env.types.get(text(object_node), ""))
            target_class = self.classes.get(declared)
        if target_class is None:
            return None
        methods = target_class.methods.get(name)
        if methods:
            return methods[0]
        return None

    def _resolve_receiver_type(self, object_node: Optional[Node], cls: ClassInfo,
                               env: Env) -> str:
        if object_node is None:
            return cls.name
        if object_node.type == "this":
            return cls.name
        if object_node.type == "object_creation_expression":
            return simple_type(text(field(object_node, "type")))
        if object_node.type == "identifier":
            name = text(object_node)
            if name in env.types:
                return simple_type(env.types[name])
            if name in cls.fields:
                return simple_type(cls.fields[name])
            if name in self.classes:
                return name
        if object_node.type == "method_invocation":
            return ""  # chained call: receiver hint comes from the text itself
        if object_node.type == "field_access":
            field_name = text(field(object_node, "field"))
            if field_name in cls.fields:
                return simple_type(cls.fields[field_name])
        return ""

    def _call_method(self, method: MethodInfo, args: List[Value], caller_env: Env,
                     depth: int) -> Value:
        if method.body is None:
            return Value()
        taint_signature = tuple("1" if value.tainted else "0" for value in args)
        key = (method.owner, method.name, taint_signature)
        if depth >= self.max_depth or key in self._active:
            if any(value.tainted for value in args):
                return merge(*args)
            return Value()
        self._active.add(key)
        try:
            class_info = self.classes.get(method.owner)
            if class_info is None:
                return Value()
            env = Env()
            for index, (param_type, param_name) in enumerate(method.params):
                value = args[index] if index < len(args) else Value()
                env.set(param_name, value)
                env.types[param_name] = param_type
            self.exec_block(method.body, class_info, env)
            return merge(*env.returns) if env.returns else Value()
        finally:
            self._active.discard(key)

    # ------------------------------------------------------------------ pattern sinks

    def _check_call_patterns(self, node: Node, name: str, args: List[Value],
                             receiver_text: str, receiver: Value) -> None:
        lowered = name.lower()

        for method, rule_id, cwe, severity, title in catalog.COOKIE_FLAG_RULES:
            if lowered == method and args and args[0].is_const and args[0].const is False:
                self._report(rule_id, cwe, severity, title, node,
                             f"`{name}(false)` disables a cookie protection flag.",
                             confidence="high")

        if lowered == "getinstance":
            for prefix, (rule_id, cwe, severity, title) in catalog.CRYPTO_GETINSTANCE_RECEIVERS.items():
                if prefix not in receiver_text:
                    continue
                algorithm = args[0].const if args and args[0].is_const else None
                weak = catalog.is_weak_hash(algorithm) if prefix in ("messagedigest", "mac", "signature") \
                    else catalog.is_weak_cipher(algorithm)
                if weak:
                    self._report(rule_id, cwe, severity, title, node,
                                 f"`{receiver_text.strip()} getInstance(\"{algorithm}\")` uses a broken algorithm.",
                                 confidence="high", extra={"algorithm": algorithm})
                break

        if lowered == "random" and "math" in receiver_text:
            self._report("java-weak-random", "CWE-330", Severity.MEDIUM,
                         "Insecure random number generator", node,
                         "`Math.random()` uses a predictable PRNG for security sensitive values.",
                         confidence="high", extra={"algorithm": "Math.random"})

        if lowered in ("sendredirect",) and args and args[0].tainted:
            self._report("java-open-redirect", "CWE-601", Severity.MEDIUM,
                         "Open redirect: attacker controlled redirect target", node,
                         f"Untrusted data reaches `{name}(...)`.", args[0].tags,
                         confidence="high")

    def _check_secret(self, name: str, value: Value, node: Node) -> None:
        if not value.is_const or not isinstance(value.const, str):
            return
        literal = value.const.strip()
        if len(literal) < 6 or literal.lower() in catalog.SECRET_PLACEHOLDERS:
            return
        if not catalog.SECRET_NAME_RE.search(name):
            return
        self._report("java-hardcoded-secret", "CWE-798", Severity.HIGH,
                     "Hardcoded credential", node,
                     f"Variable `{name}` is initialised with a hardcoded secret.",
                     confidence="high")


def load_properties(root: str, max_files: int = 40) -> Dict[str, str]:
    """Collect `key=value` pairs from *.properties files under ``root``."""
    properties: Dict[str, str] = {}
    found = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "target", "build", "dist")]
        for filename in filenames:
            if not filename.endswith(".properties"):
                continue
            found += 1
            if found > max_files:
                return properties
            try:
                with open(os.path.join(dirpath, filename), "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line or line.startswith(("#", "!")):
                            continue
                        if "=" in line:
                            key, value = line.split("=", 1)
                        elif ":" in line:
                            key, value = line.split(":", 1)
                        else:
                            continue
                        properties.setdefault(key.strip(), value.strip())
            except OSError:
                continue
    return properties


def analyze_file(path: str, root: str, source: Optional[bytes] = None,
                 properties: Optional[Dict[str, str]] = None) -> List[Finding]:
    """Analyse one Java file and return findings with paths relative to ``root``."""
    relative = os.path.relpath(path, root).replace(os.sep, "/") if root else path
    if source is None:
        try:
            source = open(path, "rb").read()
        except OSError:
            return []
    engine = JavaEngine(relative, source, properties=properties)
    return engine.run()
