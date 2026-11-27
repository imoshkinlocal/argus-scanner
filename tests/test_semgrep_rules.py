"""Bundled Semgrep rule packs: structure, validity and detection."""

from __future__ import annotations

import os
import re
import subprocess

import pytest

from argus.sast import semgrep_engine

BUNDLE = semgrep_engine.bundle_root()
LANGUAGES = [language for language in semgrep_engine.SEMGREP_LANGUAGES
             if os.path.isdir(os.path.join(BUNDLE, semgrep_engine.RULE_DIR_ALIASES.get(language, language)))]
ALLOWED_SEVERITIES = {"ERROR", "WARNING", "INFO"}

#: Natural id prefixes that differ from the language name.
ID_PREFIX = {"javascript": "js", "typescript": "ts"}

SEMGREP = semgrep_engine.find_semgrep()

requires_semgrep = pytest.mark.skipif(SEMGREP is None, reason="semgrep is not installed")


def rule_files():
    """Yield ``(language, path)`` once per rule pack (aliases collapse)."""
    seen = set()
    for language in LANGUAGES:
        directory = os.path.join(BUNDLE, semgrep_engine.RULE_DIR_ALIASES.get(language, language))
        if directory in seen:
            continue
        seen.add(directory)
        for filename in sorted(os.listdir(directory)):
            if filename.endswith((".yaml", ".yml")):
                yield language, os.path.join(directory, filename)


def parse_rules(path):
    """Split a pack into rule blocks (the files use a flat ``rules:`` list)."""
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    blocks, current = [], None
    for line in lines:
        if line.strip().startswith("- id:"):
            current = [line]
            blocks.append(current)
        elif current is not None:
            current.append(line)
    return ["\n".join(block) for block in blocks]


# --------------------------------------------------------------------------- structure

def test_every_language_has_a_rule_pack():
    assert sorted(LANGUAGES) == sorted(semgrep_engine.SEMGREP_LANGUAGES)


def test_rule_ids_are_unique_and_prefixed():
    seen = {}
    for language, path in rule_files():
        prefix = ID_PREFIX.get(language, language)
        for block in parse_rules(path):
            rule_id = block.split("- id:", 1)[1].split("\n", 1)[0].strip()
            assert rule_id not in seen, f"duplicate rule id {rule_id}"
            seen[rule_id] = path
            assert rule_id.startswith(f"{prefix}-"), f"{rule_id} in {path} lacks the {prefix}- prefix"
    assert len(seen) >= 40


def test_rule_blocks_have_required_fields():
    for _language, path in rule_files():
        for block in parse_rules(path):
            rule_id = block.split("- id:", 1)[1].split("\n", 1)[0].strip()
            assert "languages:" in block, f"{rule_id} has no languages"
            assert "message:" in block, f"{rule_id} has no message"
            assert "metadata:" in block, f"{rule_id} has no metadata"
            assert "cwe:" in block, f"{rule_id} has no CWE"
            severity = block.split("severity:", 1)[1].split("\n", 1)[0].strip()
            assert severity in ALLOWED_SEVERITIES, f"{rule_id} has severity {severity}"


def test_list_rules_matches_files_on_disk():
    listed = semgrep_engine.list_rules()
    on_disk = sum(len(parse_rules(path)) for _language, path in rule_files())
    assert len(listed) == on_disk
    assert {rule["language"] for rule in listed} == set(LANGUAGES) - set(semgrep_engine.RULE_DIR_ALIASES)
    for rule in listed:
        assert rule["cwe"].startswith("CWE-"), rule


def _field(block: str, name: str) -> str:
    """Read a scalar top-level field from one rule block."""
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{name}:"):
            return stripped.split(":", 1)[1].strip()
    return ""


def test_fix_suggestions_are_well_formed():
    """A fix is a proposal: it must be complete, valid and keep the severity.

    The rules never opt into autofix, so the only correctness requirements are
    that the replacement is usable as written and that the rule still declares
    a severity the shared ladder can map.  A bare ``...`` in a replacement is
    rejected because Semgrep writes it literally to the source.
    """
    fixed = 0
    for _language, path in rule_files():
        for block in parse_rules(path):
            rule_id = _field(block, "id")
            has_fix = bool(_field(block, "fix")) or "fix-regex:" in block
            if not has_fix:
                continue
            fixed += 1
            severity = _field(block, "severity")
            assert severity in ALLOWED_SEVERITIES, f"{rule_id} has severity {severity}"
            replacement = _field(block, "fix")
            if replacement:
                # ``$...ARGS`` is a metavariable, not an ellipsis literal.
                remaining = re.sub(r"\$\.\.\.[A-Z_][A-Z0-9_]*", "", replacement)
                assert "..." not in remaining, (
                    f"{rule_id} has an ellipsis in its fix; it would be written "
                    "to the source literally")
            if "fix-regex:" in block:
                assert "regex:" in block, f"{rule_id} has fix-regex without regex"
                assert "replacement:" in block, f"{rule_id} has fix-regex without replacement"
    assert fixed >= 5, "expected the bundle to carry suggested fixes"


# --------------------------------------------------------------------------- semgrep integration

@requires_semgrep
def test_semgrep_validates_bundled_rules():
    completed = subprocess.run(
        [SEMGREP, "scan", "--validate", "--config", BUNDLE, "--metrics=off",
         "--disable-version-check"],
        capture_output=True, text=True, timeout=600,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "Configuration is valid" in (completed.stdout + completed.stderr)


@requires_semgrep
def test_rule_packs_fire_on_known_vulnerabilities(rulecheck_dir):
    findings, errors = semgrep_engine.run_semgrep(rulecheck_dir, jobs=1)
    assert not errors
    by_file = {}
    for finding in findings:
        by_file.setdefault(os.path.basename(finding.file), set()).add(finding.rule_id)
    assert "python-command-injection" in by_file["app.py"]
    assert "js-command-injection" in by_file["app.js"]
    assert "go-command-injection" in by_file["app.go"]
    assert "php-command-injection" in by_file["app.php"]
    assert "ruby-command-injection" in by_file["app.rb"]
    assert "ruby-marshal-load" in by_file["app.rb"]
    assert "c-unbounded-copy" in by_file["app.c"]
    for finding in findings:
        assert finding.engine == "semgrep"
        assert finding.kind == "sast"
        assert finding.start_line >= 1
        assert not finding.rule_id.startswith(os.sep), "rule ids must not be path-namespaced"


@requires_semgrep
def test_clean_python_file_has_no_findings(tmp_path):
    (tmp_path / "safe.py").write_text(
        "import subprocess\n"
        "subprocess.run(['ls', '-l'], check=True)\n"
        "print('hello')\n"
    )
    findings, _errors = semgrep_engine.run_semgrep(str(tmp_path), jobs=1)
    assert findings == []


@requires_semgrep
def test_ruby_pack_detects_common_sinks(tmp_path):
    (tmp_path / "app.rb").write_text(
        "def handle(params)\n"
        "  system(params[:cmd])\n"
        "  eval(params[:code])\n"
        "  Marshal.load(params[:blob])\n"
        "  YAML.load(params[:yaml])\n"
        "  File.read(params[:path])\n"
        "  Digest::MD5.hexdigest(params[:data])\n"
        "end\n"
    )
    (tmp_path / "view.erb").write_text("<h1><%= raw @name %></h1>\n<h2><%= @safe %></h2>\n")
    findings, errors = semgrep_engine.run_semgrep(
        str(tmp_path), rules=os.path.join(BUNDLE, "ruby"), jobs=1)
    assert not errors
    ids = {finding.rule_id for finding in findings}
    assert {
        "ruby-command-injection",
        "ruby-dynamic-code",
        "ruby-marshal-load",
        "ruby-yaml-load",
        "ruby-path-traversal",
        "ruby-weak-hash",
        "ruby-erb-unescaped-output",
    } <= ids
    erb = [finding for finding in findings if finding.file.endswith(".erb")]
    assert len(erb) == 1


@requires_semgrep
def test_c_memory_copy_noise_is_suppressed(tmp_path):
    (tmp_path / "bounded.c").write_text(
        "#include <string.h>\n"
        "#include <stdlib.h>\n"
        "void f(char *src, size_t n) {\n"
        "  char *buf = malloc(n);\n"
        "  memcpy(buf, src, n);\n"
        "  char *term = alloc(n + 1);\n"
        "  memcpy(term, src, n);\n"
        "  int *values = calloc(n, sizeof(int));\n"
        "  memcpy(values, src, sizeof(int) * n);\n"
        "  memcpy(values, src, sizeof(int));\n"
        "}\n"
    )
    (tmp_path / "unbounded.c").write_text(
        "#include <string.h>\n"
        "void g(char *dst, char *src, size_t n) {\n"
        "  memcpy(dst, src, n);\n"
        "  memcpy(dst, src, n * sizeof(int));\n"
        "}\n"
    )
    findings, _errors = semgrep_engine.run_semgrep(
        str(tmp_path), rules=os.path.join(BUNDLE, "c"), jobs=1)
    pairs = {(os.path.basename(finding.file), finding.rule_id) for finding in findings}
    assert ("bounded.c", "c-unsafe-memory-copy") not in pairs
    assert ("unbounded.c", "c-unsafe-memory-copy") in pairs
    assert all(name == "unbounded.c" for name, _rule in pairs)


def test_missing_rule_directory_raises(tmp_path):
    with pytest.raises(semgrep_engine.SemgrepError):
        semgrep_engine.run_semgrep(str(tmp_path), rules=str(tmp_path / "nope"))


def test_languages_for_paths():
    assert semgrep_engine.languages_for_paths(
        ["a.py", "b.js", "c.ts", "d.go", "e.php", "f.c", "g.cpp", "h.java", "i.rb", "j.erb"]
    ) == ["c", "cpp", "go", "java", "javascript", "php", "python", "ruby", "typescript"]
    assert semgrep_engine.languages_for_paths(["README.md"]) == []


def test_rule_dirs_only_returns_existing_languages():
    directories = semgrep_engine.rule_dirs(["python", "cobol"])
    assert directories == [os.path.join(BUNDLE, "python")]


def test_typescript_shares_the_javascript_pack():
    assert semgrep_engine.rule_dirs(["typescript"]) == [os.path.join(BUNDLE, "javascript")]
    assert semgrep_engine.rule_dirs(["javascript", "typescript"]) == [os.path.join(BUNDLE, "javascript")]
