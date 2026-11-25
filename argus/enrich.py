"""Finding enrichment: source context, remediation hints and CWE names.

Enrichment is deliberately dependency-free and cheap.  It turns the raw
location of a finding into a short code snippet and a concrete "what to do"
list, which is what makes a report actionable without opening an IDE.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import cwe as cwe_module
from .models import Finding, Severity, parse_severity

DEFAULT_CONTEXT_LINES = 2
DEFAULT_MAX_FILE_BYTES = 2_000_000
MAX_SNIPPET_LINE = 400

#: Short, rule-family specific advice for the Java/Semgrep rules.
_RULE_HINTS: Tuple[Tuple[str, str], ...] = (
    ("sql", "Use a prepared statement with bound parameters instead of string concatenation."),
    ("xss", "Escape output for the exact HTML/JS/URL context, or use a templating engine "
            "with auto-escaping."),
    ("command", "Pass an argument list to ProcessBuilder and never invoke a shell."),
    ("exec", "Avoid dynamic code execution; map user input to a fixed set of operations."),
    ("path", "Canonicalise the path and verify it stays inside the allowed base directory."),
    ("traversal", "Canonicalise the path and verify it stays inside the allowed base directory."),
    ("ldap", "Escape LDAP filter metacharacters or use the provider's filter builder."),
    ("xpath", "Use XPath variables instead of concatenating user input."),
    ("xxe", "Disable DTDs and external entities on the XML parser."),
    ("deserial", "Do not deserialise untrusted data; use a data-only format such as JSON."),
    ("redirect", "Allow only relative paths or an explicit allowlist of hosts."),
    ("ssrf", "Allowlist schemes and hosts, and block loopback/private address ranges."),
    ("crypto", "Replace MD5/SHA-1/DES/RC4 with AES-GCM, SHA-256+ or a password hash."),
    ("random", "Use a cryptographically secure random generator (SecureRandom, secrets)."),
    ("cookie", "Set the Secure, HttpOnly and SameSite attributes on session cookies."),
    ("temp", "Create temporary files with mkstemp/TemporaryFile in a private directory."),
    ("upload", "Validate extension and MIME type against an allowlist and store uploads "
               "outside the web root."),
    ("secret", "Remove the secret from the repository, rotate it and load it from a "
               "secret manager or environment variable."),
    ("docker", "Run the container as a non-root user with a read-only root filesystem."),
    ("terraform", "Remove public access and enable encryption for the resource."),
)

#: Upgrade commands per OSV ecosystem. ``{name}`` and ``{version}`` are filled in.
_UPGRADE_COMMANDS: Dict[str, str] = {
    "npm": "npm install {name}@{version}",
    "PyPI": "pip install '{name}=={version}'",
    "Maven": "mvn versions:use-dep-version -Dincludes={name} -DdepVersion={version}",
    "Go": "go get {name}@{version}",
    "Packagist": "composer require '{name}:{version}'",
    "RubyGems": "bundle update {name} --conservative  # target {version}",
    "crates.io": "cargo update -p {name} --precise {version}",
    "NuGet": "dotnet add package {name} --version {version}",
    "ConanCenter": "conan install --requires={name}/{version}",
}


@dataclasses.dataclass
class EnrichOptions:
    """Controls what ``enrich`` attaches to findings."""

    root: str = ""
    context_lines: int = DEFAULT_CONTEXT_LINES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    snippets: bool = True
    remediation: bool = True
    cwe_names: bool = True


def read_snippet(path: str, line: int, context: int = DEFAULT_CONTEXT_LINES,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Optional[Tuple[int, List[str]]]:
    """Return ``(start_line, lines)`` around ``line`` (1-based)."""
    if not path or line <= 0 or context < 0:
        return None
    try:
        if os.path.getsize(path) > max_file_bytes:
            return None
        with open(path, "rb") as handle:
            raw = handle.read(max_file_bytes + 1)
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return None
    index = min(max(line - 1, 0), len(lines) - 1)
    start = max(0, index - context)
    end = min(len(lines), index + context + 1)
    snippet = [
        (item[:MAX_SNIPPET_LINE] + ("..." if len(item) > MAX_SNIPPET_LINE else ""))
        for item in lines[start:end]
    ]
    return start + 1, snippet


def attach_snippets(findings: Iterable[Finding], root: str = "",
                    context: int = DEFAULT_CONTEXT_LINES,
                    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> int:
    """Attach source snippets to file-based findings. Returns the count."""
    attached = 0
    for finding in findings:
        if not finding.file or finding.start_line <= 0:
            continue
        path = finding.file
        if not os.path.isabs(path):
            path = os.path.join(root or ".", path)
        result = read_snippet(path, finding.start_line, context, max_file_bytes)
        if result is None:
            continue
        start, lines = result
        finding.snippet_start = start
        finding.snippet = lines
        attached += 1
    return attached


def _rule_hint(rule_id: str) -> str:
    lowered = rule_id.lower()
    for marker, hint in _RULE_HINTS:
        if marker in lowered:
            return hint
    return ""


def upgrade_command(finding: Finding) -> str:
    """Return the ecosystem-specific upgrade command, or an empty string."""
    if not finding.package or not finding.fixed_version:
        return ""
    ecosystem = str(finding.metadata.get("ecosystem") or "")
    template = _UPGRADE_COMMANDS.get(ecosystem)
    if not template:
        return ""
    return template.format(name=finding.package, version=finding.fixed_version)


def remediation_for(finding: Finding) -> List[str]:
    """Build a short, ordered remediation list for one finding."""
    commands: List[str] = []
    if finding.kind == "sca":
        if finding.fixed_version:
            command = upgrade_command(finding)
            if command:
                commands.append(command)
            commands.append(
                f"Upgrade {finding.package} from {finding.version or '?'} "
                f"to {finding.fixed_version} or later.")
        else:
            commands.append(
                f"No fixed version is published yet for {finding.package}; "
                "track the advisory and apply mitigations.")
    entry = cwe_module.lookup(finding.cwe)
    if entry is not None and entry.known:
        for mitigation in entry.mitigations[:2]:
            if mitigation not in commands:
                commands.append(mitigation)
    hint = _rule_hint(finding.rule_id)
    if hint and hint not in commands:
        commands.insert(0, hint)
    if finding.engine == "argus-secrets":
        extra = "Rotate the exposed credential and purge it from git history."
        if extra not in commands:
            commands.insert(0, extra)
    return commands[:4]


def attach_remediation(findings: Iterable[Finding]) -> int:
    """Attach remediation hints to every finding. Returns the count."""
    attached = 0
    for finding in findings:
        hints = remediation_for(finding)
        if hints:
            finding.remediation = hints
            attached += 1
    return attached


def attach_cwe_names(findings: Iterable[Finding]) -> int:
    """Resolve ``cwe`` into the official and Russian names."""
    attached = 0
    for finding in findings:
        entry = cwe_module.lookup(finding.cwe)
        if entry is None:
            continue
        finding.cwe_name = entry.name
        finding.cwe_name_ru = entry.name_ru
        attached += 1
    return attached


def _override_matches(finding: Finding, pattern: str) -> bool:
    text = str(pattern or "").strip()
    if not text:
        return False
    if text.upper().startswith("CWE-"):
        return cwe_module.format_cwe(text) == cwe_module.format_cwe(finding.cwe)
    if text.lower().startswith(("pkg:", "package:")):
        wanted = text.split(":", 1)[1]
        candidates = [finding.package, finding.purl,
                      f"{finding.package}@{finding.version}"]
        return any(candidate and _glob(candidate, wanted) for candidate in candidates)
    return _glob(finding.rule_id, text)


def _glob(value: str, pattern: str) -> bool:
    return (fnmatch.fnmatchcase(value, pattern)
            or fnmatch.fnmatchcase(value.lower(), pattern.lower()))


def apply_severity_overrides(findings: Iterable[Finding],
                             overrides: Mapping[str, Any]) -> int:
    """Apply ``rule``/``CWE``/``package`` severity overrides in place."""
    if not overrides:
        return 0
    changed = 0
    for finding in findings:
        for pattern, value in overrides.items():
            if not _override_matches(finding, str(pattern)):
                continue
            severity = parse_severity(value, Severity.UNKNOWN)
            if severity is Severity.UNKNOWN:
                continue
            if severity != finding.severity:
                finding.metadata.setdefault("severity_original", finding.severity.value)
                finding.metadata["severity_override"] = str(pattern)
                finding.severity = severity
                changed += 1
            break
    return changed


def enrich(findings: Iterable[Finding], options: Optional[EnrichOptions] = None) -> Dict[str, int]:
    """Apply all enrichment steps and return counters."""
    opts = options or EnrichOptions()
    items = list(findings)
    counts = {"snippets": 0, "remediation": 0, "cwe": 0}
    if opts.cwe_names:
        counts["cwe"] = attach_cwe_names(items)
    if opts.remediation:
        counts["remediation"] = attach_remediation(items)
    if opts.snippets and opts.context_lines > 0:
        counts["snippets"] = attach_snippets(
            items, opts.root, context=opts.context_lines,
            max_file_bytes=opts.max_file_bytes)
    return counts


def format_snippet(finding: Finding, marker: int = 0) -> str:
    """Render an attached snippet with line numbers for terminals and GUI."""
    if not finding.snippet:
        return ""
    start = finding.snippet_start or max(1, finding.start_line)
    highlight = marker or finding.start_line
    width = len(str(start + len(finding.snippet)))
    lines = []
    for offset, text in enumerate(finding.snippet):
        number = start + offset
        prefix = ">" if number == highlight else " "
        lines.append(f"{prefix} {number:>{width}} | {text}")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_CONTEXT_LINES",
    "EnrichOptions",
    "apply_severity_overrides",
    "attach_cwe_names",
    "attach_remediation",
    "attach_snippets",
    "enrich",
    "format_snippet",
    "read_snippet",
    "remediation_for",
    "upgrade_command",
]
