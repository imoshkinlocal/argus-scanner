"""Offline secret scanning for argus.

The module implements a small, dependency-free rule set for credentials that
are accidentally committed to source code.  It is deliberately independent
from the SAST and SCA pipelines: callers pass a directory and receive ordinary
:class:`argus.models.Finding` objects.

Secrets are never copied into a finding.  Messages and metadata contain only a
masked form (first four and last four characters) and the original length, so
reports can be shared without leaking the credential.
"""

from __future__ import annotations

import collections
import dataclasses
import math
import os
import re
from typing import Dict, Iterator, List, Optional, Pattern, Sequence, Tuple

from .models import Finding, Severity, normalize_path

#: Files larger than this are skipped by default.
DEFAULT_MAX_FILE_BYTES = 512_000

#: Directories that never contain first-party source worth scanning.
SKIP_DIRECTORIES: Tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
)

#: Case-insensitive substrings that mark an obvious non-secret placeholder.
PLACEHOLDER_MARKERS: Tuple[str, ...] = (
    "example",
    "sample",
    "changeme",
    "placeholder",
    "dummy",
    "test",
    "xxxx",
    "yyyy",
    "your_",
    "<",
    ">",
    "${",
    "{{",
    "}}",
    "os.environ",
    "process.env",
    "getenv",
    "variables",
)

#: Rule id of the heuristic key/value rule, handled separately below.
GENERIC_RULE_ID = "secret-generic-assignment"

#: Minimum Shannon entropy for a generic assignment to be reported.
GENERIC_MIN_ENTROPY = 3.5

#: Official provider documentation linked from findings.
AWS_KEYS_REFERENCE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
)
GITHUB_REFERENCE = (
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
    "about-authentication-to-github"
)
SLACK_REFERENCE = "https://api.slack.com/authentication/token-types"
STRIPE_REFERENCE = "https://docs.stripe.com/keys"
GOOGLE_REFERENCE = "https://cloud.google.com/docs/authentication/api-keys"
PRIVATE_KEY_REFERENCE = "https://datatracker.ietf.org/doc/html/rfc5958"
JWT_REFERENCE = "https://datatracker.ietf.org/doc/html/rfc7519"
CWE_REFERENCE = "https://cwe.mitre.org/data/definitions/798.html"


@dataclasses.dataclass(frozen=True)
class SecretRule:
    """One detection rule.

    ``value_group`` selects the group of ``pattern`` that contains the secret;
    ``-1`` means the rule is handled by custom logic (generic assignments).
    """

    rule_id: str
    title: str
    severity: Severity
    pattern: Pattern[str]
    references: Tuple[str, ...] = ()
    value_group: int = 0


def _compile(pattern: str) -> Pattern[str]:
    return re.compile(pattern)


RULES: Tuple[SecretRule, ...] = (
    SecretRule(
        rule_id="secret-aws-access-key",
        title="AWS access key ID",
        severity=Severity.CRITICAL,
        pattern=_compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        references=(AWS_KEYS_REFERENCE,),
    ),
    SecretRule(
        rule_id="secret-aws-secret-key",
        title="AWS secret access key",
        severity=Severity.CRITICAL,
        pattern=_compile(
            r"(?i)\b(?:aws_secret_access_key|secret_access_key)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])[\"']?"
        ),
        references=(AWS_KEYS_REFERENCE,),
        value_group=1,
    ),
    SecretRule(
        rule_id="secret-github-token",
        title="GitHub token",
        severity=Severity.HIGH,
        pattern=_compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
        references=(GITHUB_REFERENCE,),
    ),
    SecretRule(
        rule_id="secret-slack-token",
        title="Slack token",
        severity=Severity.HIGH,
        pattern=_compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
        references=(SLACK_REFERENCE,),
    ),
    SecretRule(
        rule_id="secret-stripe-secret-key",
        title="Stripe live secret key",
        severity=Severity.CRITICAL,
        pattern=_compile(r"\bsk_live_[0-9A-Za-z]{10,}\b"),
        references=(STRIPE_REFERENCE,),
    ),
    SecretRule(
        rule_id="secret-google-api-key",
        title="Google API key",
        severity=Severity.HIGH,
        pattern=_compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        references=(GOOGLE_REFERENCE,),
    ),
    SecretRule(
        rule_id="secret-private-key",
        title="PEM private key",
        severity=Severity.CRITICAL,
        pattern=_compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        references=(PRIVATE_KEY_REFERENCE,),
    ),
    SecretRule(
        rule_id="secret-jwt",
        title="JSON Web Token",
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
        ),
        references=(JWT_REFERENCE,),
    ),
    SecretRule(
        rule_id=GENERIC_RULE_ID,
        title="Hardcoded secret",
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"(?i)\b[A-Za-z0-9_.-]*"
            r"(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|client_secret)"
            r"[A-Za-z0-9_.-]*\s*[:=]\s*"
            r"(?:\"(?P<double>[^\"\n]{12,})\"|'(?P<single>[^'\n]{12,})')"
        ),
        references=(CWE_REFERENCE,),
        value_group=-1,
    ),
)


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    counts = collections.Counter(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def mask_secret(value: str) -> str:
    """Mask a secret, keeping the first and last four characters visible."""
    if len(value) <= 8:
        return "\u2026"
    return f"{value[:4]}\u2026{value[-4:]}"


def _is_placeholder(value: str) -> bool:
    """True when the value is obviously a placeholder rather than a secret."""
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    stripped = value.strip()
    return bool(stripped) and len(set(stripped)) == 1


def _is_usable_secret(value: str, min_entropy: Optional[float] = None) -> bool:
    if len(value) < 8 or _is_placeholder(value):
        return False
    if min_entropy is not None and shannon_entropy(value) < min_entropy:
        return False
    return True


def _is_provider_token(value: str) -> bool:
    """True when a generic assignment already matches a provider-specific rule."""
    return any(
        rule.pattern.fullmatch(value)
        for rule in RULES
        if rule.rule_id != GENERIC_RULE_ID
    )


def _position(text: str, offset: int) -> Tuple[int, int]:
    """Convert an absolute offset to a 1-based ``(line, column)`` pair."""
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset - last_newline
    return line, column


def _generic_match(match: "re.Match[str]") -> Optional[Tuple[str, int, int, str]]:
    """Extract ``(key, start, end, value)`` from a generic assignment match."""
    group = "double" if match.group("double") is not None else "single"
    value = match.group(group)
    if value is None:
        return None
    start, end = match.span(group)
    key_match = re.match(r"[A-Za-z0-9_.-]+", match.group(0))
    key = key_match.group(0) if key_match else ""
    return key, start, end, value


def _iter_rule_matches(text: str) -> Iterator[Tuple[SecretRule, int, int, str]]:
    """Yield ``(rule, start, end, secret)`` for every reportable match."""
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            if rule.value_group < 0:
                parsed = _generic_match(match)
                if parsed is None:
                    continue
                key, start, end, value = parsed
                if "secret_access_key" in key.lower():
                    # Covered by the dedicated AWS rule.
                    continue
                if _is_provider_token(value):
                    continue
                if not _is_usable_secret(value, GENERIC_MIN_ENTROPY):
                    continue
            else:
                start, end = match.span(rule.value_group)
                if start < 0:
                    continue
                value = text[start:end]
                if not _is_usable_secret(value):
                    continue
            yield rule, start, end, value


def _make_finding(
    rule: SecretRule,
    relative: str,
    text: str,
    start: int,
    end: int,
    value: str,
) -> Finding:
    masked = mask_secret(value)
    start_line, start_col = _position(text, start)
    end_line, end_col = _position(text, end)
    metadata: Dict[str, object] = {
        "secret_masked": masked,
        "secret_length": len(value),
    }
    if rule.rule_id == GENERIC_RULE_ID:
        metadata["entropy"] = round(shannon_entropy(value), 2)
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        kind="sast",
        engine="argus-secrets",
        file=relative,
        start_line=start_line,
        start_col=start_col,
        end_line=end_line,
        end_col=end_col,
        message=f"{rule.title} detected: {masked} ({len(value)} characters).",
        cwe="CWE-798",
        confidence="high",
        references=list(rule.references),
        metadata=metadata,
    )


def scan_text(text: str, relative: str = "") -> List[Finding]:
    """Scan ``text`` and return findings located in ``relative``.

    Duplicate findings of the same rule on the same line are collapsed.
    """
    findings: List[Finding] = []
    seen: set[Tuple[str, int]] = set()
    for rule, start, end, value in _iter_rule_matches(text):
        start_line = text.count("\n", 0, start) + 1
        key = (rule.rule_id, start_line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_make_finding(rule, relative, text, start, end, value))
    return findings


def _matches_exclude(relative: str, excludes: Sequence[str]) -> bool:
    return any(token in relative for token in excludes if token)


def _read_text(path: str, max_file_bytes: int) -> Tuple[Optional[str], Optional[str], bool]:
    """Read a file.

    Returns ``(text, error, skipped)``.  ``skipped`` is true when the file is
    binary or too large; ``text`` is then ``None`` and ``error`` is ``None``.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, str(exc), False
    if size > max_file_bytes:
        return None, None, True
    try:
        with open(path, "rb") as handle:
            raw = handle.read(max_file_bytes + 1)
    except OSError as exc:
        return None, str(exc), False
    if len(raw) > max_file_bytes or b"\x00" in raw:
        return None, None, True
    try:
        return raw.decode("utf-8"), None, False
    except UnicodeDecodeError:
        return raw.decode("latin-1"), None, False


def scan_target(
    root: str,
    exclude: Sequence[str] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> Tuple[List[Finding], Dict[str, object], List[str]]:
    """Recursively scan ``root`` for hardcoded secrets.

    Returns ``(findings, stats, errors)``.  ``stats`` contains
    ``files_scanned`` (content read and scanned), ``files_skipped`` (binary,
    too large, excluded or unreadable), ``findings`` and ``rules`` (number of
    distinct rules that matched).

    Paths containing any substring from ``exclude`` are skipped.  Hidden VCS
    and dependency directories (:data:`SKIP_DIRECTORIES`) are always pruned.
    Files containing a NUL byte and files larger than ``max_file_bytes`` are
    skipped.
    """
    root_abs = os.path.abspath(root)
    findings: List[Finding] = []
    errors: List[str] = []
    files_scanned = 0
    files_skipped = 0

    if not os.path.isdir(root_abs):
        if not os.path.exists(root_abs):
            errors.append(f"{root}: no such directory")
        else:
            errors.append(f"{root}: not a directory")
        stats = _build_stats(files_scanned, files_skipped, findings)
        return findings, stats, errors

    for dirpath, dirnames, filenames in os.walk(root_abs):
        relative_dir = normalize_path(dirpath, root_abs)
        if relative_dir == ".":
            relative_dir = ""

        kept_dirs = []
        for name in sorted(dirnames):
            if name in SKIP_DIRECTORIES:
                continue
            child = f"{relative_dir}/{name}" if relative_dir else name
            if _matches_exclude(child, exclude):
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            relative = f"{relative_dir}/{name}" if relative_dir else name
            if _matches_exclude(relative, exclude):
                files_skipped += 1
                continue

            absolute = os.path.join(dirpath, name)
            text, error, skipped = _read_text(absolute, max_file_bytes)
            if skipped:
                files_skipped += 1
                continue
            if text is None:
                files_skipped += 1
                errors.append(f"{relative}: {error}")
                continue

            files_scanned += 1
            findings.extend(scan_text(text, relative))

    findings.sort(key=lambda item: (item.file, item.start_line, item.start_col, item.rule_id))
    stats = _build_stats(files_scanned, files_skipped, findings)
    return findings, stats, errors


def _build_stats(
    files_scanned: int,
    files_skipped: int,
    findings: Sequence[Finding],
) -> Dict[str, object]:
    return {
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "findings": len(findings),
        "rules": len({finding.rule_id for finding in findings}),
    }
