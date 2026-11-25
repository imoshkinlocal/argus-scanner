"""Lightweight infrastructure-as-code scanner.

The module walks a directory tree and applies a compact set of textual rules to
Dockerfiles, Kubernetes manifests and Terraform files. It deliberately avoids
third-party parsers so it can run in constrained and offline environments.

Rules aim at high-signal misconfigurations. The scanner is context aware only in
a minimal sense: comments are ignored and Terraform checks use the surrounding
resource/block whenever the resource type matters.
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .models import Finding, Severity

ENGINE = "argus-iac"
KIND = "sast"

#: Directory names that are never useful for IaC configuration scanning.
SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".terraform",
    }
)

Stats = Dict[str, object]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_target(
    root: str,
    exclude: Sequence[str] = (),
    max_file_bytes: int = 1_000_000,
) -> Tuple[List[Finding], Stats, List[str]]:
    """Scan ``root`` for IaC misconfigurations.

    Returns a tuple of ``(findings, stats, errors)``. ``errors`` contains
    human-readable messages for files that could not be read; those errors are
    non-fatal and never abort the walk. Files larger than ``max_file_bytes`` are
    skipped and counted in ``stats["files_skipped"]``.
    """
    root_abs = os.path.abspath(root)
    excludes = _prepare_excludes(exclude, root_abs)
    counters = {
        "files_scanned": 0,
        "files_skipped": 0,
        "files_excluded": 0,
        "directories_skipped": 0,
    }
    findings: List[Finding] = []
    errors: List[str] = []

    if os.path.isdir(root_abs):
        _walk(
            root_abs,
            root_abs,
            excludes,
            max_file_bytes,
            counters,
            findings,
            errors,
        )
    elif os.path.isfile(root_abs):
        name = os.path.basename(root_abs)
        if _is_excluded(name, name, excludes):
            counters["files_excluded"] += 1
        else:
            _scan_one(
                root_abs,
                name,
                name,
                max_file_bytes,
                counters,
                findings,
                errors,
            )
    else:
        errors.append(f"{root}: no such file or directory")

    stats: Stats = {"root": root_abs}
    stats.update(counters)
    return _finalize(findings, stats), stats, errors


# ---------------------------------------------------------------------------
# Tree walking and file IO
# ---------------------------------------------------------------------------


def _walk(
    current: str,
    root: str,
    excludes: Tuple[str, ...],
    max_file_bytes: int,
    counters: Dict[str, int],
    findings: List[Finding],
    errors: List[str],
) -> None:
    try:
        with os.scandir(current) as entries:
            items = sorted(entries, key=lambda entry: entry.name)
    except OSError as exc:
        errors.append(f"{_relative(current, root)}: {exc}")
        return

    directories: List[os.DirEntry[str]] = []
    files: List[os.DirEntry[str]] = []
    for entry in items:
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError as exc:
            errors.append(f"{_relative(entry.path, root)}: {exc}")
            continue
        (directories if is_dir else files).append(entry)

    for entry in directories:
        if entry.name in SKIP_DIRS or _is_excluded(
            _relative(entry.path, root), entry.name, excludes
        ):
            counters["directories_skipped"] += 1
            continue
        _walk(
            entry.path,
            root,
            excludes,
            max_file_bytes,
            counters,
            findings,
            errors,
        )

    for entry in files:
        relative = _relative(entry.path, root)
        if _is_excluded(relative, entry.name, excludes):
            counters["files_excluded"] += 1
            continue
        _scan_one(
            entry.path,
            relative,
            entry.name,
            max_file_bytes,
            counters,
            findings,
            errors,
        )


def _scan_one(
    path: str,
    relative: str,
    name: str,
    max_file_bytes: int,
    counters: Dict[str, int],
    findings: List[Finding],
    errors: List[str],
) -> None:
    if not _is_supported(name):
        return
    try:
        text = _read_text(path, max_file_bytes)
    except _FileTooLarge:
        counters["files_skipped"] += 1
        return
    except OSError as exc:
        errors.append(f"{relative}: {exc}")
        counters["files_skipped"] += 1
        return

    counters["files_scanned"] += 1
    findings.extend(_scan_text(relative, name, text))


class _FileTooLarge(Exception):
    """Internal marker for files above the configured size limit."""


def _read_text(path: str, max_file_bytes: int) -> str:
    size = os.path.getsize(path)
    if size > max_file_bytes:
        raise _FileTooLarge
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        # Read one extra character to catch a file growing between stat and read.
        text = handle.read(max_file_bytes + 1)
    if len(text) > max_file_bytes:
        raise _FileTooLarge
    return text


def _relative(path: str, root: str) -> str:
    try:
        relative = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except ValueError:
        relative = path
    return relative.replace(os.sep, "/")


def _prepare_excludes(exclude: Sequence[str], root: str) -> Tuple[str, ...]:
    prepared: List[str] = []
    for raw in exclude:
        text = str(raw).strip()
        if not text:
            continue
        if os.path.isabs(text):
            try:
                text = os.path.relpath(text, root)
            except ValueError:
                continue
        text = text.replace(os.sep, "/").strip("/")
        text = os.path.normpath(text).replace(os.sep, "/")
        if not text or text == "." or text.startswith("../"):
            continue
        prepared.append(text)
    return tuple(prepared)


def _is_excluded(relative: str, name: str, excludes: Sequence[str]) -> bool:
    for pattern in excludes:
        if relative == pattern or name == pattern or relative.startswith(pattern + "/"):
            return True
        if any(char in pattern for char in "*?["):
            if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern):
                return True
    return False


def _is_supported(name: str) -> bool:
    lower = name.lower()
    return (
        _is_dockerfile(lower)
        or lower.endswith(".tf")
        or lower.endswith(".yaml")
        or lower.endswith(".yml")
    )


def _is_dockerfile(lower_name: str) -> bool:
    return (
        lower_name in {"dockerfile", "containerfile"}
        or lower_name.endswith(".dockerfile")
        or lower_name.startswith("dockerfile.")
    )


def _scan_text(relative: str, name: str, text: str) -> List[Finding]:
    lower = name.lower()
    if _is_dockerfile(lower):
        return _scan_dockerfile(relative, text)
    if lower.endswith(".tf"):
        return _scan_terraform(relative, text)
    if lower.endswith((".yaml", ".yml")) and _looks_like_kubernetes(text):
        return _scan_kubernetes(relative, text)
    return []


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    file: str,
    line: int,
    message: str,
    confidence: str = "high",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        kind=KIND,
        engine=ENGINE,
        file=file,
        start_line=line,
        start_col=1,
        end_line=line,
        message=message,
        cwe=cwe,
        confidence=confidence,
    )


def _finalize(findings: List[Finding], stats: Stats) -> List[Finding]:
    unique: Dict[Tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.start_line)
        if key not in unique:
            unique[key] = finding
    ordered = sorted(
        unique.values(),
        key=lambda item: (item.file, item.start_line, item.rule_id),
    )

    by_severity = {level.value: 0 for level in Severity}
    by_rule: Dict[str, int] = {}
    for finding in ordered:
        by_severity[finding.severity.value] += 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    stats["findings"] = len(ordered)
    stats["by_severity"] = by_severity
    stats["by_rule"] = by_rule
    return ordered


# ---------------------------------------------------------------------------
# Dockerfile rules
# ---------------------------------------------------------------------------

_DOCKER_USER_RE = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE)
_DOCKER_ADD_REMOTE_RE = re.compile(r"^\s*ADD\s+.*https?://", re.IGNORECASE)
_DOCKER_RUN_RE = re.compile(r"^\s*RUN\s+(.*)$", re.IGNORECASE)
_DOCKER_ENV_RE = re.compile(r"^\s*(ENV|ARG)\s+(.+)$", re.IGNORECASE)
_DOCKER_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE
)

_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
    re.IGNORECASE,
)
_PROCESS_SUBSTITUTION_RE = re.compile(
    r"\b(?:ba|z|k)?sh\s+<\(\s*(?:curl|wget)\b", re.IGNORECASE
)
_PRIVILEGED_FLAG_RE = re.compile(r"(?:^|\s)--privileged(?=$|[\s=])")

_SECRET_NAME_RE = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|"
    r"CREDENTIALS?)(?![A-Z])",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*("([^"]*)"|'([^']*)'|(\S+))"""
)
_PLACEHOLDER_RE = re.compile(
    r"""
    (?:
        <[^>]*>
        | \$\{[^}]*\}
        | \$[A-Za-z_][A-Za-z0-9_]*
        | %[A-Za-z_][A-Za-z0-9_]*%
        | change[-_]?me
        | example
        | placeholder
        | your[-_].*
        | xxx+
        | todo
        | dummy
        | redacted
        | secret
        | test
        | null
        | none
        | \*+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _scan_dockerfile(relative: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    for line_no, logical in _docker_logical_lines(text.splitlines()):
        stripped = logical.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        user_match = _DOCKER_USER_RE.match(logical)
        if user_match:
            user = user_match.group(1).split(":", 1)[0].lower()
            if user in {"root", "0"}:
                findings.append(
                    _finding(
                        "iac-docker-root-user",
                        "Container runs as root",
                        Severity.MEDIUM,
                        "CWE-250",
                        relative,
                        line_no,
                        "User directive selects the root account; use an unprivileged user.",
                    )
                )

        if _DOCKER_ADD_REMOTE_RE.match(logical):
            findings.append(
                _finding(
                    "iac-docker-add-remote",
                    "Remote ADD instruction",
                    Severity.MEDIUM,
                    "CWE-494",
                    relative,
                    line_no,
                    "ADD downloads a remote resource without integrity verification; "
                    "prefer COPY or pin a checksum.",
                )
            )

        run_match = _DOCKER_RUN_RE.match(logical)
        if run_match:
            command = run_match.group(1)
            if _PIPE_TO_SHELL_RE.search(command) or _PROCESS_SUBSTITUTION_RE.search(command):
                findings.append(
                    _finding(
                        "iac-docker-curl-pipe-shell",
                        "Downloaded script piped to a shell",
                        Severity.HIGH,
                        "CWE-494",
                        relative,
                        line_no,
                        "RUN executes code downloaded at build time without integrity checks.",
                    )
                )
            if _PRIVILEGED_FLAG_RE.search(command):
                findings.append(
                    _finding(
                        "iac-docker-privileged",
                        "Privileged build step",
                        Severity.HIGH,
                        "CWE-250",
                        relative,
                        line_no,
                        "RUN uses --privileged, granting the build step full host capabilities.",
                    )
                )

        env_match = _DOCKER_ENV_RE.match(logical)
        if env_match:
            instruction = env_match.group(1).upper()
            secret_names = []
            for key, value in _env_assignments(env_match.group(2), instruction):
                if _SECRET_NAME_RE.search(key) and _is_secret_value(value):
                    if key not in secret_names:
                        secret_names.append(key)
            if secret_names:
                findings.append(
                    _finding(
                        "iac-docker-hardcoded-secret",
                        "Hardcoded credential in Dockerfile",
                        Severity.HIGH,
                        "CWE-798",
                        relative,
                        line_no,
                        "Secret-like value assigned in "
                        f"{instruction} variable(s): {', '.join(secret_names)}. "
                        "Pass secrets at runtime instead of baking them into the image.",
                        confidence="medium",
                    )
                )

        from_match = _DOCKER_FROM_RE.match(logical)
        if from_match:
            image = from_match.group(1)
            if "@" not in image:
                last_segment = image.rsplit("/", 1)[-1]
                if ":" in last_segment:
                    tag = last_segment.rsplit(":", 1)[1].lower()
                    if tag == "latest":
                        findings.append(
                            _finding(
                                "iac-docker-latest-tag",
                                "Base image uses the latest tag",
                                Severity.INFO,
                                "CWE-1104",
                                relative,
                                line_no,
                                "FROM uses the mutable 'latest' tag; pin a digest or version.",
                            )
                        )
    return findings


def _docker_logical_lines(lines: List[str]) -> Iterator[Tuple[int, str]]:
    buffer: List[str] = []
    start = 0
    for number, raw in enumerate(lines, 1):
        stripped = raw.rstrip()
        if not buffer:
            start = number
            if stripped.lstrip().startswith("#"):
                continue
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].strip())
            continue
        buffer.append(stripped.strip())
        joined = " ".join(part for part in buffer if part).strip()
        buffer = []
        if joined:
            yield start, joined
    if buffer:
        joined = " ".join(part for part in buffer if part).strip()
        if joined:
            yield start, joined


def _env_assignments(text: str, instruction: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for match in _ASSIGNMENT_RE.finditer(text):
        key = match.group(1)
        if match.group(3) is not None:
            value = match.group(3)
        elif match.group(4) is not None:
            value = match.group(4)
        else:
            value = match.group(5) or ""
        pairs.append((key, value))
    if not pairs and instruction == "ENV":
        parts = text.strip().split(None, 1)
        if parts and "=" not in parts[0]:
            pairs.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return pairs


def _is_secret_value(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    return _PLACEHOLDER_RE.fullmatch(text) is None


# ---------------------------------------------------------------------------
# Kubernetes rules
# ---------------------------------------------------------------------------

_K8S_API_RE = re.compile(r"^\s*apiVersion\s*:", re.MULTILINE)
_K8S_KIND_RE = re.compile(r"^\s*kind\s*:", re.MULTILINE)
_K8S_PRIVILEGED_RE = re.compile(r"^\s*privileged\s*:\s*true\s*$", re.IGNORECASE)
_K8S_HOST_NAMESPACE_RE = re.compile(
    r"^\s*(hostNetwork|hostPID|hostIPC)\s*:\s*true\s*$", re.IGNORECASE
)
_K8S_RUN_AS_USER_RE = re.compile(r"""^\s*runAsUser\s*:\s*["']?0["']?\s*$""")
_K8S_ALLOW_ESCALATION_RE = re.compile(
    r"^\s*allowPrivilegeEscalation\s*:\s*true\s*$", re.IGNORECASE
)
_K8S_READ_ONLY_FS_RE = re.compile(
    r"^\s*readOnlyRootFilesystem\s*:\s*false\s*$", re.IGNORECASE
)

_HOST_NAMESPACE_RULES = {
    "hostnetwork": ("iac-k8s-host-network", "Host network namespace enabled"),
    "hostpid": ("iac-k8s-host-pid", "Host PID namespace enabled"),
    "hostipc": ("iac-k8s-host-ipc", "Host IPC namespace enabled"),
}


def _looks_like_kubernetes(text: str) -> bool:
    return bool(_K8S_API_RE.search(text) and _K8S_KIND_RE.search(text))


def _scan_kubernetes(relative: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = _strip_yaml_comment(raw)
        if not line.strip():
            continue

        if _K8S_PRIVILEGED_RE.match(line):
            findings.append(
                _finding(
                    "iac-k8s-privileged",
                    "Privileged Kubernetes container",
                    Severity.HIGH,
                    "CWE-250",
                    relative,
                    line_no,
                    "securityContext sets privileged: true, granting all host capabilities.",
                )
            )

        host_match = _K8S_HOST_NAMESPACE_RE.match(line)
        if host_match:
            flag = host_match.group(1).lower()
            rule_id, title = _HOST_NAMESPACE_RULES[flag]
            findings.append(
                _finding(
                    rule_id,
                    title,
                    Severity.HIGH,
                    "CWE-250",
                    relative,
                    line_no,
                    f"{host_match.group(1)}: true shares a host namespace with the pod.",
                )
            )

        if _K8S_RUN_AS_USER_RE.match(line):
            findings.append(
                _finding(
                    "iac-k8s-run-as-root",
                    "Container runs as UID 0",
                    Severity.HIGH,
                    "CWE-250",
                    relative,
                    line_no,
                    "securityContext sets runAsUser: 0, running the container as root.",
                )
            )

        if _K8S_ALLOW_ESCALATION_RE.match(line):
            findings.append(
                _finding(
                    "iac-k8s-privilege-escalation",
                    "Privilege escalation allowed",
                    Severity.MEDIUM,
                    "CWE-250",
                    relative,
                    line_no,
                    "allowPrivilegeEscalation: true lets processes gain more privileges.",
                )
            )

        if _K8S_READ_ONLY_FS_RE.match(line):
            findings.append(
                _finding(
                    "iac-k8s-writable-root-fs",
                    "Writable root filesystem",
                    Severity.LOW,
                    "CWE-732",
                    relative,
                    line_no,
                    "readOnlyRootFilesystem: false leaves the container filesystem writable.",
                )
            )
    return findings


def _strip_yaml_comment(line: str) -> str:
    quote: Optional[str] = None
    for index, char in enumerate(line):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


# ---------------------------------------------------------------------------
# Terraform rules
# ---------------------------------------------------------------------------

_RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"')
_PUBLIC_ACL_RE = re.compile(r'^\s*acl\s*=\s*"(public-read|public-read-write)"\s*$')
_PUBLICLY_ACCESSIBLE_RE = re.compile(
    r"^\s*publicly_accessible\s*=\s*true\s*$", re.IGNORECASE
)
_ENCRYPTED_FALSE_RE = re.compile(
    r"^\s*(storage_encrypted|encrypted)\s*=\s*false\s*$", re.IGNORECASE
)
_INGRESS_START_RE = re.compile(r"^\s*ingress\s*=?\s*\{")
_ADMIN_PORTS_RE = re.compile(
    r"^\s*(?:from_port|to_port|port)\s*=\s*(\d+)", re.IGNORECASE | re.MULTILINE
)


def _scan_terraform(relative: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = [_strip_terraform_comment(line) for line in text.splitlines()]

    depth = 0
    resources: Dict[int, str] = {}
    pending_resource: Optional[str] = None

    for index, line in enumerate(lines):
        line_no = index + 1
        resource_match = _RESOURCE_RE.match(line)
        if resource_match:
            pending_resource = resource_match.group(1)

        current_resource: Optional[str] = None
        for level in range(depth, 0, -1):
            if level in resources:
                current_resource = resources[level]
                break

        acl_match = _PUBLIC_ACL_RE.match(line)
        if acl_match and (
            current_resource is None or "s3" in current_resource.lower()
        ):
            findings.append(
                _finding(
                    "iac-tf-public-s3",
                    "Publicly readable S3 bucket",
                    Severity.HIGH,
                    "CWE-732",
                    relative,
                    line_no,
                    f'S3 bucket ACL is set to "{acl_match.group(1)}".',
                )
            )

        if _PUBLICLY_ACCESSIBLE_RE.match(line):
            findings.append(
                _finding(
                    "iac-tf-publicly-accessible",
                    "Publicly accessible managed resource",
                    Severity.HIGH,
                    "CWE-732",
                    relative,
                    line_no,
                    "publicly_accessible = true exposes the resource to the internet.",
                )
            )

        encrypted_match = _ENCRYPTED_FALSE_RE.match(line)
        if encrypted_match:
            findings.append(
                _finding(
                    "iac-tf-unencrypted",
                    "Encryption disabled",
                    Severity.MEDIUM,
                    "CWE-311",
                    relative,
                    line_no,
                    f"{encrypted_match.group(1)} = false disables encryption at rest.",
                )
            )

        opens, closes = _brace_delta(line)
        for _ in range(opens):
            depth += 1
            if pending_resource is not None:
                resources[depth] = pending_resource
                pending_resource = None
        for _ in range(closes):
            resources.pop(depth, None)
            if depth > 0:
                depth -= 1

    for start_index, block in _ingress_blocks(lines):
        ports = {int(value) for value in _ADMIN_PORTS_RE.findall("\n".join(block))}
        admin_ports = sorted(ports & {22, 3389})
        if not admin_ports:
            continue
        for offset, block_line in enumerate(block):
            if '"0.0.0.0/0"' not in block_line:
                continue
            ports_text = ", ".join(str(port) for port in admin_ports)
            findings.append(
                _finding(
                    "iac-tf-open-admin-port",
                    "Administrative port exposed to the internet",
                    Severity.HIGH,
                    "CWE-284",
                    relative,
                    start_index + offset + 1,
                    f"Ingress allows 0.0.0.0/0 to administrative port(s) {ports_text}.",
                )
            )
            break
    return findings


def _strip_terraform_comment(line: str) -> str:
    quote: Optional[str] = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == "\\" and index + 1 < len(line):
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#":
            return line[:index]
        elif char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            return line[:index]
        index += 1
    return line


def _brace_delta(line: str) -> Tuple[int, int]:
    opens = 0
    closes = 0
    quote: Optional[str] = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == "\\" and index + 1 < len(line):
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "{":
            opens += 1
        elif char == "}":
            closes += 1
        index += 1
    return opens, closes


def _ingress_blocks(lines: List[str]) -> Iterator[Tuple[int, List[str]]]:
    index = 0
    while index < len(lines):
        if not _INGRESS_START_RE.match(lines[index]):
            index += 1
            continue
        start = index
        depth = 0
        block: List[str] = []
        while index < len(lines):
            block.append(lines[index])
            opens, closes = _brace_delta(lines[index])
            depth += opens - closes
            if depth <= 0:
                break
            index += 1
        yield start, block
        index += 1
