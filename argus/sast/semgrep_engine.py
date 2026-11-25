"""Thin, dependency-free wrapper around the Semgrep CLI.

Semgrep is used as the multi-language SAST backend: the ``argus`` CLI ships a
curated rule pack (``argus/sast/rules/<language>``) and turns Semgrep's JSON
output into :class:`~argus.models.Finding` objects.  Semgrep is *not* vendored;
the wrapper locates an existing binary (``semgrep`` on ``PATH``, the package
virtualenv, or ``$ARGUS_SEMGREP``) and reports a clear error when it is missing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from ..models import Finding, ScanError, Severity, normalize_path, parse_severity

#: Languages covered by the bundled Semgrep rule packs.
SEMGREP_LANGUAGES = ("java", "python", "javascript", "typescript", "go", "php", "c", "cpp", "ruby")

#: File extensions handled by each Semgrep rule pack.
LANGUAGE_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "java": (".java",),
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "go": (".go",),
    "php": (".php", ".phtml"),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
    "ruby": (".rb", ".rake", ".gemspec", ".erb"),
}

#: Languages that share a rule pack with another language.  The JavaScript pack
#: declares ``languages: [javascript, typescript]``, so a TypeScript-only tree
#: must load the ``javascript`` directory instead of a non-existent one.
RULE_DIR_ALIASES: Dict[str, str] = {"typescript": "javascript"}

#: Semgrep severity names mapped onto the shared severity ladder.
_SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "inventory": Severity.INFO,
    "experiment": Severity.LOW,
}


class SemgrepError(RuntimeError):
    """Raised when Semgrep cannot be located or fails to run."""


def bundle_root() -> str:
    """Directory holding the bundled rule packs."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def find_semgrep(explicit: Optional[str] = None) -> Optional[str]:
    """Locate a Semgrep executable without assuming a particular install mode."""
    candidates: List[str] = []
    if explicit:
        candidates.append(explicit)
    env_path = os.environ.get("ARGUS_SEMGREP")
    if env_path:
        candidates.append(env_path)
    # ``sys.executable`` may live inside a virtualenv that has semgrep installed.
    bin_dir = os.path.dirname(os.path.abspath(sys.executable))
    candidates.extend([
        os.path.join(bin_dir, "semgrep"),
        os.path.join(bin_dir, "semgrep.exe"),
    ])
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("semgrep")


def _normalise_cwe(value: object) -> str:
    """``"CWE-79: Cross-site scripting"`` -> ``"CWE-79"``."""
    if isinstance(value, (list, tuple)):
        return _normalise_cwe(value[0]) if value else ""
    if not isinstance(value, str):
        return ""
    token = value.strip().split(":", 1)[0].strip().replace(" ", "")
    token = token.upper()
    if token.startswith("CWE") and "-" not in token:
        token = token.replace("CWE", "CWE-")
    return token if token.startswith("CWE-") else ""


def _first_line(text: str, limit: int = 120) -> str:
    line = text.strip().split("\n", 1)[0].strip()
    return line[:limit] if len(line) > limit else line


def finding_from_result(result: dict, root: str, rule_meta: Optional[dict] = None) -> Finding:
    """Convert one Semgrep JSON result into a :class:`Finding`."""
    extra = result.get("extra") or {}
    metadata = dict(extra.get("metadata") or {})
    if rule_meta:
        for key, value in rule_meta.items():
            metadata.setdefault(key, value)
    message = str(extra.get("message") or metadata.get("message") or "").strip()
    severity = _SEVERITY_MAP.get(str(extra.get("severity", "")).lower())
    if severity is None:
        severity = parse_severity(extra.get("severity"))
    start = result.get("start") or {}
    end = result.get("end") or {}
    path = str(result.get("path") or "")
    references = metadata.get("references") or []
    if isinstance(references, str):
        references = [references]
    cwe = _normalise_cwe(metadata.get("cwe") or metadata.get("owasp"))
    return Finding(
        rule_id=str(result.get("check_id") or "semgrep"),
        title=_first_line(message) or "Semgrep finding",
        severity=severity,
        kind="sast",
        engine="semgrep",
        file=normalize_path(path, root),
        start_line=int(start.get("line") or 0),
        start_col=int(start.get("col") or 0),
        end_line=int(end.get("line") or 0),
        end_col=int(end.get("col") or 0),
        message=message,
        description=str(metadata.get("description") or ""),
        cwe=cwe,
        confidence=str(metadata.get("confidence") or "medium").lower(),
        references=[str(ref) for ref in references],
        metadata={
            key: value
            for key, value in metadata.items()
            if key in ("category", "technology", "subcategory", "likelihood", "impact", "source", "shortDescription")
        },
    )


def _load_rule_metadata(rules: Optional[str]) -> Dict[str, dict]:
    """Best-effort map of rule id -> metadata for lookups Semgrep may omit."""
    meta: Dict[str, dict] = {}
    if not rules or not os.path.isdir(rules):
        return meta
    for dirpath, _dirnames, filenames in os.walk(rules):
        for filename in filenames:
            if not filename.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
            except OSError:
                continue
            # The rule files are small and regular; parse ids/metadata with a
            # shallow scan instead of pulling in a YAML dependency.
            current: Optional[dict] = None
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("- id:"):
                    current = {"id": stripped.split(":", 1)[1].strip()}
                    meta[current["id"]] = current
                elif current is not None and stripped.startswith("cwe:"):
                    current["cwe"] = stripped.split(":", 1)[1].strip().strip("'\"")
    return meta


def run_semgrep(targets: Union[str, Sequence[str]], rules: Union[str, Sequence[str], None] = None,
                jobs: int = 1, binary: Optional[str] = None, verbose: bool = False,
                extra_args: Sequence[str] = (), root: Optional[str] = None,
                timeout: float = 900.0) -> Tuple[List[Finding], List[ScanError]]:
    """Run Semgrep over one or more paths and return findings plus non-fatal errors.

    ``targets`` may be a directory or an explicit list of files.  Passing the
    caller's already filtered file list keeps Semgrep out of directories the
    caller excluded (``vendor``, ``.pc``, ...); ``root`` controls how reported
    paths are made relative.
    """
    executable = binary or find_semgrep()
    if not executable:
        raise SemgrepError(
            "semgrep executable not found; install it (pip install semgrep) "
            "or point $ARGUS_SEMGREP at the binary"
        )
    if isinstance(targets, str):
        paths = [targets]
    else:
        paths = [str(item) for item in targets]
    if not paths:
        raise SemgrepError("no files to scan")
    for path in paths:
        if not os.path.exists(path):
            raise SemgrepError(f"target does not exist: {path}")
    if rules is None:
        configs: List[str] = [bundle_root()]
    elif isinstance(rules, str):
        configs = [rules]
    else:
        configs = [str(item) for item in rules]
    if not configs:
        configs = [bundle_root()]
    for config in configs:
        if not os.path.exists(config):
            raise SemgrepError(f"semgrep rule path does not exist: {config}")
    absolute_paths = [os.path.abspath(path) for path in paths]
    if root:
        scan_root = os.path.abspath(root)
    elif len(absolute_paths) == 1 and os.path.isdir(absolute_paths[0]):
        scan_root = absolute_paths[0]
    else:
        scan_root = os.path.dirname(absolute_paths[0])
    command = [
        executable, "scan",
        "--json",
        "--no-git-ignore",
        "--metrics=off",
        "--disable-version-check",
        "--timeout=60",
        "--max-target-bytes=2000000",
    ]
    for config in configs:
        command.extend(["--config", config])
    command.extend(absolute_paths)
    if jobs and jobs > 1:
        command.append(f"--jobs={int(jobs)}")
    command.extend(extra_args)

    if verbose:
        print(f"[semgrep] {' '.join(command)}", file=sys.stderr)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise SemgrepError(f"failed to execute semgrep: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SemgrepError(f"semgrep timed out after {timeout:.0f}s") from exc

    errors: List[ScanError] = []
    payload = _load_payload(completed.stdout)
    if payload is None:
        detail = (completed.stderr or completed.stdout).strip()[:800]
        raise SemgrepError(f"semgrep produced no JSON output (exit {completed.returncode}): {detail}")

    for error in payload.get("errors") or []:
        message = str(error.get("message") or error.get("type") or "semgrep error")
        if "partial parsing" in message.lower():
            continue
        errors.append(ScanError(scanner="semgrep", message=message[:400],
                                file=str(error.get("path") or "")))

    metadata: Dict[str, dict] = {}
    for config in configs:
        metadata.update(_load_rule_metadata(config))
    findings: List[Finding] = []
    for result in payload.get("results") or []:
        rule_id = str(result.get("check_id") or "")
        meta = metadata.get(rule_id)
        if meta is None:
            # Semgrep namespaces ids with the config path; keep our short id.
            short = rule_id.rsplit(".", 1)[-1]
            if short in metadata:
                rule_id, meta = short, metadata[short]
                result = {**result, "check_id": rule_id}
        try:
            findings.append(finding_from_result(result, scan_root, meta))
        except Exception as exc:  # noqa: BLE001 - never fail the whole scan
            errors.append(ScanError(scanner="semgrep", message=f"bad result: {exc}",
                                    file=str(result.get("path") or "")))
    if verbose:
        print(f"[semgrep] {len(findings)} findings, {len(errors)} errors", file=sys.stderr)
    return findings, errors


def _load_payload(stdout: str) -> Optional[dict]:
    """Parse Semgrep's JSON, tolerating leading log lines."""
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass
    start = stdout.find("{")
    while start != -1:
        try:
            return json.loads(stdout[start:])
        except json.JSONDecodeError:
            start = stdout.find("{", start + 1)
    return None


def languages_for_paths(paths: Iterable[str]) -> List[str]:
    """Languages whose rule packs should run for the given files."""
    found = set()
    for path in paths:
        extension = os.path.splitext(path)[1].lower()
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if extension in extensions:
                found.add(language)
    return sorted(found)


def rule_dirs(languages: Iterable[str], root: Optional[str] = None) -> List[str]:
    """Existing rule directories for ``languages`` (deduplicated, stable order)."""
    base = root or bundle_root()
    directories: List[str] = []
    for language in languages:
        directory = RULE_DIR_ALIASES.get(language, language)
        candidate = os.path.join(base, directory)
        if os.path.isdir(candidate) and candidate not in directories:
            directories.append(candidate)
    return directories


def list_rules(root: Optional[str] = None) -> List[dict]:
    """Enumerate bundled rules (id, language, severity, cwe, file)."""
    base = root or bundle_root()
    rules: List[dict] = []
    for language in SEMGREP_LANGUAGES:
        if language in RULE_DIR_ALIASES:
            continue  # reported through the pack that owns the rules
        directory = os.path.join(base, language)
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(directory, filename)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            current: Optional[dict] = None
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("- id:"):
                    current = {"id": stripped.split(":", 1)[1].strip(), "language": language,
                               "file": os.path.join(language, filename)}
                    rules.append(current)
                elif current is not None:
                    for key in ("severity", "cwe"):
                        if stripped.startswith(key + ":"):
                            current[key] = stripped.split(":", 1)[1].strip().strip("'\"")
    return rules


def write_temp_config(rules: str, destination: Optional[str] = None) -> str:
    """Materialise a single Semgrep config path (used by tests and CI)."""
    if destination:
        shutil.copytree(rules, destination, dirs_exist_ok=True)
        return destination
    temp = tempfile.mkdtemp(prefix="argus-semgrep-")
    shutil.copytree(rules, temp, dirs_exist_ok=True)
    return temp
