"""Unified SAST entry point.

Dispatch policy:

* Java goes to the built-in tree-sitter taint engine (:mod:`argus.sast.java`),
  which reasons about intra-file dataflow and is what the OWASP Benchmark
  results in ``benchmark_results/`` were produced with.
* Everything else goes to Semgrep with the bundled rule packs.
* ``engine="semgrep"`` forces Semgrep for Java too, which is useful for
  comparing rule-based and dataflow-based detection.
"""

from __future__ import annotations

import concurrent.futures
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import Finding, ScanError, ScanResult, Severity, filter_findings, normalize_path
from . import semgrep_engine

#: Extensions handled by the built-in Java engine.
JAVA_EXTENSIONS = (".java",)

#: Above this many files Semgrep is pointed at the directory instead of an
#: explicit file list (command line length limits).  Directory mode cannot apply
#: argus' own excludes, so Semgrep's ignore rules take over.
MAX_SEMGREP_TARGETS = 4000

#: Directories never scanned.
DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv",
    "__pycache__", "target", "build", "dist", "out", ".gradle", ".idea", ".mypy_cache",
    ".pytest_cache", "vendor", ".pc",
)

#: Extensions for which a language is assumed; used for "--language" filtering.
EXTENSION_LANGUAGE = {
    ".java": "java", ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".php": "php", ".phtml": "php", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby", ".erb": "ruby",
}


@dataclass
class SastOptions:
    engine: str = "auto"  # auto | java | semgrep
    jobs: int = 1
    min_severity: Severity = Severity.UNKNOWN
    languages: Sequence[str] = ()
    exclude: Sequence[str] = ()
    rules_dir: Optional[str] = None
    properties: Optional[Dict[str, str]] = None
    max_file_bytes: int = 2_000_000
    verbose: bool = False
    secrets: bool = True
    iac: bool = True
    secrets_max_file_bytes: int = 512_000
    iac_max_file_bytes: int = 1_000_000
    cache: bool = True
    cache_dir: Optional[str] = None


def _should_skip(relative: str, excludes: Iterable[str]) -> bool:
    parts = relative.replace(os.sep, "/").split("/")
    for exclude in excludes:
        if not exclude:
            continue
        if exclude in parts or relative.startswith(exclude) or exclude in relative:
            return True
    return False


def discover_files(target: str, options: SastOptions) -> List[Tuple[str, str]]:
    """Return ``(absolute path, relative path)`` for every scannable file."""
    if os.path.isfile(target):
        return [(os.path.abspath(target), os.path.basename(target))]
    excludes = tuple(dict.fromkeys((*DEFAULT_EXCLUDES, *options.exclude)))
    wanted = {language.lower() for language in options.languages}
    found: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for filename in sorted(filenames):
            absolute = os.path.join(dirpath, filename)
            relative = os.path.relpath(absolute, target).replace(os.sep, "/")
            if _should_skip(relative, excludes):
                continue
            language = EXTENSION_LANGUAGE.get(os.path.splitext(filename)[1].lower())
            if language is None:
                continue
            if wanted and language not in wanted:
                continue
            try:
                if os.path.getsize(absolute) > options.max_file_bytes:
                    continue
            except OSError:
                continue
            found.append((absolute, relative))
    return found


def _analyse_java(payload: Tuple[str, str, Optional[Dict[str, str]], Optional[bytes]]) \
        -> Tuple[str, List[Finding], Optional[str]]:
    """Worker for the Java engine (module level so it can be pickled)."""
    absolute, root, properties, source = payload
    from .java import analyze_file

    try:
        findings = analyze_file(absolute, root, source=source, properties=properties)
        return absolute, findings, None
    except Exception as exc:  # noqa: BLE001 - one broken file must not abort the scan
        return absolute, [], f"{type(exc).__name__}: {exc}"


def scan_target(target: str, options: Optional[SastOptions] = None) -> ScanResult:
    """Run the configured SAST engine(s) over ``target``."""
    options = options or SastOptions()
    target = os.path.abspath(target)
    if not os.path.exists(target):
        raise FileNotFoundError(f"target does not exist: {target}")
    root = target if os.path.isdir(target) else os.path.dirname(target) or "."
    result = ScanResult(target=root)

    files = discover_files(target, options)
    java_files = [item for item in files if item[0].endswith(JAVA_EXTENSIONS)]
    other_files = [item for item in files if not item[0].endswith(JAVA_EXTENSIONS)]

    use_java_engine = options.engine in ("auto", "java")
    use_semgrep = options.engine in ("auto", "semgrep")
    if options.engine == "java":
        use_semgrep = False

    findings: List[Finding] = []

    # ---- built-in Java engine
    cache = None
    if use_java_engine and java_files:
        from .java import load_properties

        properties = options.properties if options.properties is not None else load_properties(root)
        if options.cache:
            from .cache import SastCache

            try:
                cache = SastCache(options.cache_dir, enabled=True,
                                  verbose=options.verbose)
            except Exception:  # noqa: BLE001 - a broken cache must not block a scan
                cache = None
        outputs: List[Tuple[str, List[Finding], Optional[str]]] = []
        payloads: List[Tuple[str, str, Optional[Dict[str, str]], Optional[bytes]]] = []
        pending_keys: List[str] = []
        for absolute, relative in java_files:
            try:
                with open(absolute, "rb") as handle:
                    source = handle.read()
            except OSError:
                source = None
            key = ""
            if cache is not None and source is not None:
                from .cache import cache_key

                key = cache_key(relative, source, properties=properties)
                cached = cache.get(key)
                if cached is not None:
                    outputs.append((absolute, cached, None))
                    continue
            payloads.append((absolute, root, properties, source))
            pending_keys.append(key)
        if payloads:
            if options.jobs > 1 and len(payloads) > 8:
                with concurrent.futures.ProcessPoolExecutor(max_workers=options.jobs) as pool:
                    fresh = list(pool.map(_analyse_java, payloads, chunksize=16))
            else:
                fresh = [_analyse_java(payload) for payload in payloads]
            for index, (absolute, file_findings, error) in enumerate(fresh):
                outputs.append((absolute, file_findings, error))
                key = pending_keys[index]
                if cache is not None and key and error is None:
                    cache.put(key, file_findings)
        for absolute, file_findings, error in outputs:
            findings.extend(file_findings)
            if error:
                result.errors.append(ScanError(scanner="argus-java",
                                               message=error,
                                               file=normalize_path(absolute, root)))
        result.engines.append("argus-java")
        if cache is not None:
            result.stats["sast_cache"] = cache.stats()
            cache.close()

    # ---- Semgrep for everything else (and for Java when forced)
    semgrep_files = other_files + (java_files if (use_semgrep and not use_java_engine) else [])
    if use_semgrep and semgrep_files:
        languages = semgrep_engine.languages_for_paths(path for _absolute, path in semgrep_files)
        directories = semgrep_engine.rule_dirs(languages, options.rules_dir)
        if not directories:
            result.errors.append(ScanError(
                scanner="semgrep",
                message=f"no bundled rules for languages: {', '.join(languages) or 'none'}",
            ))
        else:
            try:
                paths = [absolute for absolute, _relative in semgrep_files]
                if len(paths) > MAX_SEMGREP_TARGETS:
                    paths = [target]
                file_findings, errors = semgrep_engine.run_semgrep(
                    paths, directories, jobs=options.jobs, verbose=options.verbose,
                    root=root,
                )
            except semgrep_engine.SemgrepError as exc:
                result.errors.append(ScanError(scanner="semgrep", message=str(exc)))
            else:
                findings.extend(file_findings)
                result.errors.extend(errors)
                result.engines.append("semgrep")

    # ---- secrets and infrastructure-as-code heuristics
    if options.secrets:
        from .. import secrets as secrets_scanner

        secret_findings, secret_stats, secret_errors = secrets_scanner.scan_target(
            root, exclude=options.exclude,
            max_file_bytes=options.secrets_max_file_bytes)
        findings.extend(secret_findings)
        result.stats["secrets"] = secret_stats
        for message in secret_errors:
            result.errors.append(ScanError(scanner="argus-secrets", message=message))
        if secret_findings:
            result.engines.append("argus-secrets")

    if options.iac:
        from .. import iac as iac_scanner

        iac_findings, iac_stats, iac_errors = iac_scanner.scan_target(
            root, exclude=options.exclude,
            max_file_bytes=options.iac_max_file_bytes)
        findings.extend(iac_findings)
        result.stats["iac"] = iac_stats
        for message in iac_errors:
            result.errors.append(ScanError(scanner="argus-iac", message=message))
        if iac_findings:
            result.engines.append("argus-iac")

    result.findings = filter_findings(findings, options.min_severity)
    result.sort()
    result.stats.update({
        "files_total": len(files),
        "files_java": len(java_files),
        "files_other": len(other_files),
        "engine": options.engine,
    })
    return result
