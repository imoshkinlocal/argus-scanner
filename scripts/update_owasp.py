#!/usr/bin/env python3
"""Regenerate the bundled OWASP Top 10 -> CWE mapping.

The shipped catalog is ``argus/owasp_top10.json``.  This script rebuilds it
from the official OWASP Top 10 repository, so a new edition can be added
without hand-editing hundreds of CWE numbers::

    python scripts/update_owasp.py

By default the script downloads the Markdown sources from GitHub.  Pass
``--repo-dir`` to read a local OWASP/Top10 checkout instead, which also works
offline::

    python scripts/update_owasp.py --repo-dir /path/to/OWASP-Top10

The official 2021 and 2025 pages contain a "List of Mapped CWEs" section.  The
2017 document only lists representative CWEs in each category's "External"
references, and its A09 page has no CWE list at all; for A09 we reuse the three
successor CWEs from the 2021 A06 list (937, 1035, 1104).

Exit codes: 0 written/unchanged, 1 ``--check`` found a difference, 2 error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

DEFAULT_REF = "master"
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "argus", "owasp_top10.json",
)
SOURCE = "https://github.com/OWASP/Top10"

#: Russian names for every category.  Kept here so regeneration is offline.
RU_NAMES: Dict[str, str] = {
    # 2017
    "2017/A1": "Инъекции",
    "2017/A2": "Нарушение аутентификации",
    "2017/A3": "Раскрытие конфиденциальных данных",
    "2017/A4": "Внешние XML-сущности (XXE)",
    "2017/A5": "Нарушение контроля доступа",
    "2017/A6": "Неверная конфигурация безопасности",
    "2017/A7": "Межсайтовый скриптинг (XSS)",
    "2017/A8": "Небезопасная десериализация",
    "2017/A9": "Использование компонентов с известными уязвимостями",
    "2017/A10": "Недостаточное журналирование и мониторинг",
    # 2021
    "2021/A01": "Нарушение контроля доступа",
    "2021/A02": "Криптографические сбои",
    "2021/A03": "Инъекции",
    "2021/A04": "Небезопасный дизайн",
    "2021/A05": "Неверная конфигурация безопасности",
    "2021/A06": "Уязвимые и устаревшие компоненты",
    "2021/A07": "Сбои идентификации и аутентификации",
    "2021/A08": "Сбои целостности программного обеспечения и данных",
    "2021/A09": "Сбои журналирования и мониторинга безопасности",
    "2021/A10": "Подделка запросов на стороне сервера (SSRF)",
    # 2025
    "2025/A01": "Нарушение контроля доступа",
    "2025/A02": "Неверная конфигурация безопасности",
    "2025/A03": "Сбои цепочки поставок программного обеспечения",
    "2025/A04": "Криптографические сбои",
    "2025/A05": "Инъекции",
    "2025/A06": "Небезопасный дизайн",
    "2025/A07": "Сбои аутентификации",
    "2025/A08": "Сбои целостности программного обеспечения или данных",
    "2025/A09": "Сбои журналирования и оповещения безопасности",
    "2025/A10": "Неправильная обработка исключительных ситуаций",
}

#: 2017 files and their category ids.  The URLs are the canonical owasp.org
#: pages; A10 uses the double-encoded ampersand used by that site.
CATEGORIES_2017: Tuple[Tuple[str, str, str], ...] = (
    ("0xa1-injection.md", "A1", "A1_2017-Injection.html"),
    ("0xa2-broken-authentication.md", "A2", "A2_2017-Broken_Authentication.html"),
    ("0xa3-sensitive-data-disclosure.md", "A3", "A3_2017-Sensitive_Data_Exposure.html"),
    ("0xa4-xxe.md", "A4", "A4_2017-XML_External_Entities_(XXE).html"),
    ("0xa5-broken-access-control.md", "A5", "A5_2017-Broken_Access_Control.html"),
    ("0xa6-security-misconfiguration.md", "A6", "A6_2017-Security_Misconfiguration.html"),
    ("0xa7-xss.md", "A7", "A7_2017-Cross-Site_Scripting_(XSS).html"),
    ("0xa8-insecure-deserialization.md", "A8", "A8_2017-Insecure_Deserialization.html"),
    ("0xa9-known-vulns.md", "A9",
     "A9_2017-Using_Components_with_Known_Vulnerabilities.html"),
    ("0xaa-logging-detection-response.md", "A10",
     "A10_2017-Insufficient_Logging%2526Monitoring.html"),
)

#: The 2017 A09 page does not list CWEs; these are the successors of the
#: category from the official 2021 A06 list.
CWES_2017_A9 = (937, 1035, 1104)

_CWE_RE = re.compile(r"CWE-(\d+)")
_TITLE_RE = re.compile(r"^#\s+(.+)$", re.MULTILINE)
_CATEGORY_RE = re.compile(r"^A(\d\d)_", re.MULTILINE)


class UpdateError(RuntimeError):
    """Raised when the sources cannot be read or parsed."""


def _fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "argus-owasp-updater"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8")
    except OSError as exc:
        raise UpdateError(f"cannot download {url}: {exc}") from exc


def _list_remote(year: str, ref: str) -> List[Tuple[str, str]]:
    """Return ``(name, download_url)`` for the English pages of one edition."""
    api = f"https://api.github.com/repos/OWASP/Top10/contents/{year}/docs/en?ref={ref}"
    try:
        entries = json.loads(_fetch(api))
    except json.JSONDecodeError as exc:
        raise UpdateError(f"cannot parse the GitHub response for {year}: {exc}") from exc
    if not isinstance(entries, list):
        raise UpdateError(f"unexpected GitHub response for {year}: {entries!r}")
    return [(item["name"], item["download_url"])
            for item in entries if item.get("type") == "file"]


def _read_remote(url: str) -> str:
    return _fetch(url)


def _list_local(directory: str) -> List[Tuple[str, str]]:
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        raise UpdateError(f"cannot read {directory}: {exc}") from exc
    return [(name, os.path.join(directory, name))
            for name in names if os.path.isfile(os.path.join(directory, name))]


def _read_local(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise UpdateError(f"cannot read {path}: {exc}") from exc


def _cwe_list(body: str) -> List[int]:
    return sorted({int(value) for value in _CWE_RE.findall(body)})


def _parse_mapped_section(text: str) -> List[int]:
    marker = "## List of Mapped CWEs"
    if marker not in text:
        raise UpdateError("page has no 'List of Mapped CWEs' section")
    body = text.split(marker, 1)[1].split("\n## ", 1)[0]
    return _cwe_list(body)


def _parse_external_section(text: str) -> List[int]:
    parts = re.split(r"^###\s+External\s*$", text, flags=re.MULTILINE)
    if len(parts) < 2:
        return []
    return _cwe_list(parts[-1].split("\n## ", 1)[0])


def _title(text: str, fallback: str) -> str:
    match = _TITLE_RE.search(text)
    if not match:
        return fallback
    title = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", match.group(1))
    title = re.sub(r"\{:[^}]*\}", "", title)
    return " ".join(title.split())


def _category(year: str, category_id: str, title: str, url: str,
              cwes: Iterable[int]) -> Dict[str, object]:
    name = re.sub(r"^A\d+:\d{4}\s*[-–—]?\s*", "", title).strip()
    return {
        "id": category_id,
        "name": name,
        "name_ru": RU_NAMES.get(f"{year}/{category_id}", ""),
        "url": url,
        "cwes": sorted({int(value) for value in cwes}),
    }


def collect(year: str, repo_dir: Optional[str], ref: str) -> List[Dict[str, object]]:
    """Collect the categories and their CWEs for one Top 10 edition."""
    categories: List[Dict[str, object]] = []
    if year == "2017":
        base = os.path.join(repo_dir, "2017", "en") if repo_dir else None
        for filename, category_id, slug in CATEGORIES_2017:
            if base:
                text = _read_local(os.path.join(base, filename))
            else:
                text = _read_remote(
                    f"https://raw.githubusercontent.com/OWASP/Top10/{ref}/2017/en/{filename}")
            title = _title(text, f"{category_id}:2017")
            cwes = _parse_external_section(text)
            if category_id == "A9" and not cwes:
                cwes = list(CWES_2017_A9)
            url = f"https://owasp.org/www-project-top-ten/2017/{slug}"
            categories.append(_category(year, category_id, title, url, cwes))
        return categories

    if repo_dir:
        directory = os.path.join(repo_dir, year, "docs", "en")
        entries = _list_local(directory)
        reader = _read_local
    else:
        entries = _list_remote(year, ref)
        reader = _read_remote

    for name, location in entries:
        match = _CATEGORY_RE.match(name)
        if not match or name.startswith(("A00", "A11")):
            continue
        text = reader(location)
        title = _title(text, name[:-3])
        cwes = _parse_mapped_section(text)
        slug = name[:-3]
        url = f"https://owasp.org/Top10/{slug}/" if year == "2021" \
            else f"https://owasp.org/Top10/{year}/{slug}/"
        categories.append(_category(year, f"A{match.group(1)}", title, url, cwes))
    categories.sort(key=lambda item: str(item["id"]))
    return categories


def build(repo_dir: Optional[str], ref: str) -> Dict[str, object]:
    versions: Dict[str, object] = {}
    for year in ("2017", "2021", "2025"):
        categories = collect(year, repo_dir, ref)
        if len(categories) != 10:
            raise UpdateError(f"expected 10 categories for {year}, got {len(categories)}")
        versions[year] = {
            "source": (f"https://github.com/OWASP/Top10/tree/{ref}/{year}"
                       if not repo_dir else SOURCE),
            "categories": categories,
        }
    return {
        "schema": 1,
        "source": SOURCE,
        "default": "2021",
        "versions": versions,
    }


def dumps(document: Dict[str, object]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="destination JSON file (default: argus/owasp_top10.json)")
    parser.add_argument("--repo-dir", help="local OWASP/Top10 checkout to read instead of GitHub")
    parser.add_argument("--ref", default=DEFAULT_REF, help="Git ref to download (default: master)")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the file on disk differs from the generated data")
    args = parser.parse_args(argv)
    try:
        document = build(args.repo_dir, args.ref)
    except UpdateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = dumps(document)
    if args.check:
        try:
            with open(args.output, encoding="utf-8") as handle:
                current = handle.read()
        except OSError as exc:
            print(f"error: cannot read {args.output}: {exc}", file=sys.stderr)
            return 2
        if current != payload:
            print(f"{args.output} is out of date", file=sys.stderr)
            return 1
        print(f"{args.output} is up to date")
        return 0
    directory = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(directory, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(payload)
    counts = ", ".join(f"{year}: {len(data['categories'])}"  # type: ignore[index]
                       for year, data in document["versions"].items())  # type: ignore[union-attr]
    print(f"wrote {args.output} ({counts})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
