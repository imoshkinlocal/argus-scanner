"""Offline CWE reference: parsing, lookup, search and CLI output."""

from __future__ import annotations

import json
import re
from pathlib import Path

from argus import cwe
from argus.cli import EXIT_ERROR, EXIT_OK, main


def test_normalize_cwe_accepts_common_shapes():
    assert cwe.normalize_cwe("CWE-79") == 79
    assert cwe.normalize_cwe("cwe/89") == 89
    assert cwe.normalize_cwe("CWE-079: Cross-site Scripting") == 79
    assert cwe.normalize_cwe("134") == 134
    assert cwe.normalize_cwe(502) == 502
    assert cwe.normalize_cwe("") is None
    assert cwe.normalize_cwe("nope") is None
    assert cwe.normalize_cwe("-1") is None
    assert cwe.normalize_cwe(0) is None
    assert cwe.format_cwe("cwe-22") == "CWE-22"


def test_catalog_lookup_exposes_description_and_mitre_link():
    entry = cwe.lookup("CWE-89")
    assert entry is not None
    assert entry.known is True
    assert entry.cwe_id == "CWE-89"
    assert "SQL" in entry.name_ru
    assert entry.description
    assert entry.mitigations
    assert entry.url == "https://cwe.mitre.org/data/definitions/89.html"


def test_unknown_cwe_falls_back_to_mitre_stub():
    entry = cwe.lookup("CWE-99999")
    assert entry is not None
    assert entry.known is False
    assert entry.cwe_id == "CWE-99999"
    assert entry.url.endswith("/99999.html")
    assert "MITRE" in entry.description


def test_catalog_is_sorted_unique_and_non_empty():
    entries = cwe.all_entries()
    ids = [entry.id for entry in entries]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert len(ids) >= 60
    assert cwe.categories()


def test_search_by_number_name_and_russian_text():
    assert [entry.id for entry in cwe.search("79")] == [79]
    assert [entry.id for entry in cwe.search("CWE-89")] == [89]
    assert any(entry.id == 22 for entry in cwe.search("path traversal"))
    assert any(entry.id == 79 for entry in cwe.search("межсайтовый"))
    assert any(entry.id == 502 for entry in cwe.search("десериализация"))
    assert cwe.search("") == cwe.all_entries()
    assert cwe.search("этого-точно-нет-в-каталоге") == []


def test_entries_for_deduplicates_and_skips_junk():
    entries = cwe.entries_for(["CWE-79", "79", "cwe/89", "junk", "", None])
    assert [entry.id for entry in entries] == [79, 89]


def test_catalog_covers_every_cwe_used_by_bundled_rules():
    root = Path(__file__).resolve().parent.parent / "argus" / "sast"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in root.rglob("*")
        if path.suffix in {".py", ".yaml", ".yml"} and "__pycache__" not in path.parts
    )
    ids = {int(number.lstrip("0") or "0")
           for number in re.findall(r"CWE-0*(\d+)", text)}
    missing = sorted(number for number in ids
                     if number and not cwe.lookup(f"CWE-{number}").known)
    assert missing == [], f"CWEs missing from the local catalog: {missing}"


def test_cli_cwe_detail_json_and_markdown(capsys, tmp_path):
    code = main(["cwe", "79", "-f", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["count"] == 1
    assert payload["entries"][0]["cwe"] == "CWE-79"
    assert payload["entries"][0]["known"] is True

    code = main(["cwe", "79", "CWE-89", "-f", "md"])
    markdown = capsys.readouterr().out
    assert code == EXIT_OK
    assert "## CWE-79" in markdown and "## CWE-89" in markdown
    assert "https://cwe.mitre.org/data/definitions/79.html" in markdown

    target = tmp_path / "cwe.json"
    code = main(["cwe", "502", "-f", "json", "-o", str(target)])
    assert code == EXIT_OK
    assert json.loads(target.read_text(encoding="utf-8"))["count"] == 1


def test_cli_cwe_list_search_and_bad_identifier(capsys):
    code = main(["cwe"])
    listing = capsys.readouterr().out
    assert code == EXIT_OK
    assert "CWE-79" in listing and "Всего:" in listing

    code = main(["cwe", "--search", "sql"])
    found = capsys.readouterr().out
    assert code == EXIT_OK
    assert "CWE-89" in found
    assert "Всего:" in found

    code = main(["cwe", "not-a-cwe"])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "not a CWE identifier" in captured.err
