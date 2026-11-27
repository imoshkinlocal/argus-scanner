"""OWASP Top 10 mapping: bundled editions, custom files and enrichment."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import enrich, owasp
from argus.cli import EXIT_ERROR, EXIT_OK, main
from argus.models import Finding, Severity


def make_finding(cwe="CWE-89", rule="java-sqli-jdbc") -> Finding:
    return Finding(rule_id=rule, title="finding", severity=Severity.HIGH,
                   kind="sast", engine="argus-java", file="App.java",
                   start_line=1, cwe=cwe)


# --------------------------------------------------------------------------- bundled catalog

def test_available_versions_and_default():
    versions = owasp.available_versions()
    assert versions == ["2017", "2021", "2025"]
    assert owasp.default_version() == "2021"
    assert owasp.load_mapping().version == "2021"


def test_normalize_version_and_category_id():
    assert owasp.normalize_version("2021") == "2021"
    assert owasp.normalize_version(2025) == "2025"
    assert owasp.normalize_version("v2021") == "2021"
    assert owasp.normalize_version("OWASP-2021") == "2021"
    assert owasp.normalize_version("top 10 2017") == "2017"
    assert owasp.normalize_version("") == ""
    assert owasp.normalize_category_id("a3") == "A3"
    assert owasp.normalize_category_id("A03:2021") == "A03"
    with pytest.raises(owasp.OwaspError):
        owasp.normalize_category_id("injection")


def test_builtin_2021_maps_common_cwes():
    mapping = owasp.load_builtin("2021")
    assert [c.label for c in mapping.lookup("CWE-89")] == ["A03:2021"]
    assert [c.label for c in mapping.lookup(79)] == ["A03:2021"]
    assert [c.label for c in mapping.lookup("CWE-502")] == ["A08:2021"]
    assert [c.label for c in mapping.lookup("CWE-918")] == ["A10:2021"]
    assert [c.label for c in mapping.lookup("CWE-937")] == ["A06:2021"]
    assert mapping.lookup("CWE-999999") == ()
    assert mapping.lookup("not a cwe") == ()


def test_builtin_2025_remaps_categories():
    mapping = owasp.load_builtin("2025")
    assert [c.label for c in mapping.lookup("CWE-89")] == ["A05:2025"]
    assert [c.label for c in mapping.lookup("CWE-1104")] == ["A03:2025"]
    assert [c.label for c in mapping.lookup("CWE-918")] == ["A01:2025"]
    assert "A05:2025" in {category.label for category in mapping.categories}


def test_builtin_2017_uses_the_official_document():
    mapping = owasp.load_builtin("2017")
    assert [c.label for c in mapping.lookup("CWE-89")] == ["A1:2017"]
    assert [c.label for c in mapping.lookup("CWE-79")] == ["A7:2017"]
    # A09 has no CWE list in the 2017 document; the successor CWEs are used.
    assert [c.label for c in mapping.lookup("CWE-1104")] == ["A9:2017"]


def test_cwe_can_map_to_several_categories():
    mapping = owasp.load_builtin("2021")
    labels = [category.label for category in mapping.lookup("CWE-259")]
    assert labels == ["A02:2021", "A07:2021"]


def test_category_lookup_and_display():
    mapping = owasp.load_builtin("2021")
    category = mapping.category("A03:2021")
    assert category is not None
    assert category.id == "A03"
    assert category.name == "Injection"
    assert category.name_ru == "Инъекции"
    assert category.display == "A03:2021 Injection"
    assert category.display_ru == "A03:2021 Инъекции"
    assert category.url.startswith("https://owasp.org/")
    assert mapping.category("A99") is None


def test_aggressive_loading_is_rejected():
    with pytest.raises(owasp.OwaspError):
        owasp.load_builtin("2029")


def test_bundled_document_is_well_formed():
    path = Path(owasp.data_path())
    assert path.is_file()
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["default"] == "2021"
    for year, edition in document["versions"].items():
        categories = edition["categories"]
        assert len(categories) == 10
        ids = [category["id"] for category in categories]
        assert len(ids) == len(set(ids))
        for category in categories:
            assert category["name"]
            assert category["name_ru"]
            assert category["url"].startswith("https://")
            assert category["cwes"] == sorted(set(category["cwes"]))
            assert all(isinstance(number, int) and number > 0
                       for number in category["cwes"])


def test_mapping_to_dict_keeps_cwes():
    mapping = owasp.load_builtin("2021")
    payload = mapping.to_dict()
    assert payload["version"] == "2021"
    injection = next(item for item in payload["categories"]
                     if item["id"] == "A03:2021")
    assert 89 in injection["cwes"]
    assert "cwes" in injection


# --------------------------------------------------------------------------- enrichment

def test_attach_replaces_and_clears_references():
    findings = [make_finding("CWE-89"), make_finding("CWE-999999", "other")]
    mapping = owasp.load_builtin("2021")
    assert owasp.attach(findings, mapping) == 1
    assert [category.label for category in findings[0].owasp] == ["A03:2021"]
    assert findings[1].owasp == []
    # Re-running with another edition must not keep stale labels.
    owasp.attach(findings, owasp.load_builtin("2025"))
    assert [category.label for category in findings[0].owasp] == ["A05:2025"]


def test_enrich_options_control_owasp():
    finding = make_finding()
    counts = enrich.enrich([finding], enrich.EnrichOptions(
        snippets=False, remediation=False, owasp=True))
    assert counts["owasp"] == 1
    assert finding.owasp[0].label == "A03:2021"
    disabled = make_finding()
    counts = enrich.enrich([disabled], enrich.EnrichOptions(
        snippets=False, remediation=False, owasp=False))
    assert counts["owasp"] == 0
    assert disabled.owasp == []


# --------------------------------------------------------------------------- custom files

def test_load_custom_single_edition_json(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({
        "version": "2029",
        "source": "internal",
        "categories": [
            {"id": "A01", "name": "Broken Access Control",
             "name_ru": "Нарушение контроля доступа", "cwes": ["CWE-89", 79]},
            {"id": "A02", "name": "Injection", "name_ru": "Инъекции",
             "cwes": [89, "CWE-564"]},
        ],
    }), encoding="utf-8")
    mapping = owasp.load_mapping(path=str(path))
    assert mapping.version == "2029"
    assert mapping.source == "internal"
    assert [c.label for c in mapping.lookup("CWE-89")] == ["A01:2029", "A02:2029"]
    assert [c.label for c in mapping.lookup("CWE-79")] == ["A01:2029"]


def test_custom_multi_edition_document_selects_a_version(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({
        "default": "2031",
        "versions": {
            "2029": {"categories": [{"id": "A01", "name": "Old", "cwes": [89]}]},
            "2031": {"categories": [{"id": "A05", "name": "New", "cwes": [89]}]},
        },
    }), encoding="utf-8")
    assert owasp.load_mapping(path=str(path)).version == "2031"
    chosen = owasp.load_mapping("2029", str(path))
    assert chosen.version == "2029"
    assert [c.label for c in chosen.lookup(89)] == ["A01:2029"]
    with pytest.raises(owasp.OwaspError):
        owasp.load_mapping("2040", str(path))


def test_custom_multi_edition_requires_a_version(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({"versions": {
        "2029": {"categories": [{"id": "A01", "name": "One", "cwes": [89]}]},
        "2031": {"categories": [{"id": "A01", "name": "Two", "cwes": [89]}]},
    }}), encoding="utf-8")
    with pytest.raises(owasp.OwaspError):
        owasp.load_mapping(path=str(path))


def test_custom_toml_mapping(tmp_path):
    path = tmp_path / "mapping.toml"
    path.write_text(
        'version = "2029"\n'
        '[[categories]]\n'
        'id = "A03"\n'
        'name = "Injection"\n'
        'name_ru = "Инъекции"\n'
        'cwes = [89, "CWE-79"]\n',
        encoding="utf-8")
    mapping = owasp.load_mapping(path=str(path))
    assert mapping.version == "2029"
    assert [c.label for c in mapping.lookup(79)] == ["A03:2029"]


def test_invalid_custom_mappings_raise(tmp_path):
    bad_cwe = tmp_path / "bad-cwe.json"
    bad_cwe.write_text(json.dumps({"version": "2029", "categories": [
        {"id": "A01", "name": "X", "cwes": ["nope"]}]}), encoding="utf-8")
    with pytest.raises(owasp.OwaspError):
        owasp.load_mapping(path=str(bad_cwe))

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps({"version": "2029", "categories": [
        {"id": "A01", "name": "X", "cwes": [89]},
        {"id": "A1", "name": "Y", "cwes": [79]}]}), encoding="utf-8")
    with pytest.raises(owasp.OwaspError):
        owasp.load_mapping(path=str(duplicate))

    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"version": "2029", "categories": []}),
                     encoding="utf-8")
    with pytest.raises(owasp.OwaspError):
        owasp.load_mapping(path=str(empty))

    with pytest.raises(owasp.OwaspError):
        owasp.load_mapping(path=str(tmp_path / "missing.json"))


# --------------------------------------------------------------------------- CLI

def test_cli_owasp_lists_categories(capsys):
    assert main(["owasp"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "OWASP Top 10 — 2021" in output
    assert "A01:2021" in output
    assert "A03:2021" in output


def test_cli_owasp_maps_requested_cwes(capsys):
    assert main(["owasp", "89", "79", "--version", "2025"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "CWE-89" in output and "A05:2025" in output
    assert "CWE-79" in output

    assert main(["owasp", "259", "-f", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    mapped = payload["mapped"][0]
    assert mapped["cwe"] == "CWE-259"
    assert [item["id"] for item in mapped["categories"]] == [
        "A02:2021", "A07:2021"]


def test_cli_owasp_rejects_unknown_version_and_bad_cwe(capsys):
    assert main(["owasp", "--version", "2029"]) == EXIT_ERROR
    assert "unknown OWASP" in capsys.readouterr().err
    assert main(["owasp", "definitely-not-a-cwe"]) == EXIT_ERROR
    assert "not a CWE identifier" in capsys.readouterr().err


def test_cli_owasp_reads_a_custom_file(tmp_path, capsys):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({"version": "2029", "categories": [
        {"id": "A01", "name": "Custom", "name_ru": "Своя",
         "cwes": [89]}]}), encoding="utf-8")
    assert main(["owasp", "89", "--file", str(path)]) == EXIT_OK
    output = capsys.readouterr().out
    assert "A01:2029" in output
    assert "Своя" in output
