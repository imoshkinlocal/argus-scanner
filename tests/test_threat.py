"""EPSS and CISA KEV threat intelligence."""

from __future__ import annotations

import json

import pytest

import argus.cli as cli_module
from argus import threat
from argus.cli import EXIT_OK, main
from argus.models import Finding, ScanResult, Severity
from argus.output import markdown_report, sarif_report


EPSS_PAYLOAD = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97400", "percentile": "0.99990",
         "date": "2026-11-24"},
        {"cve": "CVE-2020-0001", "epss": "0.00100", "percentile": "0.10000",
         "date": "2026-11-24"},
    ],
}

KEV_PAYLOAD = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2020-0001",
            "vendorProject": "Example",
            "product": "Widget",
            "vulnerabilityName": "Example bug",
            "dateAdded": "2020-01-01",
            "dueDate": "2020-01-20",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


def write_feeds(tmp_path):
    epss = tmp_path / "epss.json"
    kev = tmp_path / "kev.json"
    epss.write_text(json.dumps(EPSS_PAYLOAD))
    kev.write_text(json.dumps(KEV_PAYLOAD))
    return str(epss), str(kev)


def sca_finding(rule="GHSA-jfh8-c2jp-5v3q", aliases=("CVE-2021-44228",),
                package="org.apache.logging.log4j:log4j-core") -> Finding:
    return Finding(
        rule_id=rule, title="RCE", severity=Severity.CRITICAL, kind="sca",
        engine="osv", package=package, version="2.14.1", fixed_version="2.17.0",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        aliases=list(aliases))


# --------------------------------------------------------------------------- parsers

def test_parse_epss_api_shape():
    records = threat.parse_epss(EPSS_PAYLOAD)
    assert set(records) == {"CVE-2021-44228", "CVE-2020-0001"}
    assert records["CVE-2021-44228"]["epss"] == pytest.approx(0.974)
    assert records["CVE-2021-44228"]["percentile"] == pytest.approx(0.9999)


def test_parse_epss_plain_mapping_and_junk():
    records = threat.parse_epss({
        "CVE-2022-0001": {"epss": 0.5, "percentile": 0.9},
        "not-a-cve": {"epss": 0.9},
        "CVE-2022-0002": "0.2",
    })
    assert records["CVE-2022-0001"]["epss"] == 0.5
    assert records["CVE-2022-0002"]["epss"] == 0.2
    assert "not-a-cve" not in records


def test_parse_kev_shape_and_ransomware_flag():
    records = threat.parse_kev(KEV_PAYLOAD)
    assert records["CVE-2021-44228"]["ransomware"] is True
    assert records["CVE-2020-0001"]["ransomware"] is False
    assert records["CVE-2021-44228"]["due_date"] == "2021-12-24"
    assert records["CVE-2021-44228"]["vendor"] == "Apache"


def test_parse_kev_ignores_malformed_entries():
    assert threat.parse_kev({"vulnerabilities": [{"cveID": "nope"}, "x"]}) == {}


# --------------------------------------------------------------------------- matching

def test_finding_cves_uses_rule_and_aliases():
    finding = sca_finding(rule="CVE-2023-1111", aliases=["GHSA-x", "CVE-2023-2222"])
    assert threat.finding_cves(finding) == {"CVE-2023-1111", "CVE-2023-2222"}
    finding.rule_id = "GHSA-only"
    finding.aliases = []
    assert threat.finding_cves(finding) == set()


def test_apply_annotates_sca_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(threat, "_download", lambda *a, **k: pytest.fail("network used"))
    epss_path, kev_path = write_feeds(tmp_path)
    finding = sca_finding()
    stats = threat.apply([finding], threat.ThreatOptions(
        epss_file=epss_path, kev_file=kev_path, cache=False))
    assert stats["epss_matches"] == 1
    assert stats["kev_matches"] == 1
    assert stats["kev_ransomware"] == 1
    assert finding.metadata["epss"] == pytest.approx(0.974)
    assert finding.metadata["epss_cve"] == "CVE-2021-44228"
    assert finding.metadata["kev"] is True
    assert finding.metadata["kev_ransomware"] is True
    assert finding.metadata["kev_due_date"] == "2021-12-24"


def test_apply_ignores_sast_findings(tmp_path):
    epss_path, kev_path = write_feeds(tmp_path)
    finding = Finding(rule_id="CVE-2021-44228", title="x", severity=Severity.HIGH,
                      kind="sast", engine="argus-java", file="A.java")
    stats = threat.apply([finding], threat.ThreatOptions(
        epss_file=epss_path, kev_file=kev_path, cache=False))
    assert stats["epss_matches"] == 0
    assert "epss" not in finding.metadata


def test_apply_keeps_unmatched_findings_clean(tmp_path):
    epss_path, kev_path = write_feeds(tmp_path)
    finding = sca_finding(aliases=["CVE-1999-9999"])
    finding.rule_id = "GHSA-unknown"
    stats = threat.apply([finding], threat.ThreatOptions(
        epss_file=epss_path, kev_file=kev_path, cache=False))
    assert stats["epss_matches"] == 0
    assert stats["kev_matches"] == 0
    assert finding.metadata == {}


def test_bad_feed_file_raises(tmp_path):
    with pytest.raises(threat.ThreatIntelError):
        threat.apply([], threat.ThreatOptions(
            epss_file=str(tmp_path / "missing.json"), cache=False))


# --------------------------------------------------------------------------- cache

def test_network_result_is_cached_and_reused(tmp_path, monkeypatch):
    calls = []

    def fake_download(url, timeout):
        calls.append(url)
        return EPSS_PAYLOAD if "epss" in url else KEV_PAYLOAD

    monkeypatch.setattr(threat, "_download", fake_download)
    options = threat.ThreatOptions(cache=True, cache_dir=str(tmp_path))
    first = threat.apply([sca_finding()], options)
    assert first["sources"] == {"epss": "network", "kev": "network"}
    assert len(calls) == 2

    monkeypatch.setattr(threat, "_download",
                        lambda *a, **k: pytest.fail("cache miss"))
    second = threat.apply([sca_finding()], options)
    assert second["sources"] == {"epss": "cache", "kev": "cache"}


def test_stale_cache_is_used_when_network_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(threat, "_download",
                        lambda url, timeout: EPSS_PAYLOAD if "epss" in url else KEV_PAYLOAD)
    options = threat.ThreatOptions(cache=True, cache_dir=str(tmp_path), ttl_hours=0)
    threat.apply([sca_finding()], options)
    monkeypatch.setattr(threat, "_download",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    stats = threat.apply([sca_finding()], options)
    assert stats["sources"] == {"epss": "cache-stale", "kev": "cache-stale"}
    assert stats["errors"]
    assert stats["kev_matches"] == 1


def test_no_cache_skips_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(threat, "_download",
                        lambda url, timeout: EPSS_PAYLOAD if "epss" in url else KEV_PAYLOAD)
    options = threat.ThreatOptions(cache=False, cache_dir=str(tmp_path))
    threat.apply([sca_finding()], options)
    assert not any(tmp_path.iterdir())


# --------------------------------------------------------------------------- reports

def test_markdown_shows_epss_and_kev(tmp_path):
    epss_path, kev_path = write_feeds(tmp_path)
    finding = sca_finding()
    result = ScanResult(target="/src")
    result.findings = [finding]
    result.stats["threat_intel"] = threat.apply([finding], threat.ThreatOptions(
        epss_file=epss_path, kev_file=kev_path, cache=False))
    markdown = markdown_report(result)
    assert "| Severity | Advisory | CWE | OWASP | EPSS | KEV |" in markdown
    assert "0.974 (100%)" in markdown
    assert "yes (ransomware)" in markdown
    assert "* Threat intel: 1 EPSS match(es), 1 KEV match(es), 1 ransomware-linked" in markdown


def test_sarif_includes_threat_properties(tmp_path):
    epss_path, kev_path = write_feeds(tmp_path)
    finding = sca_finding()
    threat.apply([finding], threat.ThreatOptions(
        epss_file=epss_path, kev_file=kev_path, cache=False))
    result = ScanResult(target="/src")
    result.findings = [finding]
    properties = sarif_report(result, "/src")["runs"][0]["results"][0]["properties"]
    assert properties["epss"] == pytest.approx(0.974)
    assert properties["epss_percentile"] == pytest.approx(0.9999)
    assert properties["kev"] is True
    assert properties["kev_ransomware"] is True
    assert properties["kev_due_date"] == "2021-12-24"


# --------------------------------------------------------------------------- CLI

def test_cli_sca_threat_intel_flags(tmp_path, monkeypatch, capsys):
    epss_path, kev_path = write_feeds(tmp_path)

    def fake_scan(target, options):
        return [sca_finding()], {"manifests_scanned": 1}, []

    monkeypatch.setattr(cli_module, "sca_scan", fake_scan)
    code = main(["sca", str(tmp_path), "--min-severity", "low",
                 "--threat-intel", "--epss-file", epss_path,
                 "--kev-file", kev_path, "--no-threat-cache",
                 "--fail-on", "none", "-f", "json", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert payload["stats"]["threat_intel"]["epss_matches"] == 1
    assert payload["stats"]["threat_intel"]["kev_matches"] == 1
    assert payload["findings"][0]["metadata"]["kev"] is True


def test_cli_feed_file_implies_threat_intel(tmp_path, monkeypatch, capsys):
    epss_path, kev_path = write_feeds(tmp_path)

    def fake_scan(target, options):
        return [sca_finding()], {}, []

    monkeypatch.setattr(cli_module, "sca_scan", fake_scan)
    main(["sca", str(tmp_path), "--min-severity", "low", "--epss-file", epss_path,
          "--kev-file", kev_path, "--fail-on", "none", "-f", "json", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert "threat_intel" in payload["stats"]


def test_epss_query_is_targeted_at_needed_cves(tmp_path, monkeypatch):
    seen = []

    def fake_download(url, timeout):
        seen.append(url)
        if "epss" in url:
            assert "cve=CVE-2021-44228" in url
            return EPSS_PAYLOAD
        return KEV_PAYLOAD

    monkeypatch.setattr(threat, "_download", fake_download)
    threat.apply([sca_finding()], threat.ThreatOptions(
        cache=True, cache_dir=str(tmp_path)))
    epss_urls = [url for url in seen if "epss" in url]
    assert len(epss_urls) == 1
    assert "CVE-2021-44228" in epss_urls[0]


def test_no_cves_skips_network(tmp_path, monkeypatch):
    monkeypatch.setattr(threat, "_download", lambda *a, **k: pytest.fail("network used"))
    stats = threat.apply([sca_finding(aliases=[])], threat.ThreatOptions(
        cache=True, cache_dir=str(tmp_path)))
    assert stats["sources"] == {"epss": "skipped", "kev": "skipped"}
    assert not any(tmp_path.iterdir())
