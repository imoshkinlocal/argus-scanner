"""Project configuration: discovery, parsing and argparse defaults."""

from __future__ import annotations

import json
import os

import pytest

from argus import config


TOML = """\
[scan]
format = "md"
fail_on = "critical"
min_severity = "low"
baseline = "baseline.json"
baseline_out = "out/base.json"

[sast]
exclude = ["vendor", "build"]
languages = ["java"]

[sca]
include_dev = true
offline = true

[sbom]
format = "cyclonedx"
name = "demo"

[gates]
max_total = 5
deny_packages = ["log4j-core"]
deny_cwes = ["CWE-502"]

[severity]
"CWE-89" = "critical"

[[suppress]]
rule = "java-sqli-*"
reason = "legacy"
"""


def test_parse_toml(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text(TOML)
    loaded = config.load(str(path))
    assert loaded.get("scan", "format") == "md"
    assert loaded.get("gates", "max_total") == 5
    assert loaded.severity_overrides() == {"CWE-89": "critical"}
    assert loaded.suppressions()[0]["rule"] == "java-sqli-*"


def test_parse_json(tmp_path):
    path = tmp_path / "argus.json"
    path.write_text(json.dumps({"scan": {"fail_on": "low"}, "suppress": [{"rule": "x"}]}))
    loaded = config.load(str(path))
    assert loaded.get("scan", "fail_on") == "low"
    assert loaded.suppressions() == [{"rule": "x"}]


def test_invalid_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(config.ConfigError):
        config.load(str(path))


def test_missing_file_raises(tmp_path):
    with pytest.raises(config.ConfigError):
        config.load(str(tmp_path / "absent.toml"))


def test_find_searches_upwards(tmp_path):
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (tmp_path / "argus.toml").write_text("[scan]\nfail_on = \"low\"\n")
    found = config.find(start=str(nested))
    assert found is not None
    assert found.path == os.path.join(str(tmp_path), "argus.toml")


def test_find_explicit_wins(tmp_path):
    root = tmp_path / "argus.toml"
    root.write_text("[scan]\nfail_on = \"low\"\n")
    explicit = tmp_path / "custom.toml"
    explicit.write_text("[scan]\nfail_on = \"critical\"\n")
    found = config.find(start=str(tmp_path), explicit=str(explicit))
    assert found.get("scan", "fail_on") == "critical"


def test_env_variable_config(tmp_path, monkeypatch):
    path = tmp_path / "env.toml"
    path.write_text("[scan]\nfail_on = \"medium\"\n")
    monkeypatch.setenv(config.CONFIG_ENV, str(path))
    found = config.find(start=str(tmp_path / "elsewhere"))
    assert found.get("scan", "fail_on") == "medium"


def test_find_returns_none(tmp_path, monkeypatch):
    monkeypatch.delenv(config.CONFIG_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    assert config.find(start=str(tmp_path)) is None


def test_relative_paths_resolved(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text("[scan]\nbaseline = \"ci/base.json\"\nsummary = \"reports/r.md\"\n")
    loaded = config.load(str(path))
    defaults = config.argparse_defaults(loaded, "scan")
    assert defaults["baseline"] == os.path.join(str(tmp_path), "ci", "base.json")
    assert defaults["summary"] == os.path.join(str(tmp_path), "reports", "r.md")


def test_argparse_defaults_scan(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text(TOML)
    loaded = config.load(str(path))
    defaults = config.argparse_defaults(loaded, "scan")
    assert defaults["format"] == "md"
    assert defaults["fail_on"] == "critical"
    assert defaults["include_dev"] is True
    assert defaults["offline"] is True
    assert set(defaults["exclude"]) == {"vendor", "build"}
    assert defaults["language"] == ["java"]


def test_argparse_defaults_gates(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text(TOML)
    loaded = config.load(str(path))
    gates = loaded.gate_options()
    assert gates["max_total"] == 5
    assert gates["deny_packages"] == ["log4j-core"]
    assert gates["fail_on"] == "critical"


def test_argparse_defaults_sbom(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text(TOML)
    loaded = config.load(str(path))
    defaults = config.argparse_defaults(loaded, "sbom")
    assert defaults["format"] == "cyclonedx"
    assert defaults["name"] == "demo"


def test_minimal_toml_fallback():
    data = config._minimal_toml(
        '# comment\n[scan]\nfail_on = "high"\nlist = [1, 2, 3]\n'
        "nested = { a = true, b = 'x' }\n")
    assert data["scan"]["fail_on"] == "high"
    assert data["scan"]["list"] == [1, 2, 3]
    assert data["scan"]["nested"] == {"a": True, "b": "x"}


def test_glob_match():
    assert config.glob_match("src/app/Main.java", "src/*/Main.java")
    assert config.glob_match("Main.JAVA", "*.java")
    assert not config.glob_match("src/main.py", "*.java")


def test_threat_intel_config(tmp_path):
    path = tmp_path / "argus.toml"
    path.write_text("""\
[sca]
threat_intel = true
epss_file = "feeds/epss.json"
kev_file = "feeds/kev.json"
threat_cache = false
threat_cache_dir = "cache/threat"
threat_ttl = 24
""")
    loaded = config.load(str(path))
    defaults = config.argparse_defaults(loaded, "scan")
    assert defaults["threat_intel"] is True
    assert defaults["epss_file"] == os.path.join(str(tmp_path), "feeds", "epss.json")
    assert defaults["kev_file"] == os.path.join(str(tmp_path), "feeds", "kev.json")
    assert defaults["no_threat_cache"] is True
    assert defaults["threat_cache_dir"] == os.path.join(str(tmp_path), "cache", "threat")
    assert defaults["threat_ttl"] == 24
