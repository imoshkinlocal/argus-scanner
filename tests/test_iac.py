"""Tests for the lightweight infrastructure-as-code scanner."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Dict, List

from argus.iac import scan_target
from argus.models import Finding, Severity

DOCKER_VULNERABLE = textwrap.dedent(
    """\
    FROM ubuntu:latest
    USER root
    ADD https://example.com/tool.tar.gz /tmp/
    RUN curl -fsSL https://example.com/install.sh | sh
    RUN apt-get update && setup --privileged
    ENV DB_PASSWORD=Sup3rS3cretValue
    ARG API_TOKEN=AnotherSecretValue
    # FROM alpine:latest
    USER app
    """
)

DOCKER_SAFE = textwrap.dedent(
    """\
    FROM alpine:3.20
    USER app
    RUN apk add --no-cache curl
    ENV DB_PASSWORD=${DB_PASSWORD}
    ARG API_TOKEN
    ADD ./local /app
    COPY . /app
    """
)

K8S_VULNERABLE = textwrap.dedent(
    """\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: bad
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      template:
        spec:
          containers:
          - name: app
            image: nginx:1.25
            securityContext:
              # privileged: true this comment must not trigger
              privileged: true
              runAsUser: 0
              allowPrivilegeEscalation: true
              readOnlyRootFilesystem: false
    """
)

K8S_SAFE = textwrap.dedent(
    """\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: safe
    spec:
      template:
        spec:
          containers:
          - name: app
            image: nginx:1.25
            securityContext:
              privileged: false
              runAsUser: 1000
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
    """
)

TF_VULNERABLE = textwrap.dedent(
    """\
    resource "aws_s3_bucket" "bad" {
      bucket = "demo"
      acl    = "public-read"
    }

    resource "aws_db_instance" "bad" {
      publicly_accessible = true
      storage_encrypted   = false
    }

    resource "aws_security_group" "bad" {
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
      ingress {
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }

    # acl = "public-read"
    // encrypted = false
    """
)

TF_SAFE = textwrap.dedent(
    """\
    resource "aws_s3_bucket" "ok" {
      bucket = "demo"
      acl    = "private"
    }

    resource "aws_db_instance" "ok" {
      publicly_accessible = false
      storage_encrypted   = true
    }

    resource "aws_security_group" "ok" {
      ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["10.0.0.0/8"]
      }
    }
    """
)


def _rules(findings: List[Finding]) -> Dict[str, List[int]]:
    result: Dict[str, List[int]] = {}
    for finding in findings:
        result.setdefault(finding.rule_id, []).append(finding.start_line)
    for lines in result.values():
        lines.sort()
    return result


def _scan(root: Path, **kwargs):
    return scan_target(str(root), **kwargs)


def test_dockerfile_reports_all_rules_with_locations(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKER_VULNERABLE, encoding="utf-8")

    findings, stats, errors = _scan(tmp_path)

    assert errors == []
    assert _rules(findings) == {
        "iac-docker-latest-tag": [1],
        "iac-docker-root-user": [2],
        "iac-docker-add-remote": [3],
        "iac-docker-curl-pipe-shell": [4],
        "iac-docker-privileged": [5],
        "iac-docker-hardcoded-secret": [6, 7],
    }
    assert stats["findings"] == 7
    assert stats["files_scanned"] == 1

    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["iac-docker-latest-tag"].severity is Severity.INFO
    assert by_rule["iac-docker-latest-tag"].cwe == "CWE-1104"
    assert by_rule["iac-docker-root-user"].severity is Severity.MEDIUM
    assert by_rule["iac-docker-root-user"].cwe == "CWE-250"
    assert by_rule["iac-docker-add-remote"].severity is Severity.MEDIUM
    assert by_rule["iac-docker-add-remote"].cwe == "CWE-494"
    assert by_rule["iac-docker-curl-pipe-shell"].severity is Severity.HIGH
    assert by_rule["iac-docker-curl-pipe-shell"].cwe == "CWE-494"
    assert by_rule["iac-docker-privileged"].severity is Severity.HIGH
    assert by_rule["iac-docker-hardcoded-secret"].severity is Severity.HIGH
    assert by_rule["iac-docker-hardcoded-secret"].cwe == "CWE-798"

    for finding in findings:
        assert finding.kind == "sast"
        assert finding.engine == "argus-iac"
        assert finding.start_col == 1
        assert finding.end_line == finding.start_line
        assert finding.file == "Dockerfile"


def test_dockerfile_secret_values_are_not_leaked(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKER_VULNERABLE, encoding="utf-8")

    findings, _, _ = _scan(tmp_path)
    secrets = [f for f in findings if f.rule_id == "iac-docker-hardcoded-secret"]

    assert len(secrets) == 2
    messages = "\n".join(finding.message for finding in secrets)
    assert "DB_PASSWORD" in messages
    assert "API_TOKEN" in messages
    for finding in secrets:
        assert "Sup3rS3cretValue" not in finding.message
        assert "AnotherSecretValue" not in finding.message
    assert "Sup3rS3cretValue" not in messages
    assert "AnotherSecretValue" not in messages


def test_safe_dockerfile_produces_no_findings(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKER_SAFE, encoding="utf-8")

    findings, stats, errors = _scan(tmp_path)

    assert findings == []
    assert errors == []
    assert stats["files_scanned"] == 1


def test_dockerfile_user_zero_and_shell_pipe_variants(tmp_path):
    (tmp_path / "Dockerfile.zero").write_text(
        "FROM debian:12\n"
        "USER 0\n"
        "RUN wget -qO- https://example.com/i.sh | bash\n"
        "RUN bash <(curl -s https://example.com/j.sh)\n",
        encoding="utf-8",
    )

    findings, _, errors = _scan(tmp_path)

    assert errors == []
    assert _rules(findings) == {
        "iac-docker-root-user": [2],
        "iac-docker-curl-pipe-shell": [3, 4],
    }
    assert all(finding.severity is Severity.HIGH for finding in findings
               if finding.rule_id == "iac-docker-curl-pipe-shell")


def test_kubernetes_findings_and_locations(tmp_path):
    (tmp_path / "pod.yaml").write_text(K8S_VULNERABLE, encoding="utf-8")

    findings, _, errors = _scan(tmp_path)

    assert errors == []
    assert _rules(findings) == {
        "iac-k8s-host-network": [6],
        "iac-k8s-host-pid": [7],
        "iac-k8s-host-ipc": [8],
        "iac-k8s-privileged": [16],
        "iac-k8s-run-as-root": [17],
        "iac-k8s-privilege-escalation": [18],
        "iac-k8s-writable-root-fs": [19],
    }
    assert all(15 not in finding_lines for finding_lines in _rules(findings).values())

    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["iac-k8s-privileged"].severity is Severity.HIGH
    assert by_rule["iac-k8s-privileged"].cwe == "CWE-250"
    assert by_rule["iac-k8s-host-network"].severity is Severity.HIGH
    assert by_rule["iac-k8s-run-as-root"].severity is Severity.HIGH
    assert by_rule["iac-k8s-privilege-escalation"].severity is Severity.MEDIUM
    assert by_rule["iac-k8s-writable-root-fs"].severity is Severity.LOW
    assert by_rule["iac-k8s-writable-root-fs"].cwe == "CWE-732"


def test_safe_kubernetes_and_plain_yaml_produce_no_findings(tmp_path):
    (tmp_path / "deployment.yaml").write_text(K8S_SAFE, encoding="utf-8")
    (tmp_path / "config.yaml").write_text(
        "some: config\nprivileged: true\n", encoding="utf-8"
    )

    findings, stats, errors = _scan(tmp_path)

    assert findings == []
    assert errors == []
    assert stats["files_scanned"] == 2


def test_terraform_findings_and_locations(tmp_path):
    (tmp_path / "main.tf").write_text(TF_VULNERABLE, encoding="utf-8")

    findings, _, errors = _scan(tmp_path)

    assert errors == []
    assert _rules(findings) == {
        "iac-tf-public-s3": [3],
        "iac-tf-publicly-accessible": [7],
        "iac-tf-unencrypted": [8],
        "iac-tf-open-admin-port": [16, 22],
    }

    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["iac-tf-public-s3"].severity is Severity.HIGH
    assert by_rule["iac-tf-public-s3"].cwe == "CWE-732"
    assert by_rule["iac-tf-publicly-accessible"].severity is Severity.HIGH
    assert by_rule["iac-tf-unencrypted"].severity is Severity.MEDIUM
    assert by_rule["iac-tf-unencrypted"].cwe == "CWE-311"
    assert by_rule["iac-tf-open-admin-port"].severity is Severity.HIGH
    assert by_rule["iac-tf-open-admin-port"].cwe == "CWE-284"


def test_safe_terraform_produces_no_findings(tmp_path):
    (tmp_path / "main.tf").write_text(TF_SAFE, encoding="utf-8")

    findings, _, errors = _scan(tmp_path)

    assert findings == []
    assert errors == []


def test_terraform_comments_are_ignored(tmp_path):
    (tmp_path / "main.tf").write_text(
        textwrap.dedent(
            """\
            # acl = "public-read"
            // publicly_accessible = true
            resource "aws_s3_bucket" "ok" {
              # acl = "public-read-write"
              acl = "private" // encrypted = false
            }
            """
        ),
        encoding="utf-8",
    )

    findings, _, errors = _scan(tmp_path)

    assert findings == []
    assert errors == []


def test_exclude_and_default_skipped_directories(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\nUSER root\n", encoding="utf-8")
    (tmp_path / "keep.dockerfile").write_text(
        "FROM alpine:3.20\nUSER app\n", encoding="utf-8"
    )
    (tmp_path / "skipme.dockerfile").write_text(
        "FROM alpine:3.20\nUSER root\n", encoding="utf-8"
    )
    for directory in ("skip", "node_modules", ".git", ".terraform"):
        target = tmp_path / directory
        target.mkdir()
        (target / "Dockerfile").write_text(
            "FROM alpine:3.20\nUSER root\n", encoding="utf-8"
        )

    findings, stats, errors = _scan(tmp_path, exclude=("skip", "skipme.dockerfile"))

    assert errors == []
    assert [(finding.rule_id, finding.file) for finding in findings] == [
        ("iac-docker-root-user", "Dockerfile")
    ]
    assert stats["files_excluded"] == 1
    assert stats["directories_skipped"] == 4


def test_empty_directory_returns_clean_stats(tmp_path):
    findings, stats, errors = _scan(tmp_path)

    assert findings == []
    assert errors == []
    assert stats["files_scanned"] == 0
    assert stats["files_skipped"] == 0
    assert stats["findings"] == 0
    assert sum(stats["by_severity"].values()) == 0


def test_missing_root_is_reported_as_error(tmp_path):
    missing = tmp_path / "does-not-exist"

    findings, stats, errors = _scan(missing)

    assert findings == []
    assert stats["files_scanned"] == 0
    assert len(errors) == 1
    assert "does-not-exist" in errors[0]


def test_max_file_bytes_skips_large_files(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKER_VULNERABLE, encoding="utf-8")

    findings, stats, errors = _scan(tmp_path, max_file_bytes=16)

    assert findings == []
    assert errors == []
    assert stats["files_scanned"] == 0
    assert stats["files_skipped"] == 1


def test_unreadable_file_is_collected_in_errors(tmp_path):
    link = tmp_path / "Dockerfile.broken"
    try:
        link.symlink_to(tmp_path / "missing-target")
    except (OSError, NotImplementedError):
        return

    findings, stats, errors = _scan(tmp_path)

    assert findings == []
    assert stats["files_scanned"] == 0
    assert stats["files_skipped"] == 1
    assert any("Dockerfile.broken" in message for message in errors)


def test_stats_aggregate_severity_and_rules(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKER_VULNERABLE, encoding="utf-8")
    (tmp_path / "pod.yaml").write_text(K8S_VULNERABLE, encoding="utf-8")
    (tmp_path / "main.tf").write_text(TF_VULNERABLE, encoding="utf-8")

    findings, stats, errors = _scan(tmp_path)

    assert errors == []
    assert stats["files_scanned"] == 3
    assert stats["findings"] == len(findings) == 19
    assert sum(stats["by_severity"].values()) == len(findings)
    assert stats["by_severity"]["high"] == 13
    assert stats["by_severity"]["medium"] == 4
    assert stats["by_severity"]["low"] == 1
    assert stats["by_severity"]["info"] == 1
    assert stats["by_rule"]["iac-docker-root-user"] == 1
    assert stats["by_rule"]["iac-k8s-privileged"] == 1
    assert stats["by_rule"]["iac-tf-open-admin-port"] == 2
    assert stats["by_rule"] == {
        "iac-docker-latest-tag": 1,
        "iac-docker-root-user": 1,
        "iac-docker-add-remote": 1,
        "iac-docker-curl-pipe-shell": 1,
        "iac-docker-privileged": 1,
        "iac-docker-hardcoded-secret": 2,
        "iac-k8s-host-network": 1,
        "iac-k8s-host-pid": 1,
        "iac-k8s-host-ipc": 1,
        "iac-k8s-privileged": 1,
        "iac-k8s-run-as-root": 1,
        "iac-k8s-privilege-escalation": 1,
        "iac-k8s-writable-root-fs": 1,
        "iac-tf-public-s3": 1,
        "iac-tf-publicly-accessible": 1,
        "iac-tf-unencrypted": 1,
        "iac-tf-open-admin-port": 2,
    }
