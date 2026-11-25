"""Tests for the offline secret scanner."""

from __future__ import annotations

import json

from argus import secrets
from argus.models import Severity

AWS_ACCESS = "AKIAABCDEFGHIJKLMNOP"
AWS_ACCESS_ASIA = "ASIAQWERTYUIOPASDFGH"
AWS_SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
SLACK_TOKEN = "xoxb-123456789012-123456789012-abcdefghijklmnop"
STRIPE_KEY = "sk_live_51H8YxQ2eZvKYlo2Cabcdefgh"
GOOGLE_KEY = "AIzaSyB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uVwX"
JWT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PASSWORD = "Tr0ub4dor&3xK9mQ2v"


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _single_file(tmp_path, text: str):
    _write(tmp_path / "app.py", text)
    findings, stats, errors = secrets.scan_target(str(tmp_path))
    return findings, stats, errors


def test_detects_each_secret_family(tmp_path):
    content = (
        f"aws_access_key_id = {AWS_ACCESS}\n"
        f"asia_access_key_id = {AWS_ACCESS_ASIA}\n"
        f'aws_secret_access_key = "{AWS_SECRET}"\n'
        f"github_token = {GITHUB_TOKEN}\n"
        f"slack_token = {SLACK_TOKEN}\n"
        f"stripe_key = {STRIPE_KEY}\n"
        f"google_key = {GOOGLE_KEY}\n"
        f"jwt = {JWT_TOKEN}\n"
        f'db_password = "{PASSWORD}"\n'
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAfakefakefakefakefakefakefakefake\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    findings, stats, errors = _single_file(tmp_path, content)

    assert errors == []
    found = {finding.rule_id for finding in findings}
    assert found == {
        "secret-aws-access-key",
        "secret-aws-secret-key",
        "secret-github-token",
        "secret-slack-token",
        "secret-stripe-secret-key",
        "secret-google-api-key",
        "secret-private-key",
        "secret-jwt",
        "secret-generic-assignment",
    }
    # Both AKIA and ASIA are AWS access key IDs.
    assert sum(f.rule_id == "secret-aws-access-key" for f in findings) == 2
    assert stats["findings"] == len(findings) == 10
    assert stats["rules"] == 9


def test_finding_shape_and_severity(tmp_path):
    findings, _, _ = _single_file(
        tmp_path,
        f'aws_access_key_id = "{AWS_ACCESS}"\n'
        f"github_token = {GITHUB_TOKEN}\n"
        f'db_password = "{PASSWORD}"\n',
    )
    by_rule = {finding.rule_id: finding for finding in findings}

    aws = by_rule["secret-aws-access-key"]
    assert aws.kind == "sast"
    assert aws.engine == "argus-secrets"
    assert aws.severity is Severity.CRITICAL
    assert aws.cwe == "CWE-798"
    assert aws.confidence == "high"
    assert aws.references and aws.references[0].startswith("https://docs.aws.amazon.com/")

    assert by_rule["secret-github-token"].severity is Severity.HIGH
    assert by_rule["secret-github-token"].references
    assert by_rule["secret-generic-assignment"].severity is Severity.MEDIUM


def test_every_github_prefix_is_detected(tmp_path):
    prefixes = ("ghp", "gho", "ghu", "ghs", "ghr")
    content = "".join(
        f'{prefix}_token = {prefix}_abcdefghijklmnopqrstuvwxyz0123456789\n'
        for prefix in prefixes
    )
    findings, stats, _ = _single_file(tmp_path, content)

    assert len(findings) == len(prefixes)
    assert {finding.rule_id for finding in findings} == {"secret-github-token"}
    assert stats["rules"] == 1


def test_secrets_are_masked_everywhere(tmp_path):
    content = (
        f'aws_access_key_id = "{AWS_ACCESS}"\n'
        f'aws_secret_access_key = "{AWS_SECRET}"\n'
        f"github_token = {GITHUB_TOKEN}\n"
        f"slack_token = {SLACK_TOKEN}\n"
        f"stripe_key = {STRIPE_KEY}\n"
        f"google_key = {GOOGLE_KEY}\n"
        f"jwt = {JWT_TOKEN}\n"
        f'db_password = "{PASSWORD}"\n'
        "-----BEGIN PRIVATE KEY-----\n"
    )
    findings, _, _ = _single_file(tmp_path, content)
    assert findings

    secrets_in_file = (
        AWS_ACCESS,
        AWS_SECRET,
        GITHUB_TOKEN,
        SLACK_TOKEN,
        STRIPE_KEY,
        GOOGLE_KEY,
        JWT_TOKEN,
        PASSWORD,
    )
    for finding in findings:
        serialized = json.dumps(finding.to_dict())
        for value in secrets_in_file:
            assert value not in finding.message
            assert value not in serialized

    aws = next(f for f in findings if f.rule_id == "secret-aws-access-key")
    assert secrets.mask_secret(AWS_ACCESS) == "AKIA\u2026MNOP"
    assert aws.message == "AWS access key ID detected: AKIA\u2026MNOP (20 characters)."
    assert aws.metadata["secret_masked"] == "AKIA\u2026MNOP"
    assert aws.metadata["secret_length"] == len(AWS_ACCESS)


def test_placeholders_are_ignored(tmp_path):
    content = (
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        f'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"\n'
        'password = "example_password_123"\n'
        'api_key = "your_api_key_here"\n'
        'token = "${ACCESS_TOKEN_VALUE}"\n'
        'secret = "{{ vault_secret_value }}"\n'
        'passwd = "xxxxxxxxxxxxxxxx"\n'
        'pwd = "aaaaaaaaaaaaaaaa"\n'
        'client_secret = "changeme1234567890"\n'
        'api_key = "sample_api_key_value"\n'
        'token = "dummy_token_value_1"\n'
        'password = "<your-password>"\n'
        'api_key = "os.environ[API_KEY]"\n'
        'token = "process.env.TOKEN_VALUE"\n'
    )
    findings, stats, errors = _single_file(tmp_path, content)

    assert findings == []
    assert stats["findings"] == 0
    assert errors == []


def test_short_or_low_entropy_generic_values_are_ignored(tmp_path):
    content = (
        'password = "short"\n'
        'password = "aaaaaaaaaaaaaa"\n'
        'password = "ababababababab"\n'
        'password = "111111111112"\n'
    )
    findings, _, _ = _single_file(tmp_path, content)
    assert findings == []


def test_default_directories_and_exclude(tmp_path):
    _write(tmp_path / "keep.py", f'key = "{AWS_ACCESS}"\n')
    _write(tmp_path / "ignored_dir" / "key.py", f'key = "{AWS_ACCESS}"\n')
    _write(tmp_path / "node_modules" / "key.py", f'key = "{AWS_ACCESS}"\n')
    _write(tmp_path / "vendor" / "key.py", f'key = "{AWS_ACCESS}"\n')

    findings, stats, _ = secrets.scan_target(str(tmp_path), exclude=("ignored_dir",))
    assert [finding.file for finding in findings] == ["keep.py"]
    assert stats["files_scanned"] == 1
    assert stats["files_skipped"] == 0

    # Default skip list prunes node_modules/vendor; a normal directory is scanned.
    findings, stats, _ = secrets.scan_target(str(tmp_path))
    assert [finding.file for finding in findings] == ["ignored_dir/key.py", "keep.py"]
    assert stats["files_scanned"] == 2


def test_excluded_file_is_counted_as_skipped(tmp_path):
    _write(tmp_path / "keep.py", f'key = "{AWS_ACCESS}"\n')
    _write(tmp_path / "skipme.py", f'key = "{AWS_ACCESS}"\n')

    findings, stats, _ = secrets.scan_target(str(tmp_path), exclude=("skipme",))
    assert [finding.file for finding in findings] == ["keep.py"]
    assert stats["files_scanned"] == 1
    assert stats["files_skipped"] == 1


def test_binary_files_are_skipped(tmp_path):
    (tmp_path / "blob.bin").write_bytes(
        f'key = "{AWS_ACCESS}"\n'.encode() + b"\x00\x01\x02"
    )
    _write(tmp_path / "text.py", f'key = "{AWS_ACCESS}"\n')

    findings, stats, errors = secrets.scan_target(str(tmp_path))
    assert [finding.file for finding in findings] == ["text.py"]
    assert stats["files_scanned"] == 1
    assert stats["files_skipped"] == 1
    assert errors == []


def test_size_limit(tmp_path):
    content = f'key = "{AWS_ACCESS}"\n' + "padding\n" * 40
    _write(tmp_path / "big.py", content)

    findings, stats, _ = secrets.scan_target(str(tmp_path), max_file_bytes=64)
    assert findings == []
    assert stats["files_scanned"] == 0
    assert stats["files_skipped"] == 1

    findings, stats, _ = secrets.scan_target(str(tmp_path), max_file_bytes=10_000)
    assert len(findings) == 1
    assert stats["files_scanned"] == 1
    assert stats["files_skipped"] == 0


def test_empty_directory(tmp_path):
    findings, stats, errors = secrets.scan_target(str(tmp_path))
    assert findings == []
    assert errors == []
    assert stats == {
        "files_scanned": 0,
        "files_skipped": 0,
        "findings": 0,
        "rules": 0,
    }


def test_statistics(tmp_path):
    _write(tmp_path / "a.py", f'key = "{AWS_ACCESS}"\n')
    _write(
        tmp_path / "b.py",
        f"github_token = {GITHUB_TOKEN}\ngoogle_key = {GOOGLE_KEY}\n",
    )
    (tmp_path / "binary.dat").write_bytes(b"\x00not really text")

    findings, stats, errors = secrets.scan_target(str(tmp_path))
    assert errors == []
    assert stats["files_scanned"] == 2
    assert stats["files_skipped"] == 1
    assert stats["findings"] == 3
    assert stats["rules"] == 3
    assert stats["findings"] == len(findings)


def test_duplicate_rule_on_same_line_is_collapsed(tmp_path):
    content = (
        f'pair = "{AWS_ACCESS}", "{AWS_ACCESS}"\n'
        f"second = {AWS_ACCESS}\n"
    )
    findings, stats, _ = _single_file(tmp_path, content)

    assert len(findings) == 2
    assert [finding.start_line for finding in findings] == [1, 2]
    assert stats["findings"] == 2


def test_location_is_one_based(tmp_path):
    findings, _, _ = _single_file(tmp_path, f"key = {AWS_ACCESS}\n")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "app.py"
    assert finding.start_line == 1
    assert finding.start_col == 7
    assert finding.end_line == 1
    assert finding.end_col == 7 + len(AWS_ACCESS)
