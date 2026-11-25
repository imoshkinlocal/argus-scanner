"""Version comparison and OSV range matching."""

from __future__ import annotations

import pytest

from argus.sca import versions


@pytest.mark.parametrize("left,right,expected", [
    ("1.0", "1.0.0", 0),
    ("1.0.1", "1.0", 1),
    ("4.17.15", "4.17.21", -1),
    ("1.0.0-alpha", "1.0.0", -1),
    ("1.0.0", "1.0.0-rc1", 1),
    ("2.0.6", "2.1", -1),
    ("10.0", "9.9", 1),
    ("v5.2.17", "5.2.17", 0),
])
def test_compare(left, right, expected):
    assert versions.compare(left, right) == expected


def test_semver_build_metadata():
    assert versions.compare("1.2.3+build1", "1.2.3", "npm") == 0


def test_range_contains_introduced_fixed():
    events = [{"introduced": "2.0.0"}, {"fixed": "2.17.1"}]
    assert versions.range_contains("2.14.1", events)
    assert not versions.range_contains("2.17.1", events)
    assert not versions.range_contains("1.9.0", events)


def test_range_contains_open_ended():
    events = [{"introduced": "0"}]
    assert versions.range_contains("4.17.15", events)


def test_range_contains_last_affected():
    events = [{"introduced": "1.0"}, {"last_affected": "1.4.2"}]
    assert versions.range_contains("1.4.2", events, inclusive_last=True)
    assert not versions.range_contains("1.4.3", events, inclusive_last=True)


def test_fixed_version_for_picks_earliest_upper_bound():
    affected = {
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "3.0"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.5"}]},
        ]
    }
    assert versions.fixed_version_for("1.2", affected) == "2.5"


def test_fixed_version_for_without_ranges():
    assert versions.fixed_version_for("1.0", {}) == ""
