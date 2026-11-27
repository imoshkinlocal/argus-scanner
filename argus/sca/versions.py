"""Best-effort version comparison used for offline OSV matching.

Semantic versioning is not universal: Maven has qualifiers, Python has PEP 440
pre/post releases, Go uses pseudo versions, RubyGems uses letter suffixes.
The comparator below is deliberately forgiving and follows the rules that
matter for vulnerability range checks:

* numeric components compare numerically;
* well known pre-release markers (alpha/beta/rc/snapshot/dev) sort before the
  final release, post markers (post/rev/update/patch) sort after it;
* a longer version with a trailing pre-release marker is *older* than the
  shorter release version ("1.0.0-rc1" < "1.0.0");
* unknown trailing strings compare lexicographically.
"""

from __future__ import annotations

import functools
import re
from typing import List, Optional, Tuple

_TOKEN_RE = re.compile(r"[0-9]+|[A-Za-z]+")

_PRE_RANK = {
    "dev": -6,
    "snapshot": -5,
    "alpha": -4,
    "a": -4,
    "beta": -3,
    "b": -3,
    "milestone": -3,
    "m": -3,
    "rc": -2,
    "cr": -2,
    "pre": -2,
    "preview": -2,
}
_POST_RANK = {
    "post": 2,
    "rev": 2,
    "r": 2,
    "update": 1,
    "patch": 1,
    "sp": 1,
}
_NEUTRAL = {"final", "ga", "release", "stable", ""}


def _split_epoch(version: str) -> Tuple[int, str]:
    match = re.match(r"^(\d+):(.+)$", version)
    if match:
        return int(match.group(1)), match.group(2)
    return 0, version


def normalize(version: str) -> str:
    """Strip common decorations (purl prefixes, leading v, build metadata)."""
    text = str(version).strip()
    text = text.strip("'\"")
    if text.lower().startswith("version "):
        text = text[8:].strip()
    text = re.sub(r"^[vV](?=\d)", "", text)
    text = text.split("+", 1)[0]  # build metadata is not ordered
    return text


def _tokens(version: str) -> List[str]:
    return _TOKEN_RE.findall(version)


def _is_trailing_zero(tokens: List[str]) -> bool:
    """True when the remaining tokens add no ordering value ("1.0" vs "1.0.0")."""
    return all(token == "0" or token in _NEUTRAL for token in tokens)


def _is_pre(token: str) -> bool:
    return token.lower() in _PRE_RANK


def _is_post(token: str) -> bool:
    return token.lower() in _POST_RANK


# --------------------------------------------------------------------------- Debian

def _deb_split(version: str) -> Tuple[int, str, str]:
    """Split ``[epoch:]upstream[-revision]`` using the Debian version rules."""
    text = version.strip()
    epoch = 0
    head, separator, rest = text.partition(":")
    if separator and head.isdigit():
        epoch, text = int(head), rest
    if "-" in text:
        upstream, revision = text.rsplit("-", 1)
    else:
        upstream, revision = text, "0"
    return epoch, upstream, revision


def _deb_order(char: str) -> int:
    """Character weight from Debian policy 5.6.12 (``~`` sorts before empty)."""
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha() and char.isascii():
        return ord(char)
    if not char:
        return 0
    return ord(char) + 256


def _deb_cmp_part(left: str, right: str) -> int:
    """Compare one upstream/revision component the way dpkg does."""
    i = j = 0
    while i < len(left) or j < len(right):
        # Non-digit runs: compare character by character, end of string is 0.
        while ((i < len(left) and not left[i].isdigit())
               or (j < len(right) and not right[j].isdigit())):
            l_char = left[i] if i < len(left) and not left[i].isdigit() else ""
            r_char = right[j] if j < len(right) and not right[j].isdigit() else ""
            l_order, r_order = _deb_order(l_char), _deb_order(r_char)
            if l_order != r_order:
                return -1 if l_order < r_order else 1
            if l_char:
                i += 1
            if r_char:
                j += 1
        # Digit runs: skip leading zeros, then compare length and value.
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        start_left, start_right = i, j
        while i < len(left) and left[i].isdigit():
            i += 1
        while j < len(right) and right[j].isdigit():
            j += 1
        length_left, length_right = i - start_left, j - start_right
        if length_left != length_right:
            return -1 if length_left < length_right else 1
        if left[start_left:i] != right[start_right:j]:
            return -1 if left[start_left:i] < right[start_right:j] else 1
    return 0


def _deb_compare(left: str, right: str) -> int:
    l_epoch, l_upstream, l_revision = _deb_split(left)
    r_epoch, r_upstream, r_revision = _deb_split(right)
    if l_epoch != r_epoch:
        return -1 if l_epoch < r_epoch else 1
    upstream = _deb_cmp_part(l_upstream, r_upstream)
    if upstream:
        return upstream
    return _deb_cmp_part(l_revision, r_revision)


def compare(left: str, right: str, ecosystem: str = "") -> int:
    """Return -1, 0 or 1 when ``left`` is older, equal or newer than ``right``."""
    if str(ecosystem).lower() == "debian":
        return _deb_compare(str(left), str(right))
    if left == right:
        return 0
    l_epoch, l_ver = _split_epoch(normalize(left))
    r_epoch, r_ver = _split_epoch(normalize(right))
    if l_epoch != r_epoch:
        return -1 if l_epoch < r_epoch else 1

    # Fast path: identical after normalisation.
    if l_ver.lower() == r_ver.lower():
        return 0

    l_tokens = _tokens(l_ver.lower())
    r_tokens = _tokens(r_ver.lower())
    index = 0
    while index < len(l_tokens) and index < len(r_tokens):
        l_token, r_token = l_tokens[index], r_tokens[index]
        if l_token.isdigit() and r_token.isdigit():
            l_num, r_num = int(l_token), int(r_token)
            if l_num != r_num:
                return -1 if l_num < r_num else 1
        elif l_token.isdigit() != r_token.isdigit():
            alpha_token = r_token if l_token.isdigit() else l_token
            numeric_left = l_token.isdigit()
            if _is_pre(alpha_token):
                # 1.0 > 1.0rc1
                return 1 if numeric_left else -1
            if _is_post(alpha_token):
                return -1 if numeric_left else 1
            # Unknown suffix: numbers win over plain words.
            return 1 if numeric_left else -1
        else:
            l_rank = _PRE_RANK.get(l_token)
            r_rank = _PRE_RANK.get(r_token)
            if l_rank is not None or r_rank is not None:
                l_rank = l_rank if l_rank is not None else 0
                r_rank = r_rank if r_rank is not None else 0
                if l_rank != r_rank:
                    return -1 if l_rank < r_rank else 1
            l_post = _POST_RANK.get(l_token)
            r_post = _POST_RANK.get(r_token)
            if l_post is not None or r_post is not None:
                l_post = l_post if l_post is not None else 0
                r_post = r_post if r_post is not None else 0
                if l_post != r_post:
                    return -1 if l_post < r_post else 1
            if l_token != r_token:
                if l_token in _NEUTRAL or r_token in _NEUTRAL:
                    # "1.0" vs "1.0final" -> equal by convention.
                    continue
                return -1 if l_token < r_token else 1
        index += 1

    if index < len(l_tokens) and _is_trailing_zero(l_tokens[index:]):
        return 0
    if index < len(r_tokens) and _is_trailing_zero(r_tokens[index:]):
        return 0

    if index < len(l_tokens):
        rest = l_tokens[index:]
        if rest and _is_pre(rest[0]):
            return -1
        if rest and _is_post(rest[0]):
            return 1
        return 1
    if index < len(r_tokens):
        rest = r_tokens[index:]
        if rest and _is_pre(rest[0]):
            return 1
        if rest and _is_post(rest[0]):
            return -1
        return -1
    return 0


def lt(left: str, right: str, ecosystem: str = "") -> bool:
    return compare(left, right, ecosystem) < 0


def lte(left: str, right: str, ecosystem: str = "") -> bool:
    return compare(left, right, ecosystem) <= 0


def _event_bounds(events: List[dict], ecosystem: str) -> List[Tuple[Optional[str], Optional[str]]]:
    """Translate OSV range events into [introduced, upper) intervals."""
    intervals: List[Tuple[Optional[str], Optional[str]]] = []
    introduced: Optional[str] = None
    open_interval = False
    for event in events:
        if "introduced" in event:
            value = str(event["introduced"])
            introduced = None if value == "0" else value
            open_interval = True
        elif "fixed" in event:
            intervals.append((introduced, str(event["fixed"])))
            introduced = None
            open_interval = False
        elif "last_affected" in event:
            intervals.append((introduced, str(event["last_affected"])))
            introduced = None
            open_interval = False
        elif "limit" in event:
            intervals.append((introduced, str(event["limit"])))
            introduced = None
            open_interval = False
    if open_interval:
        intervals.append((introduced, None))
    return intervals


def range_contains(
    version: str,
    events: List[dict],
    ecosystem: str = "",
    inclusive_last: bool = False,
) -> bool:
    """Check whether ``version`` falls into an OSV range described by ``events``."""
    for lower, upper in _event_bounds(events, ecosystem):
        lower_ok = lower is None or compare(version, lower, ecosystem) >= 0
        if not lower_ok:
            continue
        if upper is None:
            return True
        cmp = compare(version, upper, ecosystem)
        if inclusive_last:
            if cmp <= 0:
                return True
        elif cmp < 0:
            return True
    return False


def fixed_version_for(
    version: str,
    affected: dict,
    ecosystem: str = "",
) -> str:
    """Return the smallest fix version that is newer than ``version``."""
    candidates: List[str] = []
    for item in affected.get("ranges", []) or []:
        if item.get("type") not in ("ECOSYSTEM", "SEMVER", ""):
            continue
        events = item.get("events") or []
        introduced: Optional[str] = None
        for event in events:
            if "introduced" in event:
                value = str(event["introduced"])
                introduced = None if value == "0" else value
            elif "fixed" in event:
                fixed = str(event["fixed"])
                if introduced is not None:
                    in_range = compare(version, introduced, ecosystem) >= 0
                else:
                    in_range = True
                if in_range and compare(version, fixed, ecosystem) < 0:
                    candidates.append(fixed)
                introduced = None
    if not candidates:
        return ""
    candidates.sort(key=functools.cmp_to_key(lambda a, b: compare(a, b, ecosystem)))
    return candidates[0]
