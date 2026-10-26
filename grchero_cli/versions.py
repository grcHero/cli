"""Version ordering and OSV range evaluation, all local. Unknown formats raise ValueError."""

import re
from collections.abc import Callable
from functools import cmp_to_key
from typing import Any

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNKNOWN = "unknown"

Comparator = Callable[[str, str], int]

SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
PEP440 = re.compile(
    r"^v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$",
    re.IGNORECASE,
)
PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
# Sentinels that sort below and above every real value, as in PEP 440's own ordering.
LOW: tuple[int, ...] = (0,)
HIGH: tuple[int, ...] = (2,)


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


def _semver_key(version: str) -> tuple[Any, ...]:
    match = SEMVER.match(version.strip())
    if not match:
        raise ValueError(version)
    release = tuple(int(part or 0) for part in match.group(1, 2, 3))
    pre = match.group(4)
    if pre is None:
        return (release, (1,))
    # Numeric identifiers sort below alphanumeric ones; a shorter equal prefix sorts first.
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")
    )
    return (release, (0, identifiers))


def compare_semver(left: str, right: str) -> int:
    first, second = _semver_key(left), _semver_key(right)
    return _sign((first > second) - (first < second))


def _pep440_key(version: str) -> tuple[Any, ...]:
    match = PEP440.match(version.strip())
    if not match:
        raise ValueError(version)
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_l, dev_l = match.group("pre_l"), match.group("dev_l")
    post = match.group("post_n1") or (
        (match.group("post_n2") or "0") if match.group("post_l") else None
    )
    dev = (match.group("dev_n") or "0") if dev_l else None
    if pre_l:
        pre: tuple[int, ...] = (1, PRE_RANK[pre_l.lower()], int(match.group("pre_n") or 0))
    elif post is None and dev is not None:
        pre = LOW  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = HIGH
    local = match.group("local")
    local_key = (
        tuple(
            (1, int(part), "") if part.isdigit() else (0, 0, part.lower())
            for part in re.split(r"[-_.]", local)
        )
        if local
        else ()
    )
    return (
        int(match.group("epoch") or 0),
        tuple(release),
        pre,
        LOW if post is None else (1, int(post)),
        HIGH if dev is None else (1, int(dev)),
        local_key,
    )


def compare_pep440(left: str, right: str) -> int:
    first, second = _pep440_key(left), _pep440_key(right)
    return (first > second) - (first < second)


def _chunks(version: str) -> list[str]:
    text = version.strip()
    if text[:1] in {"v", "V"} and text[1:2].isdigit():
        text = text[1:]
    chunks = re.findall(r"\d+|[A-Za-z]+", text)
    if not any(chunk.isdigit() for chunk in chunks):
        raise ValueError(version)
    return chunks


def compare_generic(left: str, right: str) -> int:
    """Fallback ordering: numbers numerically, letters below numbers and below a missing chunk.

    So 1.0 == 1.0.0, 1.0.a < 1.0 < 1.0.1, which matches most prerelease conventions.
    """
    first, second = _chunks(left), _chunks(right)
    for index in range(max(len(first), len(second))):
        a = first[index] if index < len(first) else None
        b = second[index] if index < len(second) else None
        if a == b:
            continue
        if a is None or b is None:
            other = b if a is None else a
            # A missing chunk equals zero; letters after it mark a prerelease, so they sort lower.
            result = (0 if int(other) == 0 else -1) if other.isdigit() else 1
            if result:
                return result if a is None else -result
            continue
        if a.isdigit() and b.isdigit():
            if int(a) != int(b):
                return _sign(int(a) - int(b))
        elif a.isdigit() != b.isdigit():
            return 1 if a.isdigit() else -1
        elif a.lower() != b.lower():
            return 1 if a.lower() > b.lower() else -1
    return 0


def comparator(ecosystem: str, range_type: str) -> Comparator:
    if ecosystem == "PyPI" and range_type != "SEMVER":
        return compare_pep440
    if range_type == "SEMVER" or ecosystem in {"npm", "Go", "crates.io"}:
        return compare_semver
    return compare_generic


def _event_version(event: dict[str, Any]) -> tuple[str, str]:
    for kind in ("introduced", "fixed", "last_affected", "limit"):
        if kind in event:
            return kind, str(event[kind])
    raise ValueError("event")


def in_range(version: str, events: list[Any], compare: Comparator) -> str:
    """OSV evaluation: walk sorted events, opening at introduced and closing at fixed."""
    parsed = [_event_version(event) for event in events if isinstance(event, dict)]
    if not parsed:
        return UNKNOWN

    def order(left: tuple[str, str], right: tuple[str, str]) -> int:
        if left[1] == right[1]:
            return 0
        if left[1] == "0" or right[1] == "*":
            return -1
        if right[1] == "0" or left[1] == "*":
            return 1
        return compare(left[1], right[1])

    try:
        limits = [value for kind, value in parsed if kind == "limit"]
        if limits and not any(value == "*" or compare(version, value) < 0 for value in limits):
            return NOT_AFFECTED
        affected = False
        for kind, value in sorted(parsed, key=cmp_to_key(order)):
            if kind == "introduced" and (value == "0" or compare(version, value) >= 0):
                affected = True
            elif kind == "fixed" and compare(version, value) >= 0:
                affected = False
            elif kind == "last_affected":
                affected = affected and compare(version, value) <= 0
    except ValueError:
        return UNKNOWN
    return AFFECTED if affected else NOT_AFFECTED


def evaluate(ecosystem: str, version: str, advisory: dict[str, Any]) -> str:
    """Affected, not affected, or unknown when the data cannot be compared with this version."""
    listed = advisory.get("versions")
    if isinstance(listed, list) and version in {str(item) for item in listed}:
        return AFFECTED
    ranges = [
        item
        for item in advisory.get("ranges") or []
        if isinstance(item, dict) and item.get("type") != "GIT"
    ]
    if not ranges:
        # Only explicit versions (or only Git commits): an unlisted version is not affected
        # when a version list exists; with no usable data at all, say so instead of guessing.
        return NOT_AFFECTED if isinstance(listed, list) and listed else UNKNOWN
    outcome = NOT_AFFECTED
    for item in ranges:
        events = item.get("events")
        result = (
            in_range(version, events, comparator(ecosystem, str(item.get("type"))))
            if isinstance(events, list)
            else UNKNOWN
        )
        if result == AFFECTED:
            return AFFECTED
        if result == UNKNOWN:
            outcome = UNKNOWN
    return outcome


def lowest_fix(ecosystem: str, version: str, advisory: dict[str, Any]) -> str | None:
    """The smallest fixed version above the current one, when the data allows comparison."""
    candidates = {str(item) for item in advisory.get("fixed") or [] if item}
    for item in advisory.get("ranges") or []:
        if isinstance(item, dict) and item.get("type") != "GIT":
            for event in item.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    candidates.add(str(event["fixed"]))
    compare = comparator(ecosystem, "ECOSYSTEM")
    above = []
    for candidate in candidates:
        try:
            if compare(candidate, version) > 0:
                above.append(candidate)
        except ValueError:
            continue
    if not above:
        return None
    return sorted(above, key=cmp_to_key(compare))[0]
