"""Local version ordering and OSV range semantics."""

import pytest

from grchero_cli.versions import (
    AFFECTED,
    NOT_AFFECTED,
    UNKNOWN,
    compare_generic,
    compare_pep440,
    compare_semver,
    evaluate,
    in_range,
    lowest_fix,
)


def ascending(compare, versions: list[str]) -> None:
    for lower, higher in zip(versions, versions[1:], strict=False):
        assert compare(lower, higher) < 0, (lower, higher)
        assert compare(higher, lower) > 0, (higher, lower)


def test_semver_ordering_including_prereleases() -> None:
    # The SemVer 2.0 specification's own example order.
    ascending(
        compare_semver,
        [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.10.0",
            "2.0.0",
        ],
    )
    assert compare_semver("v1.2.3", "1.2.3") == 0  # Go modules carry a leading v
    assert compare_semver("1.2.3+build.5", "1.2.3") == 0
    assert compare_semver("v2.0.0+incompatible", "v1.9.9") > 0
    assert compare_semver("v0.0.0-20210101000000-abcdef123456", "v0.0.1") < 0
    with pytest.raises(ValueError):
        compare_semver("not-a-version", "1.0.0")


def test_pep440_ordering() -> None:
    ascending(
        compare_pep440,
        [
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0+local.1",
            "1.0.post1.dev1",
            "1.0.post1",
            "1.0.1",
            "1.1",
            "2!0.1",
        ],
    )
    assert compare_pep440("1.0", "1.0.0") == 0
    assert compare_pep440("1.0-1", "1.0.post1") == 0
    assert compare_pep440("1.0c1", "1.0rc1") == 0
    assert compare_pep440("1.0.ALPHA1", "1.0a1") == 0
    with pytest.raises(ValueError):
        compare_pep440("latest", "1.0")


def test_generic_ordering() -> None:
    ascending(compare_generic, ["1.0.0.a", "1.0.0.rc1", "1.0.0", "1.0.1", "1.2", "1.10"])
    assert compare_generic("1.0", "1.0.0") == 0
    assert compare_generic("v2.3.0", "2.3.0") == 0
    assert compare_generic("12.0.1", "13.0.1") < 0
    with pytest.raises(ValueError):
        compare_generic("dev-main", "1.0")


def events(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{kind: value} for kind, value in pairs]


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.0.1", AFFECTED), ("1.2.2", AFFECTED), ("1.2.3", NOT_AFFECTED), ("2.0.0", NOT_AFFECTED)],
)
def test_introduced_zero_until_fixed(version: str, expected: str) -> None:
    rng = events(("introduced", "0"), ("fixed", "1.2.3"))
    assert in_range(version, rng, compare_semver) == expected


def test_last_affected_is_inclusive() -> None:
    rng = events(("introduced", "1.0.0"), ("last_affected", "1.4.0"))
    assert in_range("0.9.0", rng, compare_semver) == NOT_AFFECTED
    assert in_range("1.4.0", rng, compare_semver) == AFFECTED
    assert in_range("1.4.1", rng, compare_semver) == NOT_AFFECTED


def test_several_introduced_windows_in_any_order() -> None:
    rng = events(
        ("fixed", "2.5.0"),
        ("introduced", "2.0.0"),
        ("introduced", "1.0.0"),
        ("fixed", "1.5.0"),
    )
    assert in_range("1.2.0", rng, compare_semver) == AFFECTED
    assert in_range("1.7.0", rng, compare_semver) == NOT_AFFECTED
    assert in_range("2.1.0", rng, compare_semver) == AFFECTED
    assert in_range("3.0.0", rng, compare_semver) == NOT_AFFECTED
    assert in_range("2.0.0-rc.1", rng, compare_semver) == NOT_AFFECTED


def test_limit_bounds_the_range() -> None:
    rng = events(("introduced", "0"), ("limit", "2.0.0"))
    assert in_range("1.0.0", rng, compare_semver) == AFFECTED
    assert in_range("2.0.0", rng, compare_semver) == NOT_AFFECTED


def test_uncomparable_versions_are_unknown_not_dropped() -> None:
    rng = events(("introduced", "0"), ("fixed", "1.0.0"))
    assert in_range("weird", rng, compare_semver) == UNKNOWN
    advisory = {"ranges": [{"type": "ECOSYSTEM", "events": rng}], "versions": []}
    assert evaluate("PyPI", "latest-and-greatest", advisory) == UNKNOWN


def test_evaluate_uses_versions_ranges_and_ignores_git() -> None:
    advisory = {
        "versions": ["0.9.0"],
        "ranges": [
            {"type": "GIT", "events": events(("introduced", "abc"), ("fixed", "def"))},
            {"type": "ECOSYSTEM", "events": events(("introduced", "2.0"), ("fixed", "2.0.3"))},
        ],
    }
    assert evaluate("PyPI", "0.9.0", advisory) == AFFECTED
    assert evaluate("PyPI", "2.0.1", advisory) == AFFECTED
    assert evaluate("PyPI", "2.0.3", advisory) == NOT_AFFECTED
    assert evaluate("PyPI", "2.0.3rc1", advisory) == AFFECTED
    only_git = {"versions": [], "ranges": [advisory["ranges"][0]]}
    assert evaluate("PyPI", "1.0", only_git) == UNKNOWN
    only_versions = {"versions": ["1.0"], "ranges": []}
    assert evaluate("PyPI", "1.1", only_versions) == NOT_AFFECTED


def test_ruby_and_nuget_use_generic_ordering() -> None:
    advisory = {
        "ranges": [
            {"type": "ECOSYSTEM", "events": events(("introduced", "0"), ("fixed", "1.13.4"))}
        ]
    }
    assert evaluate("RubyGems", "1.13.0", advisory) == AFFECTED
    assert evaluate("RubyGems", "1.13.10", advisory) == NOT_AFFECTED
    assert evaluate("NuGet", "1.13.4.1", advisory) == NOT_AFFECTED


def test_lowest_fix_above_current() -> None:
    advisory = {
        "fixed": ["4.17.21", "3.10.2"],
        "ranges": [
            {
                "type": "SEMVER",
                "events": events(
                    ("introduced", "0"),
                    ("fixed", "3.10.2"),
                    ("introduced", "4.0.0"),
                    ("fixed", "4.17.21"),
                ),
            }
        ],
    }
    assert lowest_fix("npm", "4.17.20", advisory) == "4.17.21"
    assert lowest_fix("npm", "3.0.0", advisory) == "3.10.2"
    assert lowest_fix("npm", "5.0.0", advisory) is None
