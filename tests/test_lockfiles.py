"""Lockfile parsers read exact versions only, and discovery keeps scan's safety rules."""

import json
import os
from pathlib import Path

import pytest

from grchero_cli.lockfiles import (
    Package,
    discover,
    parse_cargo_lock,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_sum,
    parse_nuget_lock,
    parse_package_lock,
    parse_pipfile_lock,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
    parse_yarn_lock,
)

PACKAGE_LOCK_V3 = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/@babel/core": {"version": "7.20.0"},
            "node_modules/a/node_modules/minimist": {"version": "0.0.8"},
            "node_modules/alias": {"name": "real-name", "version": "2.0.0"},
            "node_modules/local": {"link": True, "resolved": "packages/local"},
            "node_modules/from-git": {"version": "git+https://example.com/x.git"},
            "packages/local": {"version": "0.1.0"},
        },
    }
)
PACKAGE_LOCK_V1 = json.dumps(
    {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.17.1",
                "dependencies": {"qs": {"version": "6.7.0"}},
            },
            "tarball": {"version": "https://example.com/t.tgz"},
        },
    }
)
YARN_V1 = """# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz"

lodash@^4.17.20:
  version "4.17.20"
"""
YARN_BERRY = """__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
"""
PNPM = """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20

packages:
  '@babel/core@7.20.0':
    resolution: {integrity: sha512-x}
  lodash@4.17.20: {}
    resolution: {integrity: sha512-y}
  /left-pad@1.3.0:
    resolution: {integrity: sha512-z}
  /old-style/2.0.1:
    resolution: {integrity: sha512-w}

snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
"""
REQUIREMENTS = """# pinned
Django==4.2.1  # via app
requests[socks]==2.31.0 ; python_version >= "3.8"
urllib3==2.0.0 \\
    --hash=sha256:abc
flask>=2.0
numpy
pkg==1.*
-r other.txt
"""
POETRY = """[[package]]
name = "Jinja2"
version = "3.1.2"

[[package]]
name = "requests"
version = "2.31.0"
"""
UV = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "pyyaml"
version = "6.0.1"
source = { registry = "https://pypi.org/simple" }
"""
PIPFILE = json.dumps(
    {
        "default": {"django": {"version": "==3.2.0"}},
        "develop": {"pytest": {"version": "==7.0.0"}, "editable": {"path": "."}},
    }
)
GO_SUM = """golang.org/x/text v0.3.7 h1:abc=
golang.org/x/text v0.3.7/go.mod h1:def=
golang.org/x/text v0.3.0/go.mod h1:ghi=
github.com/gin-gonic/gin v1.7.0 h1:jkl=
"""
CARGO = """version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde_json"
version = "1.0.80"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "private"
version = "0.2.0"
source = "git+https://example.com/private#abc"
"""
GEMFILE = """GIT
  remote: https://example.com/gem.git
  specs:
    private (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.0-x86_64-linux)
      racc (~> 1.4)
    rails (7.0.4)

PLATFORMS
  ruby
"""
COMPOSER = json.dumps(
    {
        "packages": [
            {"name": "Monolog/Monolog", "version": "v2.3.0"},
            {"name": "acme/dev-branch", "version": "dev-main"},
        ],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}],
    }
)
NUGET = json.dumps(
    {
        "version": 1,
        "dependencies": {
            "net6.0": {
                "Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"},
                "MyLib": {"type": "Project"},
            }
        },
    }
)

FIXTURES = {
    "web/package-lock.json": PACKAGE_LOCK_V3,
    "legacy/npm-shrinkwrap.json": PACKAGE_LOCK_V1,
    "yarn1/yarn.lock": YARN_V1,
    "berry/yarn.lock": YARN_BERRY,
    "pnpm/pnpm-lock.yaml": PNPM,
    "py/requirements-dev.txt": REQUIREMENTS,
    "py/poetry.lock": POETRY,
    "uv/uv.lock": UV,
    "pipenv/Pipfile.lock": PIPFILE,
    "go/go.sum": GO_SUM,
    "rust/Cargo.lock": CARGO,
    "ruby/Gemfile.lock": GEMFILE,
    "php/composer.lock": COMPOSER,
    "dotnet/packages.lock.json": NUGET,
}


def write_fixtures(root: Path) -> None:
    for relative, content in FIXTURES.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def names(packages: list[Package]) -> set[tuple[str, str]]:
    return {(package.name, package.version) for package in packages}


def test_package_lock_v3_reads_installed_registry_packages() -> None:
    assert names(parse_package_lock(PACKAGE_LOCK_V3)) == {
        ("lodash", "4.17.20"),
        ("@babel/core", "7.20.0"),
        ("minimist", "0.0.8"),
        ("real-name", "2.0.0"),
    }


def test_package_lock_v1_walks_the_dependency_tree() -> None:
    assert names(parse_package_lock(PACKAGE_LOCK_V1)) == {("express", "4.17.1"), ("qs", "6.7.0")}


def test_yarn_v1_and_berry() -> None:
    assert names(parse_yarn_lock(YARN_V1)) == {
        ("@babel/code-frame", "7.12.13"),
        ("lodash", "4.17.20"),
    }
    assert names(parse_yarn_lock(YARN_BERRY)) == {("lodash", "4.17.21")}


def test_pnpm_keys_in_every_format() -> None:
    assert names(parse_pnpm_lock(PNPM)) == {
        ("@babel/core", "7.20.0"),
        ("lodash", "4.17.20"),
        ("left-pad", "1.3.0"),
        ("old-style", "2.0.1"),
        ("react-dom", "18.2.0"),
    }


def test_requirements_keep_only_exact_pins() -> None:
    packages, unpinned = parse_requirements(REQUIREMENTS)
    assert names(packages) == {
        ("Django", "4.2.1"),
        ("requests", "2.31.0"),
        ("urllib3", "2.0.0"),
    }
    assert unpinned == 3


def test_python_lockfiles() -> None:
    assert names(parse_poetry_lock(POETRY)) == {("Jinja2", "3.1.2"), ("requests", "2.31.0")}
    assert names(parse_uv_lock(UV)) == {("pyyaml", "6.0.1")}
    assert names(parse_pipfile_lock(PIPFILE)) == {("django", "3.2.0"), ("pytest", "7.0.0")}


def test_go_sum_keeps_downloaded_modules() -> None:
    assert names(parse_go_sum(GO_SUM)) == {
        ("golang.org/x/text", "v0.3.7"),
        ("github.com/gin-gonic/gin", "v1.7.0"),
    }


def test_cargo_gemfile_composer_nuget() -> None:
    assert names(parse_cargo_lock(CARGO)) == {("serde_json", "1.0.80")}
    assert names(parse_gemfile_lock(GEMFILE)) == {("nokogiri", "1.13.0"), ("rails", "7.0.4")}
    assert names(parse_composer_lock(COMPOSER)) == {
        ("Monolog/Monolog", "2.3.0"),
        ("phpunit/phpunit", "9.5.0"),
    }
    assert names(parse_nuget_lock(NUGET)) == {("Newtonsoft.Json", "12.0.1")}


def test_discover_finds_every_format_and_skips_unsafe_places(tmp_path: Path) -> None:
    write_fixtures(tmp_path)
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package-lock.json").write_text(PACKAGE_LOCK_V3)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "composer.lock").write_text(COMPOSER)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "Cargo.lock").write_text(CARGO)
    os.symlink(outside, tmp_path / "linked")
    os.symlink(outside / "Cargo.lock", tmp_path / "ruby" / "Cargo.lock")
    (tmp_path / "web" / "packages" / "ui").mkdir(parents=True)
    (tmp_path / "web" / "packages" / "ui" / "package.json").write_text("{}")
    (tmp_path / "loose").mkdir()
    (tmp_path / "loose" / "package.json").write_text("{}")
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "composer.lock").write_text("{not json")

    inventory = discover(tmp_path)

    assert sorted(item.path for item in inventory.lockfiles) == sorted(FIXTURES)
    notes = "\n".join(inventory.notes)
    assert "loose/package.json: no lockfile, versions unknown. Skipped." in notes
    # A workspace package is covered by the lockfile further up.
    assert "web/packages/ui/package.json" not in notes
    assert "broken/composer.lock: could not be read as a lockfile. Skipped." in notes
    assert "py/requirements-dev.txt: 3 requirement(s) without an exact == pin" in notes


def test_discover_rejects_oversized_lockfiles(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("grchero_cli.lockfiles.MAX_LOCKFILE_BYTES", 10)
    (tmp_path / "go.sum").write_text(GO_SUM)
    inventory = discover(tmp_path)
    assert inventory.lockfiles == []
    assert inventory.notes == ["go.sum: skipped. go.sum is larger than 20 MiB."]


@pytest.mark.parametrize("name", ["package.json", "go.mod"])
def test_manifest_alone_is_never_guessed(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("{}")
    assert discover(tmp_path).lockfiles == []
