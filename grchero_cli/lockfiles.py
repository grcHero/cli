"""Find lockfiles and read exact package versions from them. Nothing here touches the network."""

import json
import os
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scope import EXCLUDED_DIRECTORIES, CliError, read_text

SKIPPED_DIRECTORIES = EXCLUDED_DIRECTORIES | {
    "env",
    "vendor",
    "target",
    "bower_components",
    "jspm_packages",
    "site-packages",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".yarn",
    ".pnpm-store",
    ".gradle",
    ".terraform",
    "coverage",
}
MAX_VISITED = 100_000
MAX_LOCKFILES = 200
MAX_LOCKFILE_BYTES = 20 * 1_048_576
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str


@dataclass
class Lockfile:
    path: str
    ecosystem: str
    packages: list[Package]
    unpinned: int = 0


@dataclass
class Inventory:
    lockfiles: list[Lockfile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _npm(name: str, version: str) -> Package | None:
    # Exact registry versions only: skip links, tarball URLs, git and file references.
    if not name or not re.match(r"^\d+\.\d+\.\d+", version):
        return None
    return Package("npm", name, version)


def parse_package_lock(text: str) -> list[Package]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("not an object")
    result: list[Package] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if "node_modules/" not in key or not isinstance(entry, dict) or entry.get("link"):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            package = _npm(str(name), str(entry.get("version", "")))
            if package:
                result.append(package)
        return result

    def walk(tree: Any) -> None:
        if not isinstance(tree, dict):
            return
        for name, entry in tree.items():
            if isinstance(entry, dict):
                package = _npm(str(name), str(entry.get("version", "")))
                if package:
                    result.append(package)
                walk(entry.get("dependencies"))

    walk(data.get("dependencies"))
    return result


def _yarn_name(descriptor: str) -> tuple[str, str]:
    descriptor = descriptor.strip().strip('"')
    at = descriptor.find("@", 1)
    if at < 1:
        raise ValueError("descriptor")
    return descriptor[:at], descriptor[at + 1 :]


def parse_yarn_lock(text: str) -> list[Package]:
    """Yarn v1 (`version "1.2.3"`) and Berry (`version: 1.2.3`) entries."""
    result: list[Package] = []
    name = ""
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            name = ""
            if not line.rstrip().endswith(":") or line.startswith("__metadata"):
                continue
            first = line.rstrip()[:-1].split(",")[0]
            try:
                candidate, reference = _yarn_name(first)
            except ValueError:
                continue
            # Berry marks the protocol; only the npm registry has advisories to match.
            protocol = reference.split(":", 1)[0] if ":" in reference else "npm"
            name = candidate if protocol == "npm" else ""
            continue
        match = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if name and match:
            package = _npm(name, match.group(1))
            if package:
                result.append(package)
            name = ""
    return result


PNPM_KEY = re.compile(
    r"^  '?/?((?:@[^/@\s'()]+/)?[^/@\s'()]+)[@/](\d+\.\d+\.\d+[^()_:'\s]*)'?"
    r"(?:[(_][^:]*)?:(?:\s.*)?$"
)


def parse_pnpm_lock(text: str) -> list[Package]:
    """Package keys under `packages:`/`snapshots:`, e.g. `/name@1.2.3`, `name@1.2.3`."""
    result: list[Package] = []
    section = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section in {"packages", "snapshots"}:
            match = PNPM_KEY.match(line)
            if match:
                package = _npm(match.group(1), match.group(2))
                if package:
                    result.append(package)
    return result


REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(;.*)?$"
)


def parse_requirements(text: str) -> tuple[list[Package], int]:
    """Only `name==version` pins count; every other requirement is reported as unpinned."""
    result: list[Package] = []
    unpinned = 0
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = REQUIREMENT.match(line)
        if match and "*" not in match.group(3):
            result.append(Package("PyPI", match.group(1), match.group(3)))
        else:
            unpinned += 1
    return result, unpinned


def _toml_packages(text: str, ecosystem: str, keep: Callable[[dict[str, Any]], bool]) -> list:
    data = tomllib.loads(text)
    return [
        Package(ecosystem, str(entry["name"]), str(entry["version"]))
        for entry in data.get("package", [])
        if isinstance(entry, dict) and entry.get("name") and entry.get("version") and keep(entry)
    ]


def parse_poetry_lock(text: str) -> list[Package]:
    return _toml_packages(text, "PyPI", lambda entry: True)


def parse_uv_lock(text: str) -> list[Package]:
    def from_index(entry: dict[str, Any]) -> bool:
        source = entry.get("source")
        return not (isinstance(source, dict) and {"editable", "virtual", "path"} & set(source))

    return _toml_packages(text, "PyPI", from_index)


def parse_pipfile_lock(text: str) -> list[Package]:
    data = json.loads(text)
    result: list[Package] = []
    for group in ("default", "develop"):
        section = data.get(group) if isinstance(data, dict) else None
        for name, entry in (section or {}).items():
            version = str(entry.get("version", "")) if isinstance(entry, dict) else ""
            if version.startswith("=="):
                result.append(Package("PyPI", str(name), version[2:]))
    return result


def parse_go_sum(text: str) -> list[Package]:
    """Modules whose content was downloaded; `/go.mod`-only lines were read for the graph only."""
    result: list[Package] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and not parts[1].endswith("/go.mod"):
            result.append(Package("Go", parts[0], parts[1]))
    return result


def parse_cargo_lock(text: str) -> list[Package]:
    return _toml_packages(
        text, "crates.io", lambda entry: str(entry.get("source", "")).startswith("registry+")
    )


def parse_gemfile_lock(text: str) -> list[Package]:
    """The GEM section's specs; GIT and PATH gems are not from the registry."""
    result: list[Package] = []
    section = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.strip()
            continue
        match = re.match(r"^    ([A-Za-z0-9][A-Za-z0-9._-]*) \(([^)\s]+)\)\s*$", line)
        if section == "GEM" and match:
            # Platform gems look like 1.2.3-x86_64-linux; gem versions never contain "-".
            result.append(Package("RubyGems", match.group(1), match.group(2).split("-", 1)[0]))
    return result


def parse_composer_lock(text: str) -> list[Package]:
    data = json.loads(text)
    result: list[Package] = []
    for group in ("packages", "packages-dev"):
        for entry in (data.get(group) if isinstance(data, dict) else None) or []:
            if not isinstance(entry, dict):
                continue
            version = str(entry.get("version", ""))
            version = version[1:] if version[:1] in {"v", "V"} else version
            if entry.get("name") and re.match(r"^\d", version):
                result.append(Package("Packagist", str(entry["name"]), version))
    return result


def parse_nuget_lock(text: str) -> list[Package]:
    data = json.loads(text)
    result: list[Package] = []
    frameworks = data.get("dependencies") if isinstance(data, dict) else None
    for packages in (frameworks or {}).values():
        for name, entry in (packages or {}).items():
            if isinstance(entry, dict) and entry.get("resolved") and entry.get("type") != "Project":
                result.append(Package("NuGet", str(name), str(entry["resolved"])))
    return result


PARSERS: dict[str, tuple[str, Callable[[str], list[Package]]]] = {
    "package-lock.json": ("npm", parse_package_lock),
    "npm-shrinkwrap.json": ("npm", parse_package_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock),
    "poetry.lock": ("PyPI", parse_poetry_lock),
    "uv.lock": ("PyPI", parse_uv_lock),
    "Pipfile.lock": ("PyPI", parse_pipfile_lock),
    "go.sum": ("Go", parse_go_sum),
    "Cargo.lock": ("crates.io", parse_cargo_lock),
    "Gemfile.lock": ("RubyGems", parse_gemfile_lock),
    "composer.lock": ("Packagist", parse_composer_lock),
    "packages.lock.json": ("NuGet", parse_nuget_lock),
}


def is_requirements(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _printable(path: str) -> str:
    return "".join(character for character in path if ord(character) >= 32)[:300]


def _has_npm_lock(directory: Path, root: Path) -> bool:
    """A workspace package is covered by a lockfile in any folder up to the project root."""
    current = directory
    while True:
        if any((current / name).is_file() for name in NPM_LOCKS):
            return True
        if current == root or root not in current.parents:
            return False
        current = current.parent


def read_lockfile(file: Path, relative: str) -> Lockfile:
    if file.stat().st_size > MAX_LOCKFILE_BYTES:
        raise CliError(f"{relative} is larger than 20 MiB.")
    text = read_text(file, MAX_LOCKFILE_BYTES)
    if is_requirements(file.name):
        packages, unpinned = parse_requirements(text)
        return Lockfile(relative, "PyPI", packages, unpinned)
    ecosystem, parse = PARSERS[file.name]
    return Lockfile(relative, ecosystem, parse(text))


def discover(root: Path) -> Inventory:
    """Walk the project like `scan` does: no symlinks, no dependency folders, bounded reads."""
    inventory = Inventory()
    visited = 0

    def walk_error(error: OSError) -> None:
        raise CliError(
            "Cannot read a project folder. Check permissions or choose a smaller folder."
        )

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        here = Path(directory)
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in SKIPPED_DIRECTORIES and not (here / name).is_symlink()
        )
        for name in sorted(names):
            visited += 1
            if visited > MAX_VISITED:
                raise CliError("Project exceeds the 100,000-file limit. Choose a smaller folder.")
            file = here / name
            relative = _printable(file.relative_to(root).as_posix())
            if file.is_symlink() or not file.is_file():
                continue
            if name == "package.json" and not _has_npm_lock(here, root):
                inventory.notes.append(f"{relative}: no lockfile, versions unknown. Skipped.")
                continue
            if name not in PARSERS and not is_requirements(name):
                continue
            if len(inventory.lockfiles) >= MAX_LOCKFILES:
                raise CliError("More than 200 lockfiles found. Choose a smaller folder.")
            try:
                lockfile = read_lockfile(file, relative)
            except CliError as cause:
                inventory.notes.append(f"{relative}: skipped. {cause}")
                continue
            except (OSError, UnicodeError, ValueError, TypeError, AttributeError, KeyError):
                inventory.notes.append(f"{relative}: could not be read as a lockfile. Skipped.")
                continue
            if lockfile.unpinned:
                inventory.notes.append(
                    f"{relative}: {lockfile.unpinned} requirement(s) without an exact == pin "
                    "were not checked."
                )
            inventory.lockfiles.append(lockfile)
    return inventory
