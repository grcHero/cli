"""`grchero deps`: match locked package versions against advisories without revealing them.

Only 4-hex-character prefixes of sha256(normalized package name) leave this machine. grcHero
returns every advisory in those buckets; names and versions are matched here.
"""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .auth import _request, load_credentials
from .lockfiles import Inventory, Package, discover
from .scope import CliError
from .versions import AFFECTED, NOT_AFFECTED, evaluate, lowest_fix

ECOSYSTEMS = ("npm", "PyPI", "Go", "crates.io", "RubyGems", "Packagist", "NuGet")
MAX_PREFIXES = 2000
PREFIX_LENGTH = 4
RESPONSE_LIMIT = 32 * 1_048_576
RESPONSE_TIMEOUT = 60
# Thresholds: unknown severity counts only at --fail-on low; malicious is always critical.
RANK = {"none": 99, "critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
MALICIOUS_ADVICE = "Malicious package: remove it and rotate any credentials it could reach."
LIMITATIONS = (
    "Exact versions from lockfiles only, matched against known advisories. "
    "A clean result does not establish that dependencies are safe."
)


def normalize(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "crates.io":
        return name.lower().replace("_", "-")
    if ecosystem in {"Go", "RubyGems"}:
        return name
    return name.lower()


def prefix(ecosystem: str, name: str) -> str:
    digest = hashlib.sha256(normalize(ecosystem, name).encode("utf-8")).hexdigest()
    return digest[:PREFIX_LENGTH]


def _text(value: Any, limit: int = 300) -> str:
    # Server and lockfile text reach a terminal: drop control characters so it cannot inject.
    return "".join(character for character in str(value or "") if ord(character) >= 32)[:limit]


def unique_packages(inventory: Inventory) -> dict[Package, list[str]]:
    """Each (ecosystem, normalized name, version) once, with every lockfile that pins it."""
    found: dict[Package, list[str]] = {}
    for lockfile in inventory.lockfiles:
        for package in lockfile.packages:
            key = Package(
                package.ecosystem, normalize(package.ecosystem, package.name), package.version
            )
            paths = found.setdefault(key, [])
            if lockfile.path not in paths:
                paths.append(lockfile.path)
    return found


def build_queries(packages: dict[Package, list[str]]) -> list[dict[str, Any]]:
    """Request bodies with at most MAX_PREFIXES sorted, unique prefixes per ecosystem each."""
    buckets: dict[str, list[str]] = {}
    for package in packages:
        buckets.setdefault(package.ecosystem, []).append(prefix(package.ecosystem, package.name))
    chunks: dict[str, list[list[str]]] = {}
    for ecosystem, values in buckets.items():
        ordered = sorted(set(values))
        chunks[ecosystem] = [
            ordered[start : start + MAX_PREFIXES] for start in range(0, len(ordered), MAX_PREFIXES)
        ]
    bodies = []
    for index in range(max((len(value) for value in chunks.values()), default=0)):
        queries = [
            {"ecosystem": ecosystem, "prefixes": parts[index]}
            for ecosystem in ECOSYSTEMS
            for parts in [chunks.get(ecosystem, [])]
            if index < len(parts)
        ]
        bodies.append({"queries": queries})
    return bodies


def fetch_advisories(bodies: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    credentials = load_credentials()
    advisories: list[dict[str, Any]] = []
    updated = ""
    for body in bodies:
        value = _request(
            f"{credentials.api_url}/api/v1/cli/advisories",
            json_body=body,
            token=credentials.access_token,
            organization_id=credentials.organization_id,
            method="POST",
            limit=RESPONSE_LIMIT,
            timeout=RESPONSE_TIMEOUT,
        )
        if not isinstance(value, dict) or not isinstance(value.get("advisories"), list):
            raise CliError("grcHero returned an invalid advisory response.")
        advisories.extend(item for item in value["advisories"] if isinstance(item, dict))
        database = value.get("database")
        if isinstance(database, dict) and database.get("updated_at"):
            updated = _text(database["updated_at"], 40)
    return advisories, updated


def _finding(
    package: Package, paths: list[str], advisory: dict[str, Any], status: str
) -> dict[str, Any]:
    advisory_id = _text(advisory.get("id"), 100)
    malicious = advisory.get("malicious") is True or advisory_id.startswith("MAL-")
    severity = str(advisory.get("severity", "unknown")).lower()
    severity = "critical" if malicious else severity if severity in SEVERITIES else "unknown"
    aliases = advisory.get("aliases")
    return {
        "ecosystem": package.ecosystem,
        "package": _text(package.name, 200),
        "version": _text(package.version, 100),
        "advisory_id": advisory_id,
        "aliases": [_text(alias, 100) for alias in aliases if alias][:10]
        if isinstance(aliases, list)
        else [],
        "summary": _text(advisory.get("summary")),
        "severity": severity,
        "malicious": malicious,
        "status": "affected" if status == AFFECTED or malicious else "possibly_affected",
        "fixed_in": None if malicious else lowest_fix(package.ecosystem, package.version, advisory),
        "url": _text(advisory.get("url"), 300),
        "lockfiles": paths,
    }


def match(
    packages: dict[Package, list[str]], advisories: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Keep only advisories for our own packages, then decide affected-ness locally."""
    by_name: dict[tuple[str, str], list[Package]] = {}
    for package in packages:
        by_name.setdefault((package.ecosystem, package.name), []).append(package)
    findings: dict[tuple[Package, str], dict[str, Any]] = {}
    for advisory in advisories:
        ecosystem = advisory.get("ecosystem")
        name = advisory.get("package")
        if ecosystem not in ECOSYSTEMS or not isinstance(name, str) or not advisory.get("id"):
            continue
        for package in by_name.get((str(ecosystem), normalize(str(ecosystem), name)), []):
            malicious = advisory.get("malicious") is True or str(advisory["id"]).startswith("MAL-")
            status = AFFECTED if malicious else evaluate(ecosystem, package.version, advisory)
            if status == NOT_AFFECTED:
                continue
            key = (package, str(advisory["id"]))
            findings.setdefault(key, _finding(package, packages[package], advisory, status))
    return sorted(
        findings.values(),
        key=lambda item: (
            -RANK[item["severity"]],
            item["status"] != "affected",
            item["ecosystem"],
            item["package"],
            item["advisory_id"],
        ),
    )


def build_report(root: Path) -> dict[str, Any]:
    inventory = discover(root)
    packages = unique_packages(inventory)
    counts = {
        ecosystem: sum(1 for package in packages if package.ecosystem == ecosystem)
        for ecosystem in ECOSYSTEMS
    }
    findings: list[dict[str, Any]] = []
    updated = ""
    if packages:
        advisories, updated = fetch_advisories(build_queries(packages))
        findings = match(packages, advisories)
    else:
        load_credentials()  # still require a signed-in workspace, as every check does
    return {
        "schema_version": 1,
        "kind": "dependency-check",
        "cli_version": __version__,
        "created_at": datetime.now(UTC).isoformat(),
        "lockfiles": [
            {"path": item.path, "ecosystem": item.ecosystem, "packages": len(item.packages)}
            for item in inventory.lockfiles
        ],
        "packages": {ecosystem: count for ecosystem, count in counts.items() if count},
        "notes": inventory.notes,
        "database": {"source": "OSV.dev", "updated_at": updated or None},
        "findings": findings,
        "limitations": LIMITATIONS,
    }


def display(report: dict[str, Any]) -> str:
    findings = report["findings"]
    packages = report["packages"]
    affected = sum(item["status"] == "affected" for item in findings)
    lines = [
        f"grcHero CLI {__version__} · Dependency check",
        "",
        f"{len(report['lockfiles'])} lockfiles · {sum(packages.values())} packages"
        + (
            " (" + ", ".join(f"{name} {count}" for name, count in packages.items()) + ")"
            if packages
            else ""
        ),
        f"{affected} affected · {len(findings) - affected} possibly affected",
    ]
    if not report["lockfiles"]:
        lines.append("No supported lockfiles found. Commit a lockfile to check exact versions.")
    elif not findings:
        lines.append("No known advisories match these versions.")
    lines.extend(f"Note: {note}" for note in report["notes"])
    for item in findings:
        aliases = f" ({', '.join(item['aliases'])})" if item["aliases"] else ""
        lines.extend(
            [
                "",
                f"[{item['severity'].upper()}] {item['package']} {item['version']} · "
                f"{item['advisory_id']}{aliases}",
            ]
        )
        if item["summary"]:
            lines.append(f"  {item['summary']}")
        if item["malicious"]:
            lines.append(f"  {MALICIOUS_ADVICE}")
        elif item["status"] != "affected":
            lines.append("  Possibly affected: this version could not be compared with the data.")
        if item["fixed_in"]:
            lines.append(f"  Fix: upgrade to {item['fixed_in']}")
        elif not item["malicious"]:
            lines.append("  Fix: no fixed version is known yet")
        lines.append(f"  {', '.join(item['lockfiles'])}")
    updated = (report["database"].get("updated_at") or "unknown")[:10]
    lines.extend(
        [
            "",
            "Only hashed name prefixes left this machine. "
            f"Advisories: OSV.dev, as mirrored by grcHero (updated {updated}).",
        ]
    )
    return "\n".join(lines)


def failed(report: dict[str, Any], fail_on: str) -> bool:
    return any(RANK[item["severity"]] >= RANK[fail_on] for item in report["findings"])


def run_deps(path: str) -> dict[str, Any]:
    root = Path(path).resolve()
    if not root.is_dir():
        raise CliError("Project directory does not exist. Pass a directory to grchero deps.")
    return build_report(root)
