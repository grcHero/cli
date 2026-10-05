"""Bounded checks. Source text is discarded after this function returns."""

# ruff: noqa: E501

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class SelectedFile(Protocol):
    @property
    def path(self) -> str: ...

    @property
    def content(self) -> str: ...


@dataclass(frozen=True)
class Observation:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    observation: str
    recommendation: str
    file_sha256: str


SECRET_NAME = re.compile(r"(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY)$", re.I)
ASSIGNMENT = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
PLACEHOLDER = re.compile(
    r"^(?:['\"]?)(?:example|sample|placeholder|changeme|your[-_].*|<.*>|\$\{.*\}|\*+)(?:['\"]?)$",
    re.I,
)
SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx")
LITERAL_CREDENTIAL = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY))\s*(?::[^=]+)?=\s*(['\"])([^'\"]{8,})\2",
    re.I,
)
RULE_AREAS = {
    "secret-in-env": "secrets",
    "literal-credential": "secrets",
    "dynamic-evaluation": "code",
    "production-debug": "configuration",
    "workflow-write-all": "ci",
    "workflow-pull-request-target": "ci",
    "docker-user-review": "container",
}


def applicable_rule_ids(
    paths: Sequence[str], enabled_areas: Sequence[str] | None = None
) -> tuple[str, ...]:
    areas = set(enabled_areas) if enabled_areas is not None else set(RULE_AREAS.values())
    applicable: set[str] = set()
    for path in paths:
        lower = path.replace("\\", "/").lower()
        if lower.endswith((".env", ".env.production", ".env.prod", ".env.local")):
            applicable.add("secret-in-env")
        if lower.endswith((".env.production", ".env.prod")):
            applicable.add("production-debug")
        if lower.endswith((".yml", ".yaml")) and ".github/workflows/" in f"/{lower}":
            applicable.update(("workflow-write-all", "workflow-pull-request-target"))
        if lower.rsplit("/", 1)[-1] == "dockerfile":
            applicable.add("docker-user-review")
        if lower.endswith(SOURCE_SUFFIXES):
            applicable.update(("literal-credential", "dynamic-evaluation"))
    return tuple(sorted(rule for rule in applicable if RULE_AREAS[rule] in areas))


def inspect_files(
    files: Sequence[SelectedFile], enabled_areas: Sequence[str] | None = None
) -> list[Observation]:
    findings: list[Observation] = []
    for file in files:
        path = file.path.replace("\\", "/")
        lower_path = path.lower()
        digest = hashlib.sha256(file.content.encode("utf-8")).hexdigest()
        lines = file.content.splitlines()
        for number, line in enumerate(lines, 1):
            if lower_path.endswith(SOURCE_SUFFIXES) and not line.lstrip().startswith(
                ("#", "//", "*")
            ):
                literal = LITERAL_CREDENTIAL.search(line)
                if literal and not PLACEHOLDER.fullmatch(literal.group(3)):
                    findings.append(
                        Observation(
                            "literal-credential",
                            "Credential-like literal in source code",
                            "high",
                            path,
                            number,
                            f"{literal.group(1)} is assigned a non-placeholder literal. The value was not retained.",
                            "Move the value to a managed secret, rotate it if exposed, and review repository history.",
                            digest,
                        )
                    )
                if re.search(r"\beval\s*\(", line):
                    findings.append(
                        Observation(
                            "dynamic-evaluation",
                            "Review dynamic code evaluation",
                            "medium",
                            path,
                            number,
                            "A dynamic evaluation call was detected; whether it is exploitable needs review.",
                            "Avoid evaluating untrusted input as code. Review the call site and its input source.",
                            digest,
                        )
                    )
            if lower_path.endswith((".env", ".env.production", ".env.prod", ".env.local")):
                match = ASSIGNMENT.match(line)
                if match and SECRET_NAME.search(match.group(1)):
                    value = match.group(2).strip().strip("'\"")
                    if len(value) >= 8 and not PLACEHOLDER.fullmatch(value):
                        findings.append(
                            Observation(
                                "secret-in-env",
                                "Credential-like value in an environment file",
                                "high",
                                path,
                                number,
                                f"{match.group(1)} has a non-placeholder value. The value was not retained.",
                                "Confirm this file is excluded from version control. If the value was committed, rotate it and remove it from history.",
                                digest,
                            )
                        )
            if lower_path.endswith((".yml", ".yaml")) and ".github/workflows/" in f"/{lower_path}":
                if re.match(r"^\s*permissions\s*:\s*write-all\s*(?:#.*)?$", line):
                    findings.append(
                        Observation(
                            "workflow-write-all",
                            "Workflow grants broad write permissions",
                            "medium",
                            path,
                            number,
                            "The workflow declares permissions: write-all.",
                            "Grant only the permissions each job needs and review events that can trigger it.",
                            digest,
                        )
                    )
                if re.match(r"^\s*pull_request_target\s*:\s*(?:\[|\{|$)", line):
                    findings.append(
                        Observation(
                            "workflow-pull-request-target",
                            "Review privileged pull-request workflow",
                            "medium",
                            path,
                            number,
                            "The workflow uses pull_request_target, which runs with base-repository context.",
                            "Review token permissions and ensure untrusted pull-request code is not executed in this workflow.",
                            digest,
                        )
                    )
            if lower_path.endswith((".env.production", ".env.prod")) and re.match(
                r"^\s*DEBUG\s*=\s*(?:true|1|yes)\s*(?:#.*)?$", line, re.I
            ):
                findings.append(
                    Observation(
                        "production-debug",
                        "Production debug mode appears enabled",
                        "medium",
                        path,
                        number,
                        "The selected production environment file enables DEBUG.",
                        "Disable debug output in production and confirm error responses do not expose internals.",
                        digest,
                    )
                )
        if (
            lower_path.rsplit("/", 1)[-1] == "dockerfile"
            and re.search(r"(?im)^\s*FROM\s+", file.content)
            and not re.search(r"(?im)^\s*USER\s+", file.content)
        ):
            findings.append(
                Observation(
                    "docker-user-review",
                    "Container user needs review",
                    "low",
                    path,
                    1,
                    "No USER directive was found in this selected Dockerfile. The base image may define one.",
                    "Confirm the runtime user in the final image and set an unprivileged user where practical.",
                    digest,
                )
            )
    # Keep high-severity observations visible when a noisy workflow reaches the cap.
    severity = {"high": 0, "medium": 1, "low": 2}
    enabled = set(applicable_rule_ids([file.path for file in files], enabled_areas))
    return sorted(
        (item for item in findings if item.rule_id in enabled),
        key=lambda item: (severity[item.severity], item.path, item.line),
    )[:100]
