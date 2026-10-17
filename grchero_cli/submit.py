"""Explicit, previewed submission of a saved report to the signed-in workspace."""

import hashlib
import json
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid5

from .auth import Credentials, OAuthRequestError, _request, load_credentials
from .scope import CliError

# Fixed namespace so the same workspace and content always yield the same import ID.
IMPORT_NAMESPACE = UUID("6f0c2d1e-5b1a-4c55-9d52-2f1d0f5e7a10")
REPORT_KEYS = [
    "schema_version",
    "cli_version",
    "rules_version",
    "mode",
    "created_at",
    "files",
    "applicable_rules",
]
FINDING_KEYS = ["rule_id", "title", "severity", "path", "line", "observation", "recommendation"]


def sanitize(report: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields the API accepts. File hashes and unknown fields are never sent."""
    return {
        **{key: report.get(key) for key in REPORT_KEYS},
        "findings": [{key: item.get(key) for key in FINDING_KEYS} for item in report["findings"]],
    }


def import_id(
    organization_id: str, project_id: str | None, title: str, body: dict[str, Any]
) -> UUID:
    digest = hashlib.sha256(
        json.dumps([project_id, title, body], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return uuid5(IMPORT_NAMESPACE, f"{organization_id}:{digest}")


def preview(
    credentials: Credentials, project_id: str | None, title: str, body: dict[str, Any]
) -> str:
    lines = [
        "Report to send to grcHero",
        f"  Workspace: {credentials.organization_name}",
        f"  Project:   {project_id or 'none (workspace report)'}",
        f"  Title:     {title}",
        f"  Scope:     {len(body['files'])} paths, {len(body['findings'])} observations",
        "",
        "Paths that will be sent:",
        *[f"  {path}" for path in body["files"]],
    ]
    if body["findings"]:
        lines += ["", "Observations that will be sent:"]
    for finding in body["findings"]:
        lines.append(f"  [{finding['severity'].upper()}] {finding['title']} ({finding['path']})")
    lines += [
        "",
        "Not sent: source text, detected credential values, file hashes.",
        "Paths and observations can still be sensitive. Review them before confirming.",
    ]
    return "\n".join(lines)


def submit(
    report: dict[str, Any],
    *,
    title: str,
    project_id: str | None,
    assume_yes: bool,
    stdin_is_terminal: bool,
) -> str:
    """Return the draft URL. Raises CliError, leaving the local report untouched."""
    if project_id is not None:
        try:
            UUID(project_id)
        except ValueError:
            raise CliError("--project must be a project UUID.") from None
    if not 2 <= len(title) <= 120:
        raise CliError("Title must be 2 to 120 characters.")
    credentials = load_credentials()
    body = sanitize(report)
    print(preview(credentials, project_id, title, body))
    if not assume_yes:
        if not stdin_is_terminal:
            raise CliError("Confirmation needed. Re-run in a terminal, or pass --yes to confirm.")
        answer = input(f"\nSend to {credentials.organization_name}? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            raise CliError("Nothing was sent.")
    key = import_id(credentials.organization_id, project_id, title, body)
    try:
        created = _request(
            f"{credentials.api_url}/api/v1/reports/scans",
            json_body={
                "import_id": str(key),
                "project_id": project_id,
                "title": title,
                "report": body,
            },
            token=credentials.access_token,
            organization_id=credentials.organization_id,
            method="POST",
        )
    except OAuthRequestError:
        raise
    except CliError:
        raise CliError(
            "Cannot confirm delivery. The report may have been received. "
            "Run the same command again; it will not create a duplicate."
        ) from None
    report_id = created.get("id") if isinstance(created, dict) else None
    try:
        UUID(str(report_id))
    except ValueError:
        raise CliError(
            "grcHero returned an unexpected response. Check Workspace > Reports."
        ) from None
    return (
        f"{credentials.api_url}/workspace/reports?report={quote(str(report_id))}"
        f"&organization={quote(credentials.organization_id)}"
    )
