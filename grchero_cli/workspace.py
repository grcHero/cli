"""The workspace and project a command acts in, and the calls it makes there.

`grchero org use` switches the saved sign-in to another of the person's workspaces;
`grchero project use` saves a default project for one workspace. `--org` and `--project`
override both for a single command. Defaults live next to the credentials, never in the
project directory, and hold only IDs and names.
"""

import json
import os
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode
from uuid import UUID

from .auth import Credentials, _request, _save, credential_path, load_credentials
from .scope import CliError

NO_PROJECT = "none"


def _uuid(value: str) -> str | None:
    try:
        return str(UUID(value))
    except ValueError:
        return None


def context_path() -> Path:
    return credential_path().with_name("context.json")


def _read_context() -> dict[str, Any]:
    try:
        value = json.loads(context_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_context(value: dict[str, Any]) -> None:
    path = context_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".context-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def saved_project(organization_id: str) -> dict[str, str] | None:
    projects = _read_context().get("projects")
    entry = projects.get(organization_id) if isinstance(projects, dict) else None
    if isinstance(entry, dict) and _uuid(str(entry.get("id", ""))):
        return {"id": str(entry["id"]), "name": str(entry.get("name", ""))}
    return None


def save_project(organization_id: str, project: dict[str, Any] | None) -> None:
    context = _read_context()
    projects = context.get("projects") if isinstance(context.get("projects"), dict) else {}
    if project is None:
        projects.pop(organization_id, None)
    else:
        projects[organization_id] = {"id": str(project["id"]), "name": str(project["name"])}
    _write_context({**context, "projects": projects})


@dataclass(frozen=True)
class Workspace:
    credentials: Credentials
    # The project lists and new records use, or None for the whole workspace.
    project_id: str | None
    project_name: str = ""

    @property
    def organization_id(self) -> str:
        return self.credentials.organization_id

    def call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        **query: Any,
    ) -> Any:
        values = {key: value for key, value in query.items() if value not in (None, "", False)}
        url = f"{self.credentials.api_url}/api/v1{path}"
        if values:
            url += "?" + urlencode(
                {key: "true" if value is True else value for key, value in values.items()},
                quote_via=quote,
            )
        return _request(
            url,
            json_body=body if method != "GET" else None,
            token=self.credentials.access_token,
            organization_id=self.organization_id,
            method=method,
        )

    def get(self, path: str, **query: Any) -> Any:
        return self.call("GET", path, **query)

    def page(self, path: str) -> str:
        """A workspace page, keeping the project so the browser opens in the same place."""
        url = f"{self.credentials.api_url}{path}"
        if self.project_id:
            url += ("&" if "?" in url else "?") + urlencode({"project": self.project_id})
        return url


def organizations(credentials: Credentials) -> list[dict[str, Any]]:
    if credentials.is_api_token:
        raise CliError("An API token belongs to one workspace. Sign in to switch workspaces.")
    value = _request(f"{credentials.api_url}/api/v1/organizations", token=credentials.access_token)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def find_organization(credentials: Credentials, wanted: str) -> dict[str, Any]:
    match = next(
        (
            item
            for item in organizations(credentials)
            if str(item.get("id")) == wanted or item.get("slug") == wanted
        ),
        None,
    )
    if match is None:
        raise CliError(f"No workspace {wanted!r} for this account. See `grchero org list`.")
    return match


def use_organization(wanted: str) -> Credentials:
    if os.getenv("GRCHERO_API_TOKEN") or os.getenv("GRCHERO_ACCESS_TOKEN"):
        raise CliError("While a token is set, the workspace is GRCHERO_ORGANIZATION_ID.")
    credentials = load_credentials()
    match = find_organization(credentials, wanted)
    updated = replace(
        credentials,
        organization_id=str(match["id"]),
        organization_name=str(match.get("name", "Workspace")),
    )
    _save(updated)
    return updated


def find_project(credentials: Credentials, wanted: str) -> dict[str, Any]:
    value = _request(
        f"{credentials.api_url}/api/v1/projects?include_archived=true",
        token=credentials.access_token,
        organization_id=credentials.organization_id,
    )
    items = [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
    matches = [
        item
        for item in items
        if str(item.get("id")) == wanted or str(item.get("name", "")).lower() == wanted.lower()
    ]
    if not matches:
        raise CliError(f"No project {wanted!r} in this workspace. See `grchero project list`.")
    if len(matches) > 1:
        raise CliError(f"More than one project is named {wanted!r}. Use its ID.")
    return matches[0]


def open_workspace(organization: str | None = None, project: str | None = None) -> Workspace:
    """Credentials for `--org` (or the saved workspace) and the project for `--project`.

    `--project none` acts on the whole workspace even when a default project is saved.
    """
    credentials = load_credentials()
    if organization and _uuid(organization) != credentials.organization_id:
        if credentials.is_api_token:
            raise CliError("An API token belongs to one workspace; --org cannot change it.")
        match = find_organization(credentials, organization)
        credentials = replace(
            credentials,
            organization_id=str(match["id"]),
            organization_name=str(match.get("name", "Workspace")),
        )
    if project == NO_PROJECT:
        return Workspace(credentials, None)
    if project:
        found = find_project(credentials, project)
        return Workspace(credentials, str(found["id"]), str(found.get("name", "")))
    saved = saved_project(credentials.organization_id)
    if saved:
        return Workspace(credentials, saved["id"], saved["name"])
    return Workspace(credentials, None)
