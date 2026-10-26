"""Upload one explicitly named evidence file, after a preview and confirmation.

The file becomes unreviewed evidence: a person in grcHero reviews and accepts it. Nothing is
uploaded implicitly, never a folder, and only the file types the workspace accepts as
evidence (documents, spreadsheets, text and images, never source code).
"""

import hashlib
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode
from uuid import UUID

from .auth import Credentials, _request, _upload, load_credentials, workspace_label
from .scope import CliError


def _api(credentials: Credentials, path: str) -> Any:
    return _request(
        f"{credentials.api_url}/api/v1{path}",
        token=credentials.access_token,
        organization_id=credentials.organization_id,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _control(credentials: Credentials, wanted: str, project: str | None) -> dict[str, Any]:
    query = f"?{urlencode({'project_id': project})}" if project else ""
    controls = [item for item in _api(credentials, f"/controls{query}") if isinstance(item, dict)]
    matches = [
        item
        for item in controls
        if str(item.get("id")) == wanted or str(item.get("code", "")).lower() == wanted.lower()
    ]
    if not matches:
        raise CliError(f"No control {wanted!r} in this workspace. Use its code or ID.")
    if len(matches) > 1:
        raise CliError(f"More than one control is coded {wanted!r}. Use its ID or --project.")
    return matches[0]


def add_evidence(
    path: Path,
    *,
    name: str | None,
    control: str | None,
    project: str | None,
    note: str,
    expires: str | None,
    assume_yes: bool,
    stdin_is_terminal: bool,
) -> str:
    if path.is_symlink() or not path.is_file():
        raise CliError("Choose one existing file. Folders and symlinks are not uploaded.")
    size = path.stat().st_size
    if size == 0:
        raise CliError("The file is empty.")
    if project is not None:
        try:
            UUID(project)
        except ValueError:
            raise CliError("--project must be a project UUID.") from None
    if expires is not None:
        try:
            date.fromisoformat(expires)
        except ValueError:
            raise CliError("--expires must be a date like 2027-01-31.") from None
    title = (name or path.name).strip()[:300]
    credentials = load_credentials()
    capabilities = _api(credentials, "/evidence/capabilities")
    if not isinstance(capabilities, dict) or not capabilities.get("upload"):
        raise CliError("This workspace cannot store files yet. Add evidence as a link instead.")
    accepted = [str(item).lower() for item in capabilities.get("accepted_extensions", [])]
    if path.suffix.lower() not in accepted:
        raise CliError(
            f"{path.suffix or 'This'} files are not accepted as evidence. "
            f"Use one of: {', '.join(accepted)}."
        )
    limit = int(capabilities.get("max_upload_bytes") or 0)
    if limit and size > limit:
        raise CliError(f"The file is larger than the upload limit ({limit // 1_048_576} MiB).")
    target = _control(credentials, control, project) if control else None
    digest = _sha256(path)
    query = f"?{urlencode({'project_id': project})}" if project else ""
    existing = next(
        (
            item
            for item in _api(credentials, f"/evidence{query}")
            if isinstance(item, dict) and item.get("sha256") == digest
        ),
        None,
    )
    print(
        "\n".join(
            [
                "Evidence to add to grcHero",
                f"  Workspace: {workspace_label(credentials)}",
                f"  File:      {path.name} ({size:,} bytes, sha256 {digest[:12]})",
                f"  Name:      {title}",
                f"  Project:   {project or 'none'}",
                f"  Control:   {target['code'] + ' ' + target['title'] if target else 'none'}",
                "",
                f"Already in grcHero as {existing.get('name')!r}; it will not be uploaded again."
                if existing
                else "The file is uploaded, scanned for malware and added as unreviewed evidence.",
                "A person reviews it in grcHero before it counts.",
            ]
        )
    )
    if not assume_yes:
        if not stdin_is_terminal:
            raise CliError("Confirmation needed. Re-run in a terminal, or pass --yes to confirm.")
        answer = input(f"\nAdd to {workspace_label(credentials)}? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            raise CliError("Nothing was uploaded.")
    if existing:
        record = existing
    else:
        params = {"filename": path.name, "name": title}
        if project:
            params["project_id"] = project
        if expires:
            params["expires_on"] = expires
        record = _upload(
            f"{credentials.api_url}/api/v1/evidence/files?{urlencode(params, quote_via=quote)}",
            path,
            token=credentials.access_token,
            organization_id=credentials.organization_id,
        )
    if target:
        _request(
            f"{credentials.api_url}/api/v1/evidence/links",
            json_body={
                "evidence_id": str(record["id"]),
                "control_id": str(target["id"]),
                "note": note[:2000],
            },
            token=credentials.access_token,
            organization_id=credentials.organization_id,
            method="POST",
        )
    workspace = f"{credentials.api_url}/workspace/evidence"
    return f"{workspace}?project={project}" if project else workspace
