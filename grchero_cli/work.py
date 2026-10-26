"""The signed-in person's open assigned work, read from the same lists as My work."""

from typing import Any
from urllib.parse import urlencode
from uuid import UUID

from .auth import Credentials, OAuthRequestError, _request, load_credentials
from .scope import CliError

# (key, heading, API path, workspace page). Paths mirror the browser's My work tabs.
KINDS = [
    ("findings", "Findings", "/findings?mine=true&active_only=true", "?mine=1"),
    (
        "evidence",
        "Evidence requests",
        "/evidence-requests?mine=true&active_only=true",
        "?mine=1&work=evidence",
    ),
    (
        "documents",
        "Document reviews",
        "/document-assurance?mine=true&active_only=true",
        "?mine=1&work=documents",
    ),
    (
        "vendors",
        "Vendor reviews",
        "/vendor-reviews?mine=true&active_only=true",
        "?mine=1&work=vendors",
    ),
    ("operations", "Operations", "/operational-work?active_only=true", "?mine=1&work=operations"),
    (
        "questionnaires",
        "Questionnaires",
        "/questionnaire-work?active_only=true",
        "?mine=1&work=questionnaires",
    ),
]
LIMIT = 10


def _text(value: Any) -> str:
    # Server text is shown in a terminal: drop control characters so it cannot inject escapes.
    return "".join(character for character in str(value or "") if ord(character) >= 32)


def _item(raw: dict[str, Any]) -> dict[str, str]:
    title = raw.get("title") or raw.get("name") or raw.get("vendor_name") or "Untitled"
    status = raw.get("effective_status") or raw.get("action") or raw.get("status") or ""
    return {
        "title": _text(title)[:160],
        "status": _text(status).replace("_", " "),
        "due": _text(raw.get("due_date") or "")[:10],
    }


def collect(
    credentials: Credentials, project: str | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    kinds: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for key, heading, path, page in KINDS:
        url = f"{credentials.api_url}/api/v1{path}"
        if project:
            url += "&" + urlencode({"project_id": project})
        try:
            value = _request(
                url,
                token=credentials.access_token,
                organization_id=credentials.organization_id,
            )
        except OAuthRequestError:
            # A role that cannot read this kind of work simply has none of it here.
            unavailable.append(heading)
            continue
        raw = value.get("items", []) if isinstance(value, dict) else []
        items = [_item(entry) for entry in raw if isinstance(entry, dict)]
        more = bool(value.get("next_cursor")) if isinstance(value, dict) else False
        if items:
            kinds.append(
                {
                    "kind": key,
                    "heading": heading,
                    "items": items,
                    "more": more,
                    "url": f"{credentials.api_url}/workspace/findings{page}",
                }
            )
    return kinds, unavailable


def display(kinds: list[dict[str, Any]], workspace: str) -> str:
    if not kinds:
        return f"Nothing is assigned to you in {workspace}."
    total = sum(len(kind["items"]) for kind in kinds)
    lines = [
        f"Your open work in {workspace}: {total}{'+' if any(k['more'] for k in kinds) else ''}"
    ]
    for kind in kinds:
        lines += ["", f"{kind['heading']} ({len(kind['items'])}{'+' if kind['more'] else ''})"]
        for item in kind["items"][:LIMIT]:
            due = f" · due {item['due']}" if item["due"] else ""
            status = f" · {item['status']}" if item["status"] else ""
            lines.append(f"  {item['title']}{status}{due}")
        if len(kind["items"]) > LIMIT or kind["more"]:
            lines.append("  ...")
        lines.append(f"  Open: {kind['url']}")
    return "\n".join(lines)


def run_work(project: str | None) -> tuple[list[dict[str, Any]], str]:
    credentials = load_credentials()
    if project:
        try:
            UUID(project)
        except ValueError:
            raise CliError("--project must be a project UUID.") from None
    kinds, unavailable = collect(credentials, project)
    if len(unavailable) == len(KINDS):
        raise CliError("grcHero did not return any of your work. Run `grchero login` again.")
    return kinds, credentials.organization_name
