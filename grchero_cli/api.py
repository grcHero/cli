"""Call any grcHero API endpoint, like `gh api` (ADR 0017 in grcHero).

The path is always relative to the signed-in workspace's API, so the access token is never sent
anywhere else. Reads and writes run at once; a request that decides or administers waits for
the person to confirm it in the browser, then runs once.
"""

import json
import re
from pathlib import Path
from typing import Any

from .auth import _request, load_credentials
from .scope import CliError

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
# A path within the API: no scheme, host, parent segments or doubled slashes.
_PATH = re.compile(r"/[A-Za-z0-9/_.~=&%:,+-]*(\?[A-Za-z0-9/_.~=&%:,+-]*)?")


def _path(value: str) -> str:
    path = value if value.startswith("/") else f"/{value}"
    path = path.removeprefix("/api/v1")
    if not _PATH.fullmatch(path) or "//" in path or "/../" in f"{path}/":
        raise CliError("Give an API path such as /risks or /exceptions/ID/decisions.")
    return path


def _body(fields: list[str], raw_fields: list[str], input_file: str | None) -> dict[str, Any]:
    if input_file:
        if fields or raw_fields:
            raise CliError("Use --input or fields, not both.")
        try:
            value = json.loads(Path(input_file).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as cause:
            raise CliError("--input must be a JSON file.") from cause
        if not isinstance(value, dict):
            raise CliError("--input must hold a JSON object.")
        return value
    body: dict[str, Any] = {}
    for item in fields:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise CliError(f"Write fields as key=value, not {item!r}.")
        body[key] = value
    for item in raw_fields:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise CliError(f"Write typed fields as key=JSON, not {item!r}.")
        try:
            body[key] = json.loads(value)
        except json.JSONDecodeError as cause:
            raise CliError(f"The value of {key} is not JSON.") from cause
    return body


def call(
    method: str,
    path: str,
    fields: list[str],
    raw_fields: list[str],
    input_file: str | None,
) -> Any:
    credentials = load_credentials()
    body = _body(fields, raw_fields, input_file)
    if method == "GET" and body:
        raise CliError("A GET request takes no fields; put filters in the path.")
    return _request(
        f"{credentials.api_url}/api/v1{_path(path)}",
        json_body=body if method != "GET" else None,
        token=credentials.access_token,
        organization_id=credentials.organization_id,
        method=method,
    )
