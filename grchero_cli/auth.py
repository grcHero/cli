"""OAuth device login and per-scan workspace authorization."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .deployment import deployment_defaults
from .scope import CliError

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
DEFAULT_TIMEOUT = 10


class OAuthRequestError(CliError):
    def __init__(self, message: str, oauth_error: str = "") -> None:
        super().__init__(message)
        self.oauth_error = oauth_error


@dataclass(frozen=True)
class Credentials:
    api_url: str
    issuer_url: str
    client_id: str
    audience: str
    access_token: str
    expires_at: int
    organization_id: str
    organization_name: str

    @property
    def is_api_token(self) -> bool:
        """grcHero API tokens act within explicit grants and cannot reach sign-in-only routes."""
        return self.access_token.startswith(API_TOKEN_PREFIX)


API_TOKEN_PREFIX = "grc_"
UPLOAD_TIMEOUT = 120


def credential_path() -> Path:
    configured = os.getenv("GRCHERO_CONFIG_DIR")
    root = Path(configured).expanduser() if configured else Path.home() / ".config" / "grchero"
    return root / "credentials.json"


def _upload(url: str, path: Path, *, token: str, organization_id: str) -> dict[str, Any]:
    """POST one file as the raw request body, streamed, with the same error handling."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        request = urllib.request.Request(
            url,
            data=stream,
            method="POST",
            headers={
                "Accept": "application/json",
                "User-Agent": "grcHero-CLI",
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
                "Authorization": f"Bearer {token}",
                "X-Organization-ID": organization_id,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=UPLOAD_TIMEOUT) as response:
                result = json.loads(response.read(1_048_577))
        except urllib.error.HTTPError as cause:
            try:
                payload = json.loads(cause.read(65_537))
                error = payload.get("error", {}) if isinstance(payload, dict) else {}
                message = error.get("message", "") if isinstance(error, dict) else ""
            except (json.JSONDecodeError, UnicodeError, ValueError):
                message = ""
            raise OAuthRequestError(str(message) or "grcHero rejected the upload.", "") from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeError):
            raise CliError("Cannot reach grcHero. Check your connection and try again.") from None
    if not isinstance(result, dict):
        raise CliError("grcHero returned an invalid upload response.")
    return result


def _origin(value: str, label: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme not in ({"http", "https"} if local else {"https"})
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CliError(f"{label} must be an HTTPS origin (HTTP is allowed only on loopback).")
    return value.rstrip("/")


def _request(
    url: str,
    *,
    data: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    token: str = "",
    organization_id: str = "",
    method: str | None = None,
) -> dict[str, Any]:
    if data is not None and json_body is not None:
        raise ValueError("Choose form or JSON data, not both")
    body = (
        urllib.parse.urlencode(data).encode()
        if data is not None
        else json.dumps(json_body).encode()
        if json_body is not None
        else None
    )
    headers = {"Accept": "application/json", "User-Agent": "grcHero-CLI"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if organization_id:
        headers["X-Organization-ID"] = organization_id
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
            raw = response.read(1_048_577)
            # 204 No Content (for example, linking evidence) is a success with nothing to read.
            if response.status == 204 or not raw.strip():
                return {}
            result = json.loads(raw)
        if not isinstance(result, dict) and not isinstance(result, list):
            raise ValueError
        return result  # type: ignore[return-value]
    except urllib.error.HTTPError as cause:
        try:
            payload = json.loads(cause.read(65_537))
            code = payload.get("error", "") if isinstance(payload, dict) else ""
            if isinstance(code, dict):
                message = code.get("message", "")
            else:
                message = (
                    payload.get("error_description", code) if isinstance(payload, dict) else ""
                )
        except (json.JSONDecodeError, UnicodeError, ValueError):
            message = ""
        raise OAuthRequestError(
            str(message) or "grcHero rejected the authentication request.",
            code if isinstance(code, str) else "",
        ) from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeError, ValueError):
        raise CliError("Cannot reach grcHero. Check your connection and try again.") from None


def _save(credentials: Credentials) -> None:
    path = credential_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(stat.S_IRWXU)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".credentials-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(credentials.__dict__, stream, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _issuer_for(token: str) -> str:
    """API tokens never talk to the identity provider, so they need no issuer URL."""
    configured = os.getenv("GRCHERO_ISSUER_URL", "")
    if token.startswith(API_TOKEN_PREFIX) and not configured:
        return ""
    return _origin(configured, "Issuer URL")


def load_credentials() -> Credentials:
    environment_token = os.getenv("GRCHERO_API_TOKEN", "") or os.getenv("GRCHERO_ACCESS_TOKEN", "")
    if environment_token:
        organization_id = os.getenv("GRCHERO_ORGANIZATION_ID", "")
        try:
            UUID(organization_id)
        except ValueError:
            raise CliError("GRCHERO_ORGANIZATION_ID must be a valid workspace UUID.") from None
        return Credentials(
            # A release already knows its server, so CI needs only the token and workspace.
            api_url=_origin(
                os.getenv("GRCHERO_API_URL", "") or deployment_defaults().get("api_url", ""),
                "API URL",
            ),
            issuer_url=_issuer_for(environment_token),
            client_id=os.getenv("GRCHERO_CLIENT_ID", "environment"),
            audience=os.getenv("GRCHERO_AUDIENCE", "environment"),
            access_token=environment_token,
            expires_at=int(time.time()) + 60,
            organization_id=organization_id,
            organization_name=os.getenv("GRCHERO_ORGANIZATION_NAME", organization_id),
        )
    path = credential_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        credentials = Credentials(**raw)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise CliError("Sign in first with `grchero login`.") from None
    if credentials.expires_at <= int(time.time()) + 30:
        raise CliError("Your grcHero session expired. Run `grchero login` again.")
    _origin(credentials.api_url, "API URL")
    _origin(credentials.issuer_url, "Issuer URL")
    try:
        UUID(credentials.organization_id)
    except ValueError:
        raise CliError("Saved workspace is invalid. Run `grchero login` again.") from None
    return credentials


def _organizations(credentials: Credentials) -> list[dict[str, Any]]:
    value = _request(f"{credentials.api_url}/api/v1/organizations", token=credentials.access_token)
    if not isinstance(value, list):
        raise CliError("grcHero returned an invalid workspace list.")
    return [item for item in value if isinstance(item, dict)]


def login(
    api_url: str,
    issuer_url: str,
    client_id: str,
    audience: str,
    organization: str = "",
) -> Credentials:
    api_url = _origin(api_url, "API URL")
    issuer_url = _origin(issuer_url, "Issuer URL")
    if not client_id or not audience:
        raise CliError("CLI client ID and audience are required.")
    scope = f"openid email profile urn:zitadel:iam:org:project:id:{audience}:aud"
    device = _request(
        f"{issuer_url}/oauth/v2/device_authorization",
        data={"client_id": client_id, "scope": scope},
        method="POST",
    )
    try:
        device_code = str(device["device_code"])
        user_code = str(device["user_code"])
        verification_uri = str(device["verification_uri"])
        complete = str(device.get("verification_uri_complete", verification_uri))
        expires_at = time.monotonic() + min(int(device.get("expires_in", 300)), 900)
        interval = max(2, min(int(device.get("interval", 5)), 15))
    except (KeyError, TypeError, ValueError):
        raise CliError("The identity service returned an invalid login response.") from None
    print(f"Open {verification_uri} and enter code {user_code}.")
    if not webbrowser.open(complete):
        print("The browser did not open automatically. Use the link above.")
    token: dict[str, Any] | None = None
    while time.monotonic() < expires_at:
        time.sleep(interval)
        try:
            token = _request(
                f"{issuer_url}/oauth/v2/token",
                data={
                    "grant_type": DEVICE_GRANT,
                    "device_code": device_code,
                    "client_id": client_id,
                },
                method="POST",
            )
            break
        except CliError as cause:
            oauth_error = cause.oauth_error if isinstance(cause, OAuthRequestError) else ""
            if oauth_error == "authorization_pending":
                continue
            if oauth_error == "slow_down":
                interval = min(interval + 5, 20)
                continue
            if oauth_error == "access_denied":
                raise CliError("Sign-in was cancelled.") from None
            raise
    if token is None:
        raise CliError("Sign-in expired. Run `grchero login` again.")
    try:
        access_token = str(token["access_token"])
        token_expires_at = int(time.time()) + int(token["expires_in"])
    except (KeyError, TypeError, ValueError):
        raise CliError("The identity service returned an invalid token response.") from None
    partial = Credentials(
        api_url, issuer_url, client_id, audience, access_token, token_expires_at, "", ""
    )
    workspaces = _organizations(partial)
    if not workspaces:
        webbrowser.open(f"{api_url}/onboarding")
        raise CliError("Finish workspace setup in the browser, then run `grchero login` again.")
    selected = None
    if organization:
        selected = next(
            (
                item
                for item in workspaces
                if str(item.get("id")) == organization or item.get("slug") == organization
            ),
            None,
        )
        if selected is None:
            raise CliError("The requested workspace was not found for this account.")
    elif len(workspaces) == 1:
        selected = workspaces[0]
    else:
        print("Choose a workspace:")
        for index, item in enumerate(workspaces, 1):
            print(f"  {index}. {item.get('name', item.get('id', 'Workspace'))}")
        try:
            choice = int(input("Workspace number: "))
            selected = workspaces[choice - 1]
        except (ValueError, IndexError, EOFError):
            raise CliError("No valid workspace was selected.") from None
    credentials = partial.__class__(
        **{
            **partial.__dict__,
            "organization_id": str(selected["id"]),
            "organization_name": str(selected.get("name", "Workspace")),
        }
    )
    _save(credentials)
    return credentials


def logout() -> None:
    path = credential_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as cause:
        raise CliError("Cannot remove the saved grcHero session.") from cause


def authorize_scan(cli_version: str) -> dict[str, Any]:
    credentials = load_credentials()
    value = _request(
        f"{credentials.api_url}/api/v1/cli/scan-authorizations",
        json_body={"request_id": str(uuid4()), "cli_version": cli_version},
        token=credentials.access_token,
        organization_id=credentials.organization_id,
        method="POST",
    )
    if not isinstance(value, dict) or value.get("allowed") is not True:
        raise CliError("This workspace cannot start a CLI scan.")
    return value
