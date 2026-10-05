import json
import stat
import time
from pathlib import Path

import pytest

from grchero_cli import auth
from grchero_cli.scope import CliError


def test_device_login_selects_workspace_and_saves_private_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRCHERO_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(auth.webbrowser, "open", lambda _url: True)
    monkeypatch.setattr(auth.time, "sleep", lambda _seconds: None)

    def request(url: str, **kwargs):
        if url.endswith("/device_authorization"):
            assert kwargs["data"]["client_id"] == "cli-client"
            return {
                "device_code": "device",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://auth.example.test/device",
                "verification_uri_complete": "https://auth.example.test/device?user_code=ABCD-EFGH",
                "expires_in": 300,
                "interval": 2,
            }
        if url.endswith("/oauth/v2/token"):
            return {"access_token": "access", "expires_in": 600}
        if url.endswith("/api/v1/organizations"):
            assert kwargs["token"] == "access"
            return [{"id": "00000000-0000-4000-8000-000000000001", "name": "Acme"}]
        raise AssertionError(url)

    monkeypatch.setattr(auth, "_request", request)
    credentials = auth.login(
        "https://app.example.test",
        "https://auth.example.test",
        "cli-client",
        "project-id",
    )
    assert credentials.organization_name == "Acme"
    saved = auth.credential_path()
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert json.loads(saved.read_text())["access_token"] == "access"


def test_environment_credentials_are_supported_for_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRCHERO_ACCESS_TOKEN", "ci-token")
    monkeypatch.setenv("GRCHERO_ORGANIZATION_ID", "00000000-0000-4000-8000-000000000001")
    monkeypatch.setenv("GRCHERO_API_URL", "https://app.example.test")
    monkeypatch.setenv("GRCHERO_ISSUER_URL", "https://auth.example.test")
    assert auth.load_credentials().access_token == "ci-token"


def test_expired_or_insecure_credentials_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRCHERO_CONFIG_DIR", str(tmp_path))
    payload = {
        "api_url": "https://app.example.test",
        "issuer_url": "https://auth.example.test",
        "client_id": "client",
        "audience": "project",
        "access_token": "token",
        "expires_at": int(time.time()) - 1,
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "organization_name": "Acme",
    }
    (tmp_path / "credentials.json").write_text(json.dumps(payload))
    with pytest.raises(CliError, match="expired"):
        auth.load_credentials()
    with pytest.raises(CliError, match="HTTPS"):
        auth._origin("http://remote.example.test", "API URL")
