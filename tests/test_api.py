import io
import json
import urllib.error

import pytest

from grchero_cli import api, auth
from grchero_cli.scope import CliError


def test_paths_stay_inside_the_api() -> None:
    assert api._path("risks") == "/risks"
    assert api._path("/api/v1/exceptions/x/decisions") == "/exceptions/x/decisions"
    assert api._path("/findings?mine=true") == "/findings?mine=true"
    for bad in ("https://evil.test/x", "//evil.test", "/a/../b", "/a b", "/x\n"):
        with pytest.raises(CliError):
            api._path(bad)


def test_fields_build_the_body() -> None:
    body = api._body(["decision=approve"], ["expected_version=3", "flag=true"], None)
    assert body == {"decision": "approve", "expected_version": 3, "flag": True}
    with pytest.raises(CliError):
        api._body(["no-equals"], [], None)
    with pytest.raises(CliError):
        api._body([], ["n=not json"], None)


class Response:
    status = 200

    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return json.dumps(self.payload).encode()


def refusal(code: str, details: dict | None = None) -> urllib.error.HTTPError:
    body = {"error": {"code": code, "message": code, "request_id": "r", "details": details or {}}}
    return urllib.error.HTTPError(
        "https://api.example.test", 403, "Forbidden", {}, io.BytesIO(json.dumps(body).encode())
    )


CONFIRMATION = "0199a000-0000-7000-8000-0000000000c1"
LINK = f"https://app.example.test/confirm/0199a000-0000-7000-8000-000000000001/{CONFIRMATION}"


def test_a_decision_waits_for_the_browser_and_repeats_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[tuple[str, str | None, dict[str, str]]] = []
    states = iter(["pending", "confirmed"])

    def urlopen(request, timeout):
        headers = {key.lower(): value for key, value in request.header_items()}
        seen.append((request.get_method(), request.full_url, headers))
        if request.full_url.endswith(f"/confirmations/{CONFIRMATION}"):
            return Response({"state": next(states)})
        if "x-grchero-confirmation" not in headers:
            raise refusal(
                "confirmation_required",
                {"confirmation_id": CONFIRMATION, "confirm_url": LINK},
            )
        return Response({"status": "approved"})

    opened: list[str] = []
    monkeypatch.setattr(auth.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(auth.webbrowser, "open", opened.append)
    monkeypatch.setattr(auth.time, "sleep", lambda _seconds: None)
    result = auth._request(
        "https://api.example.test/api/v1/exceptions/x/decisions",
        json_body={"decision": "approve"},
        token="person",
        organization_id="org",
        method="POST",
    )
    assert result == {"status": "approved"}
    assert opened == [LINK]
    assert LINK in capsys.readouterr().err
    final = seen[-1]
    assert final[0] == "POST" and final[2]["x-grchero-confirmation"] == CONFIRMATION
    # The first attempt, two polls and the one repeat.
    assert len(seen) == 4


def test_a_declined_request_stops_and_a_foreign_link_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def declined(request, timeout):
        if request.full_url.endswith(f"/confirmations/{CONFIRMATION}"):
            return Response({"state": "declined"})
        raise refusal(
            "confirmation_required", {"confirmation_id": CONFIRMATION, "confirm_url": LINK}
        )

    monkeypatch.setattr(auth.urllib.request, "urlopen", declined)
    monkeypatch.setattr(auth.webbrowser, "open", lambda _url: True)
    with pytest.raises(CliError, match="declined"):
        auth._request("https://api.example.test/api/v1/x", json_body={}, token="t", method="POST")

    def foreign(request, timeout):
        raise refusal(
            "confirmation_required",
            {"confirmation_id": CONFIRMATION, "confirm_url": "javascript:alert(1)"},
        )

    monkeypatch.setattr(auth.urllib.request, "urlopen", foreign)
    with pytest.raises(CliError, match="invalid confirmation link"):
        auth._request("https://api.example.test/api/v1/x", json_body={}, token="t", method="POST")


def test_other_errors_keep_their_code(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(request, timeout):
        raise refusal("agent_not_allowed")

    monkeypatch.setattr(auth.urllib.request, "urlopen", refuse)
    with pytest.raises(auth.OAuthRequestError) as error:
        auth._request("https://api.example.test/api/v1/x", token="t")
    assert error.value.code == "agent_not_allowed"
