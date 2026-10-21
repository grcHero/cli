from typing import Any

import pytest

from grchero_cli import submit
from grchero_cli.auth import Credentials, OAuthRequestError
from grchero_cli.scope import CliError

ORG = "00000000-0000-4000-8000-000000000001"
REPORT_ID = "00000000-0000-4000-8000-0000000000aa"


def credentials() -> Credentials:
    return Credentials(
        "https://app.example.test", "https://auth.example.test", "c", "a", "tok", 9**10, ORG, "Acme"
    )


def report() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "cli_version": "0.1.0",
        "rules_version": "2026.1",
        "mode": "local",
        "created_at": "2026-10-17T10:00:00+00:00",
        "files": [".env"],
        "applicable_rules": ["secret-in-env"],
        "limitations": "x",
        "findings": [
            {
                "rule_id": "secret-in-env",
                "title": "Credential",
                "severity": "high",
                "path": ".env",
                "line": 1,
                "observation": "o",
                "recommendation": "r",
                "file_sha256": "a" * 64,
            }
        ],
    }


@pytest.fixture(autouse=True)
def signed_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(submit, "load_credentials", credentials)


def run(**overrides: Any) -> str:
    options = {
        "title": "Review",
        "project_id": None,
        "assume_yes": True,
        "stdin_is_terminal": False,
    }
    return submit.submit(report(), **{**options, **overrides})


def test_sanitize_drops_hashes_and_unknown_fields() -> None:
    body = submit.sanitize(report())
    assert "limitations" not in body
    assert "file_sha256" not in body["findings"][0]


def test_sends_sanitized_body_with_stable_import_id(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[dict[str, Any]] = []

    def request(url: str, **kwargs: Any) -> dict[str, Any]:
        assert url == "https://app.example.test/api/v1/reports/scans"
        assert kwargs["organization_id"] == ORG
        sent.append(kwargs["json_body"])
        return {"id": REPORT_ID}

    monkeypatch.setattr(submit, "_request", request)
    first = run()
    second = run()
    assert sent[0]["import_id"] == sent[1]["import_id"]
    assert "file_sha256" not in str(sent[0])
    expected = f"https://app.example.test/workspace/reports?report={REPORT_ID}&organization={ORG}"
    assert first == second == expected
    assert "Not sent: source text" in capsys.readouterr().out


def test_changed_content_changes_import_id(monkeypatch: pytest.MonkeyPatch) -> None:
    keys: list[str] = []

    def request(_url: str, **kwargs: Any) -> dict[str, Any]:
        keys.append(kwargs["json_body"]["import_id"])
        return {"id": REPORT_ID}

    monkeypatch.setattr(submit, "_request", request)
    run(title="Review")
    run(title="Another")
    assert keys[0] != keys[1]


def test_requires_confirmation_without_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(submit, "_request", lambda *a, **k: pytest.fail("sent"))
    with pytest.raises(CliError, match="Confirmation needed"):
        run(assume_yes=False)


def test_declined_prompt_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(submit, "_request", lambda *a, **k: pytest.fail("sent"))
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    with pytest.raises(CliError, match="Nothing was sent"):
        run(assume_yes=False, stdin_is_terminal=True)


def test_rejects_bad_project_and_title(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(submit, "_request", lambda *a, **k: pytest.fail("sent"))
    with pytest.raises(CliError, match="project UUID"):
        run(project_id="nope")
    with pytest.raises(CliError, match="Title"):
        run(title="x")


def test_server_rejection_is_shown_and_network_loss_is_retry_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def rejected(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise OAuthRequestError("You do not have permission to import reports.")

    monkeypatch.setattr(submit, "_request", rejected)
    with pytest.raises(CliError, match="permission"):
        run()

    def lost(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise CliError("Cannot reach grcHero.")

    monkeypatch.setattr(submit, "_request", lost)
    with pytest.raises(CliError, match="will not create a duplicate"):
        run()


def test_unexpected_response_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(submit, "_request", lambda *a, **k: {"id": "not-a-uuid"})
    with pytest.raises(CliError, match="unexpected response"):
        run()


def test_api_tokens_cannot_send_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    from dataclasses import replace

    monkeypatch.setattr(
        submit,
        "load_credentials",
        lambda: replace(credentials(), access_token="grc_0123456789ab_x"),
    )
    with pytest.raises(CliError, match="signed-in person"):
        run()
