"""`grchero <area> <verb>`: workspace commands for people, scripts and agents (ADR 0017)."""

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from grchero_cli import auth, commands, main

ORG = "00000000-0000-4000-8000-000000000001"
OTHER_ORG = "00000000-0000-4000-8000-000000000002"
PROJECT = "00000000-0000-4000-8000-0000000000a1"
ME = "00000000-0000-4000-8000-0000000000b1"
FINDING = "00000000-0000-4000-8000-0000000000f1"
EXCEPTION = "00000000-0000-4000-8000-0000000000e1"
CHANGE = "00000000-0000-4000-8000-0000000000c1"
EVIDENCE = "00000000-0000-4000-8000-0000000000d1"
CONTROL = "00000000-0000-4000-8000-0000000000d2"
CONFIRMATION = "00000000-0000-4000-8000-0000000000aa"
STATE: dict = {}


def refuse(code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {"code": code, "message": message, "request_id": "r", "details": details or {}}
    }


def route(method: str, path: str, body: dict, headers) -> tuple[int, object]:
    """A small stand-in for the grcHero API: just the routes these commands use."""
    bare = path.split("?", 1)[0]
    if STATE.get("refuse"):
        return STATE["refuse"]
    if (method, bare) == ("GET", "/api/v1/organizations"):
        return 200, [
            {"id": ORG, "name": "Acme", "slug": "acme"},
            {"id": OTHER_ORG, "name": "Beta", "slug": "beta"},
        ]
    if (method, bare) == ("GET", "/api/v1/projects"):
        return 200, [{"id": PROJECT, "name": "Customer portal", "status": "active"}]
    if (method, bare) == ("GET", "/api/v1/risks"):
        return 200, []
    if (method, bare) == ("GET", "/api/v1/findings"):
        if "cursor=" not in path:
            return 200, {"items": [STATE["finding"]], "next_cursor": "page2"}
        return 200, {"items": [{**STATE["finding"], "id": "second"}], "next_cursor": None}
    if (method, bare) == ("GET", f"/api/v1/findings/{FINDING}"):
        return 200, STATE["finding"]
    if (method, bare) == ("POST", f"/api/v1/findings/{FINDING}/transitions"):
        if body["expected_version"] != STATE["finding"]["version"]:
            return 409, refuse("version_conflict", "The finding changed. Reload it.")
        STATE["finding"] = {
            **STATE["finding"],
            "version": STATE["finding"]["version"] + 1,
            "effective_status": "in_progress",
        }
        return 200, STATE["finding"]
    if (method, bare) == ("GET", "/api/v1/exceptions/people"):
        return 200, [
            {"user_id": ME, "display_name": "Ada", "is_current_user": True},
            {"user_id": "someone", "display_name": "Bo", "is_current_user": False},
        ]
    if (method, bare) == ("POST", "/api/v1/exceptions"):
        STATE["exception"] = {**body, "id": EXCEPTION, "state": "draft", "version": 1}
        return 201, STATE["exception"]
    if (method, bare) == ("GET", f"/api/v1/exceptions/{EXCEPTION}"):
        return 200, STATE["exception"]
    if (method, bare) == ("POST", f"/api/v1/exceptions/{EXCEPTION}/decisions"):
        presented = headers.get("X-Grchero-Confirmation")
        if not presented:
            return 403, refuse(
                "confirmation_required",
                "Confirm this in your browser.",
                {
                    "confirmation_id": CONFIRMATION,
                    "confirm_url": f"https://app.example.test/confirm/{ORG}/{CONFIRMATION}",
                },
            )
        if presented != CONFIRMATION or STATE["confirmation"] != "confirmed":
            return 403, refuse("confirmation_invalid", "That confirmation cannot be used.")
        STATE["confirmation"] = "used"
        STATE["exception"] = {**STATE["exception"], "state": "approved", "version": 3}
        return 200, STATE["exception"]
    if (method, bare) == ("GET", f"/api/v1/confirmations/{CONFIRMATION}"):
        # The person confirms in the browser while the CLI waits.
        STATE["confirmation"] = "confirmed"
        return 200, {"state": "confirmed"}
    if (method, bare) == ("GET", "/api/v1/changes/people"):
        return 200, [{"user_id": ME, "display_name": "Ada", "is_current_user": True}]
    if (method, bare) == ("POST", "/api/v1/changes"):
        STATE["change"] = {**body, "id": CHANGE, "status": "draft", "version": 1}
        return 201, STATE["change"]
    if (method, bare) == ("GET", f"/api/v1/changes/{CHANGE}"):
        return 200, STATE["change"]
    if (method, bare) == ("POST", f"/api/v1/changes/{CHANGE}/implementation"):
        STATE["change"] = {**STATE["change"], **body, "status": "implemented", "version": 4}
        return 200, STATE["change"]
    if (method, bare) == ("GET", "/api/v1/controls"):
        return 200, [{"id": CONTROL, "code": "AC-2", "title": "Account management"}]
    if (method, bare) == ("POST", "/api/v1/evidence/links"):
        return 204, None
    if (method, bare) == ("GET", "/api/v1/notifications/inbox"):
        return 200, {
            "items": [{"id": "n1", "subject": "Review \x1b[2Jdue", "read_at": None}],
            "next_cursor": None,
        }
    if (method, bare) == ("POST", "/api/v1/notifications/read-all"):
        return 200, {"updated": 1}
    return 404, refuse("not_found", f"No route {method} {bare}")


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    STATE.clear()
    STATE.update(
        requests=[],
        confirmation="pending",
        finding={
            "id": FINDING,
            "title": "Admin panel without MFA",
            "severity": "high",
            "effective_status": "open",
            "version": 2,
        },
    )

    class Handler(BaseHTTPRequestHandler):
        def handle_one(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else {}
            STATE["requests"].append(
                {
                    "method": method,
                    "path": self.path,
                    "body": body,
                    "org": self.headers.get("X-Organization-ID"),
                    "confirmation": self.headers.get("X-Grchero-Confirmation"),
                }
            )
            status, payload = route(method, self.path, body, self.headers)
            data = b"" if status == 204 else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            self.handle_one("GET")

        def do_POST(self):  # noqa: N802
            self.handle_one("POST")

        def log_message(self, _format, *_args):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    config = tmp_path / "config"
    config.mkdir()
    (config / "credentials.json").write_text(
        json.dumps(
            {
                "api_url": f"http://127.0.0.1:{httpd.server_port}",
                "issuer_url": "http://127.0.0.1:8081",
                "client_id": "cli",
                "audience": "project",
                "access_token": "person-token",
                "expires_at": int(time.time()) + 600,
                "organization_id": ORG,
                "organization_name": "Acme",
            }
        )
    )
    monkeypatch.setenv("GRCHERO_CONFIG_DIR", str(config))
    for name in ("GRCHERO_API_TOKEN", "GRCHERO_ACCESS_TOKEN", "GRCHERO_AGENT", "CLAUDECODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(auth.webbrowser, "open", lambda _url: True)
    monkeypatch.setattr(auth.time, "sleep", lambda _seconds: None)
    yield config
    httpd.shutdown()


def requests(method: str, fragment: str) -> list[dict]:
    return [r for r in STATE["requests"] if r["method"] == method and fragment in r["path"]]


def test_help_json_lists_every_command_with_its_tier(capsys) -> None:
    assert main.main(["help", "--json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    names = {entry["name"]: entry for entry in catalog["commands"]}
    for command in commands.COMMANDS:
        assert names[command.name]["tier"] == command.tier
    # Hand-written commands sit beside catalog verbs in the same tree.
    assert {"scan", "deps", "api", "evidence add", "evidence link", "help"} <= set(names)
    assert names["exception approve"]["tier"] == "decide"
    approve = {a["name"] for a in names["exception approve"]["arguments"]}
    assert {"--json", "--no-wait", "--confirmation", "--version", "--project"} <= approve
    env = {a["name"]: a for a in names["change create"]["arguments"]}["--env"]
    assert env["repeatable"] is True
    assert catalog["exit_codes"]["3"].startswith("waiting")
    assert main.main(["help"]) == 0
    assert "finding decide" in capsys.readouterr().out


def test_project_use_scopes_lists_and_whoami(server, capsys) -> None:
    assert main.main(["project", "use", "customer portal"]) == 0
    saved = json.loads((server / "context.json").read_text())
    assert saved == {"projects": {ORG: {"id": PROJECT, "name": "Customer portal"}}}
    assert main.main(["whoami"]) == 0
    assert "Default project: Customer portal" in capsys.readouterr().out
    assert main.main(["finding", "list", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    # Every page is read, up to the limit.
    assert [item["id"] for item in listed] == [FINDING, "second"]
    first = requests("GET", "/findings?")[0]["path"]
    assert f"project_id={PROJECT}" in first and "active_only=true" in first
    assert main.main(["finding", "list", "--project", "none", "--limit", "1"]) == 0
    assert "project_id" not in requests("GET", "/findings?")[-1]["path"]
    assert "Admin panel without MFA" in capsys.readouterr().out
    assert main.main(["project", "use", "--clear"]) == 0
    assert json.loads((server / "context.json").read_text()) == {"projects": {}}
    assert main.main(["project", "use", "missing"]) == 2


def test_workflow_verbs_send_the_current_version(server, capsys) -> None:
    assert main.main(["finding", "start", FINDING, "--note", "On it"]) == 0
    sent = requests("POST", "/transitions")[-1]["body"]
    assert sent == {"expected_version": 2, "action": "start", "note": "On it"}
    assert "Finding is now in progress." in capsys.readouterr().out
    # A pinned version that is no longer current is refused, not overwritten.
    pinned = ["finding", "start", FINDING, "--note", "Again", "--version", "2", "--json"]
    assert main.main(pinned) == 1
    error = json.loads(capsys.readouterr().out)
    assert error["error"]["code"] == "version_conflict" and error["exit_code"] == 1
    assert main.main(["finding", "start", "not-an-id", "--note", "x"]) == 2
    assert main.main(["finding", "view"]) == 2


def test_a_decision_outside_a_terminal_stops_with_the_link_then_runs_once(server, capsys) -> None:
    created = main.main(
        [
            "exception",
            "create",
            "--kind",
            "policy",
            "--title",
            "Laptop rollout",
            "--reason",
            "Hardware arrives in December",
            "--measures",
            "Remote wipe",
            "--expires",
            "2027-01-31",
            "--json",
        ]
    )
    assert created == 0
    draft = json.loads(capsys.readouterr().out)
    assert draft["owner_id"] == ME and draft["expires_on"] == "2027-01-31"
    # Agents and scripts have no terminal: they get exit 3 and the link to show the person.
    assert main.main(["exception", "approve", EXCEPTION, "--note", "Fine", "--json"]) == 3
    waiting = json.loads(capsys.readouterr().out)
    assert waiting["error"]["code"] == "confirmation_required"
    assert waiting["error"]["details"]["confirmation_id"] == CONFIRMATION
    # Run again with the confirmation: the CLI waits for it, then sends it with the one write.
    rerun = ["exception", "approve", EXCEPTION, "--note", "Fine", "--confirmation", CONFIRMATION]
    assert main.main([*rerun, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "approved"
    decisions = requests("POST", "/decisions")
    assert [r["confirmation"] for r in decisions] == [None, CONFIRMATION]
    assert (
        decisions[0]["body"]
        == decisions[1]["body"]
        == {
            "expected_version": 1,
            "decision": "approve",
            "note": "Fine",
        }
    )
    assert main.main(["exception", "approve", EXCEPTION, "--confirmation", "nope"]) == 2


def test_change_records_document_a_release(server, capsys) -> None:
    create = ["change", "create", "--summary", "New billing page", "--type", "release"]
    args = [
        *create,
        "--title",
        "Release 2.4",
        "--risk",
        "medium",
        "--release",
        "v2.4.0",
        "--env",
        "staging",
        "--env",
        "production",
        "--reference",
        "https://ci.example.test/run/1",
        "--start",
        "2026-11-02T14:00",
    ]
    assert main.main(args) == 0
    body = requests("POST", "/api/v1/changes")[-1]["body"]
    assert body["environments"] == ["staging", "production"]
    assert body["references"] == [{"url": "https://ci.example.test/run/1"}]
    assert body["owner_id"] == ME and body["planned_start"] == "2026-11-02T14:00:00+00:00"
    assert "Change record drafted" in capsys.readouterr().out
    assert main.main(["change", "implement", CHANGE, "--outcome", "successful"]) == 0
    implemented = requests("POST", "/implementation")[-1]["body"]
    assert implemented["expected_version"] == 1 and implemented["outcome"] == "successful"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", implemented["started_at"])
    assert main.main([*create, "--title", "x", "--risk", "low", "--start", "soon"]) == 2


def test_not_allowed_is_exit_four_with_the_api_code(server, capsys) -> None:
    STATE["refuse"] = (403, refuse("agent_not_allowed", "Agents may only read here."))
    assert main.main(["risk", "list", "--json"]) == 4
    assert json.loads(capsys.readouterr().out) == {
        "error": {
            "code": "agent_not_allowed",
            "message": "Agents may only read here.",
            "details": {},
        },
        "exit_code": 4,
    }


def test_switching_workspaces(server, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    assert main.main(["org", "list"]) == 0
    assert "beta" in capsys.readouterr().out
    assert main.main(["risk", "list", "--org", "beta"]) == 0
    assert requests("GET", "/risks")[-1]["org"] == OTHER_ORG
    assert main.main(["org", "use", "beta"]) == 0
    saved = json.loads((server / "credentials.json").read_text())
    assert (saved["organization_id"], saved["organization_name"]) == (OTHER_ORG, "Beta")
    assert main.main(["org", "use", "nowhere"]) == 2
    monkeypatch.setenv("GRCHERO_API_TOKEN", "grc_token")
    monkeypatch.setenv("GRCHERO_ORGANIZATION_ID", ORG)
    assert main.main(["org", "use", "acme"]) == 2
    assert "GRCHERO_ORGANIZATION_ID" in capsys.readouterr().err


def test_evidence_links_and_inbox_text_is_safe(server, capsys) -> None:
    assert main.main(["evidence", "link", EVIDENCE, "--control", "ac-2"]) == 0
    assert requests("POST", "/evidence/links")[-1]["body"] == {
        "evidence_id": EVIDENCE,
        "control_id": CONTROL,
        "note": "",
    }
    assert "Linked to AC-2 Account management" in capsys.readouterr().out
    assert main.main(["inbox", "list"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "Review [2Jdue" in out
    assert main.main(["inbox", "read"]) == 2
    assert main.main(["inbox", "read", "--all"]) == 0
