"""`grchero work` lists assigned work from the same lists as the browser's My work."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from grchero_cli import main

ORG = "00000000-0000-4000-8000-000000000001"
SEEN: list[str] = []


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    SEEN.clear()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            SEEN.append(self.path)
            assert self.headers["Authorization"] == "Bearer person-token"
            assert self.headers["X-Organization-ID"] == ORG
            if self.path.startswith("/api/v1/questionnaire-work"):
                status, body = 403, {"error": {"message": "No access."}}
            elif self.path.startswith("/api/v1/findings"):
                status, body = (
                    200,
                    {
                        "items": [
                            {
                                "title": "Rotate the \x1b[31mleaked key",
                                "effective_status": "in_progress",
                                "due_date": "2026-11-01",
                            }
                        ],
                        "next_cursor": None,
                    },
                )
            elif self.path.startswith("/api/v1/vendor-reviews"):
                status, body = (
                    200,
                    {
                        "items": [{"vendor_name": "Acme Mail", "status": "submitted"}],
                        "next_cursor": "more",
                    },
                )
            else:
                status, body = 200, {"items": [], "next_cursor": None}
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = tmp_path / "config"
    config.mkdir()
    (config / "credentials.json").write_text(
        json.dumps(
            {
                "api_url": f"http://127.0.0.1:{server.server_port}",
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
    monkeypatch.delenv("GRCHERO_API_TOKEN", raising=False)
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_work_lists_only_kinds_with_assigned_items(workspace, capsys) -> None:
    assert main.main(["work"]) == 0
    out = capsys.readouterr().out
    assert "Your open work in Acme: 2+" in out
    assert "Findings (1)" in out and "Vendor reviews (1+)" in out
    assert "Rotate the [31mleaked key · in progress · due 2026-11-01" in out
    assert "\x1b" not in out
    assert f"Open: {workspace}/workspace/findings?mine=1&work=vendors" in out
    # Kinds with nothing assigned, and kinds the role cannot read, are left out.
    assert "Evidence requests" not in out and "Questionnaires" not in out


def test_work_json_and_project_filter(workspace, capsys) -> None:
    project = "00000000-0000-4000-8000-0000000000aa"
    assert main.main(["work", "--project", project, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [kind["kind"] for kind in data["work"]] == ["findings", "vendors"]
    assert all(f"project_id={project}" in path for path in SEEN)
    assert main.main(["work", "--project", "not-a-uuid"]) == 2
