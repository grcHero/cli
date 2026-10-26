"""`grchero evidence add` uploads one named file, after a preview, as unreviewed evidence."""

import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from grchero_cli import main

ORG = "00000000-0000-4000-8000-000000000001"
CONTROL = "00000000-0000-4000-8000-0000000000c1"
STATE: dict = {}


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    STATE.clear()
    STATE.update(
        uploads=[],
        links=[],
        evidence=[],
        controls=[
            {"id": CONTROL, "code": "CC6.1", "title": "Logical access"},
            {"id": "00000000-0000-4000-8000-0000000000c2", "code": "DUP", "title": "One"},
            {"id": "00000000-0000-4000-8000-0000000000c3", "code": "dup", "title": "Two"},
        ],
    )

    class Handler(BaseHTTPRequestHandler):
        def reply(self, body, status=200):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            assert self.headers["X-Organization-ID"] == ORG
            path = urlsplit(self.path).path
            if path == "/api/v1/evidence/capabilities":
                return self.reply(
                    {
                        "upload": True,
                        "max_upload_bytes": 1024,
                        "accepted_extensions": [".csv", ".pdf", ".txt"],
                    }
                )
            if path == "/api/v1/controls":
                return self.reply(STATE["controls"])
            if path == "/api/v1/evidence":
                return self.reply(STATE["evidence"])
            return self.reply({"error": {"message": "Not found."}}, 404)

        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            url = urlsplit(self.path)
            if url.path == "/api/v1/evidence/files":
                query = parse_qs(url.query)
                record = {
                    "id": "00000000-0000-4000-8000-0000000000e1",
                    "name": query["name"][0],
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
                STATE["uploads"].append({"query": query, "body": body})
                STATE["evidence"].append(record)
                return self.reply(record, 201)
            if url.path == "/api/v1/evidence/links":
                STATE["links"].append(json.loads(body))
                self.send_response(204)
                self.end_headers()
                return None
            return self.reply({"error": {"message": "Not found."}}, 404)

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
    yield
    server.shutdown()
    server.server_close()


def test_upload_links_the_control_and_a_rerun_does_not_upload_again(
    workspace, tmp_path: Path, capsys
) -> None:
    report = tmp_path / "test-results.csv"
    report.write_text("suite,passed\napi,120\n")
    arguments = [
        "evidence",
        "add",
        str(report),
        "--control",
        "cc6.1",
        "--note",
        "Nightly tests",
        "--expires",
        "2027-01-31",
        "--yes",
    ]
    assert main.main(arguments) == 0
    out = capsys.readouterr().out
    assert "Control:   CC6.1 Logical access" in out
    assert "added as unreviewed evidence" in out
    assert "/workspace/evidence" in out
    [upload] = STATE["uploads"]
    assert upload["body"] == report.read_bytes()
    assert upload["query"]["filename"] == ["test-results.csv"]
    assert upload["query"]["expires_on"] == ["2027-01-31"]
    assert STATE["links"] == [
        {
            "evidence_id": "00000000-0000-4000-8000-0000000000e1",
            "control_id": CONTROL,
            "note": "Nightly tests",
        }
    ]
    # Same content again (a CI rerun): no second upload, the link is simply repeated.
    assert main.main(arguments) == 0
    assert "will not be uploaded again" in capsys.readouterr().out
    assert len(STATE["uploads"]) == 1 and len(STATE["links"]) == 2


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("app.py", "print('hi')\n", "not accepted as evidence"),
        ("big.txt", "x" * 2000, "larger than the upload limit"),
        ("empty.pdf", "", "empty"),
    ],
)
def test_refuses_files_the_workspace_would_not_accept(
    workspace, tmp_path: Path, capsys, name: str, content: str, message: str
) -> None:
    path = tmp_path / name
    path.write_text(content)
    assert main.main(["evidence", "add", str(path), "--yes"]) == 2
    assert message in capsys.readouterr().err
    assert STATE["uploads"] == []


def test_refuses_folders_ambiguous_controls_and_unconfirmed_uploads(
    workspace, tmp_path: Path, capsys
) -> None:
    assert main.main(["evidence", "add", str(tmp_path), "--yes"]) == 2
    report = tmp_path / "proof.pdf"
    report.write_bytes(b"%PDF-1.4 proof")
    assert main.main(["evidence", "add", str(report), "--control", "DUP", "--yes"]) == 2
    assert "More than one control" in capsys.readouterr().err
    assert main.main(["evidence", "add", str(report), "--control", "NOPE", "--yes"]) == 2
    # Outside a terminal, nothing is uploaded without --yes.
    assert main.main(["evidence", "add", str(report)]) == 2
    assert "Confirmation needed" in capsys.readouterr().err
    assert STATE["uploads"] == [] and STATE["links"] == []
