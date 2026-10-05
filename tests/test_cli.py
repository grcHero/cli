"""Exercise the shipped command and its filesystem/report boundaries."""

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

import pytest

from grchero_cli.scanner import applicable_rule_ids, inspect_files
from grchero_cli.scope import CliError, LocalFile, collect

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def authenticated_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            assert self.path == "/api/v1/cli/scan-authorizations"
            assert self.headers["Authorization"] == "Bearer test-access-token"
            assert self.headers["X-Organization-ID"] == "00000000-0000-4000-8000-000000000001"
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            assert payload["cli_version"] == "0.2.0"
            UUID(payload["request_id"])
            body = json.dumps(
                {
                    "authorization_id": "00000000-0000-7000-8000-000000000002",
                    "allowed": True,
                    "billing_enforced": False,
                    "remaining_credits": None,
                    "usage_count": 1,
                    "created_at": "2026-10-05T00:00:00Z",
                }
            ).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "cli-config"
    config.mkdir()
    (config / "credentials.json").write_text(
        json.dumps(
            {
                "api_url": f"http://127.0.0.1:{server.server_port}",
                "issuer_url": "http://127.0.0.1:8081",
                "client_id": "cli-test",
                "audience": "project-test",
                "access_token": "test-access-token",
                "expires_at": int(time.time()) + 600,
                "organization_id": "00000000-0000-4000-8000-000000000001",
                "organization_name": "Test workspace",
            }
        )
    )
    monkeypatch.setenv("GRCHERO_CONFIG_DIR", str(config))
    yield
    server.shutdown()
    server.server_close()


def invoke(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "grchero_cli", "scan", str(path), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=os.environ.copy(),
    )


def test_default_scope_is_private_and_rules_match_selected_files(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    (tmp_path / ".env.production").write_text("API_KEY=private-test-value\n", encoding="utf-8")
    dependencies = tmp_path / "node_modules"
    dependencies.mkdir()
    (dependencies / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    (tmp_path / "linked").symlink_to(dependencies, target_is_directory=True)
    result = invoke(tmp_path, "--format", "json")
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["files"] == ["Dockerfile"]
    assert report["applicable_rules"] == ["docker-user-review"]
    assert report["findings"][0]["rule_id"] == "docker-user-review"
    assert "private-test-value" not in result.stdout
    assert applicable_rule_ids(report["files"]) == ("docker-user-review",)
    assert (
        inspect_files([LocalFile("Dockerfile", "FROM alpine\n")])[0].rule_id == "docker-user-review"
    )


def test_explicit_secret_scope_threshold_and_saved_report(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        "API_KEY=private-test-value\nDEBUG=true\n", encoding="utf-8"
    )
    output = tmp_path / "review.json"
    result = invoke(
        tmp_path, "--include", ".env.production", "--output", str(output), "--fail-on", "high"
    )
    assert result.returncode == 1
    assert "private-test-value" not in result.stdout + output.read_text()
    report = subprocess.run(
        [
            sys.executable,
            "-m",
            "grchero_cli",
            "report",
            str(output),
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert report.returncode == 0
    assert json.loads(report.stdout) == json.loads(output.read_text())
    assert invoke(tmp_path, "--include", ".env.production", "--output", str(output)).returncode == 2


def test_preview_does_not_run_rules_or_write_reports(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    result = invoke(tmp_path, "--dry-run", "--format", "json")
    preview = json.loads(result.stdout)
    UUID(preview.pop("authorization_id"))
    assert preview == {
        "mode": "local-preview",
        "files": ["Dockerfile"],
        "applicable_rules": ["docker-user-review"],
        "upload": False,
    }
    assert invoke(tmp_path, "--dry-run", "--output", str(tmp_path / "report.json")).returncode == 2
    assert not (tmp_path / "report.json").exists()


def test_configuration_exclusions_and_cli_override(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER app\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("TOKEN=placeholder\n", encoding="utf-8")
    (tmp_path / ".grchero.json").write_text(
        json.dumps({"include": [".env.local"], "exclude": ["Dockerfile"]})
    )
    assert json.loads(invoke(tmp_path, "--format", "json").stdout)["files"] == [".env.local"]
    assert invoke(tmp_path, "--include", "Dockerfile").returncode == 2
    assert invoke(tmp_path, "--include", "../Dockerfile").returncode == 2


@pytest.mark.parametrize("content", ["not json", '{"upload": true}', '{"include": "/etc/*"}'])
def test_invalid_configuration_fails_clearly(tmp_path: Path, content: str) -> None:
    (tmp_path / ".grchero.json").write_text(content)
    result = invoke(tmp_path)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_oversize_binary_and_unsupported_scope_are_rejected(tmp_path: Path) -> None:
    file = tmp_path / "Dockerfile"
    for content in ["x" * 262_145, "FROM alpine\n\x00"]:
        file.write_text(content)
        with pytest.raises(CliError):
            collect(tmp_path, ["Dockerfile"], [])
    (tmp_path / "notes.md").write_text("not a supported review target")
    assert invoke(tmp_path, "--include", "notes.md").returncode == 2


def test_invalid_report_rejects_terminal_control_characters(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    report = json.loads(invoke(tmp_path, "--format", "json").stdout)
    report["findings"][0]["title"] = "\x1b[31mspoofed"
    output = tmp_path / "report.json"
    output.write_text(json.dumps(report))
    result = subprocess.run(
        [sys.executable, "-m", "grchero_cli", "report", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "spoofed" not in result.stdout + result.stderr


def test_file_count_and_total_size_limits(tmp_path: Path) -> None:
    for index in range(41):
        directory = tmp_path / str(index)
        directory.mkdir()
        (directory / "Dockerfile").write_text("FROM alpine\n")
    with pytest.raises(CliError, match="40 files"):
        collect(tmp_path, ["**/Dockerfile"], [])
    for index in range(5):
        (tmp_path / str(index) / "Dockerfile").write_text("#" * 262_144)
    with pytest.raises(CliError, match="1 MiB"):
        collect(tmp_path, [f"{index}/Dockerfile" for index in range(5)], [])


def test_file_symlinks_and_clean_threshold(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_text("FROM alpine\n")
    (tmp_path / "Dockerfile").symlink_to(target)
    assert invoke(tmp_path).returncode == 2
    (tmp_path / "Dockerfile").unlink()
    (tmp_path / "Dockerfile").write_text("FROM alpine\nUSER app\n")
    assert invoke(tmp_path, "--fail-on", "low").returncode == 0


def test_noisy_workflow_cannot_hide_high_severity_ci_failure(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "noisy.yml").write_text("permissions: write-all\n" * 150)
    (tmp_path / ".env.production").write_text("API_KEY=private-test-value\n")
    result = invoke(
        tmp_path,
        "--include",
        ".github/workflows/*.yml",
        "--include",
        ".env.production",
        "--format",
        "json",
        "--fail-on",
        "high",
    )
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert len(report["findings"]) == 100
    assert report["findings"][0]["severity"] == "high"


def test_scan_requires_a_live_grchero_session(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    env = os.environ.copy()
    env["GRCHERO_CONFIG_DIR"] = str(tmp_path / "missing-config")
    result = subprocess.run(
        [sys.executable, "-m", "grchero_cli", "scan", str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 2
    assert "grchero login" in result.stderr
