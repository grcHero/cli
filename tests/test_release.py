"""The release build and the sign-in defaults it stamps in."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from grchero_cli import deployment, main

ROOT = Path(__file__).resolve().parents[1]
VALUES = {
    "api_url": "https://app.example.test",
    "issuer_url": "https://auth.example.test",
    "client_id": "cli-client",
    "audience": "project-1",
}


def test_source_checkouts_have_no_stamped_defaults() -> None:
    assert not (ROOT / "grchero_cli" / "deployment.json").exists()
    assert deployment.deployment_defaults() == {}


def test_login_uses_stamped_values_and_flags_win(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    class Signed:
        organization_name = "Acme"

    def fake_login(*args):
        calls.append(args)
        return Signed()

    monkeypatch.setattr(main, "deployment_defaults", lambda: dict(VALUES))
    monkeypatch.setattr(main, "login", fake_login)
    assert main.main(["login"]) == 0
    assert calls[-1] == (
        "https://app.example.test",
        "https://auth.example.test",
        "cli-client",
        "project-1",
        "",
    )
    assert main.main(["login", "--api-url", "https://other.example.test"]) == 0
    assert calls[-1][0] == "https://other.example.test"
    assert calls[-1][1] == "https://auth.example.test"


def test_release_build_makes_a_runnable_app_with_checksums(tmp_path: Path) -> None:
    values = tmp_path / "deployment.json"
    values.write_text(json.dumps(VALUES))
    out = tmp_path / "release"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_release.py"),
            "--out",
            str(out),
            "--deployment",
            str(values),
        ],
        check=True,
        capture_output=True,
    )
    manifest = json.loads((out / "manifest.json").read_text())
    assert set(manifest["files"]) == {"grchero.pyz"}
    assert (out / "VERSION").read_text().strip() == manifest["version"]
    assert manifest["files"]["grchero.pyz"]["sha256"] in (out / "SHA256SUMS").read_text()
    doctor = subprocess.run(
        [sys.executable, str(out / "grchero.pyz"), "doctor"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Sign-in: built in for https://app.example.test" in doctor.stdout
    # The stamped file goes into the release only, never the source tree.
    assert not (ROOT / "grchero_cli" / "deployment.json").exists()


def test_release_build_rejects_incomplete_values(tmp_path: Path) -> None:
    values = tmp_path / "deployment.json"
    values.write_text(json.dumps({"api_url": "https://app.example.test"}))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_release.py"),
            "--out",
            str(tmp_path / "release"),
            "--deployment",
            str(values),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and "issuer_url" in result.stderr
