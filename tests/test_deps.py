"""`grchero deps` sends only hashed name prefixes and decides affected-ness locally."""

import hashlib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from grchero_cli import main
from grchero_cli.deps import MAX_PREFIXES, build_queries, normalize, prefix
from grchero_cli.lockfiles import Package

ORG = "00000000-0000-4000-8000-000000000001"
REQUESTS: list[bytes] = []
STATE: dict[str, object] = {}

PACKAGE_LOCK = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/evil-pkg": {"version": "1.0.0"},
        },
    }
)
REQUIREMENTS = "Django==4.2.1\nflask>=2\n"
GEMFILE = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n"
SECRETS = ["lodash", "evil-pkg", "django", "Django", "rails", "4.17.20", "4.2.1", "7.0.4", "1.0.0"]


def advisory(**fields: object) -> dict[str, object]:
    return {
        "summary": "",
        "severity": "unknown",
        "malicious": False,
        "aliases": [],
        "versions": [],
        "ranges": [],
        "fixed": [],
        "url": f"https://osv.dev/vulnerability/{fields['id']}",
        **fields,
    }


ADVISORIES = [
    advisory(
        id="GHSA-35jh-r3h4-6jhm",
        ecosystem="npm",
        package="lodash",
        summary="Command injection in \x1b[31mlodash template",
        severity="high",
        aliases=["CVE-2021-23337"],
        ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        fixed=["4.17.21"],
    ),
    advisory(
        id="GHSA-old",
        ecosystem="npm",
        package="lodash",
        severity="critical",
        ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}],
    ),
    # Same bucket, someone else's package: the CLI must drop it.
    advisory(
        id="GHSA-other",
        ecosystem="npm",
        package="lodash-es",
        severity="critical",
        ranges=[{"type": "SEMVER", "events": [{"introduced": "0"}]}],
    ),
    advisory(id="MAL-2026-1", ecosystem="npm", package="evil-pkg", malicious=True),
    advisory(
        id="GHSA-dj",
        ecosystem="PyPI",
        package="django",
        summary="SQL injection",
        severity="medium",
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "4.2"}, {"fixed": "4.2.2"}]}],
    ),
    advisory(
        id="GHSA-rails",
        ecosystem="RubyGems",
        package="rails",
        severity="low",
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "main"}]}],
    ),
    advisory(id="GHSA-wrong-eco", ecosystem="npm", package="django", severity="critical"),
]


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    REQUESTS.clear()
    STATE.clear()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            assert self.path == "/api/v1/cli/advisories"
            assert self.headers["Authorization"] == "Bearer person-token"
            assert self.headers["X-Organization-ID"] == ORG
            REQUESTS.append(self.rfile.read(int(self.headers["Content-Length"])))
            status, body = STATE.get("response") or (
                200,
                {"advisories": ADVISORIES, "database": {"updated_at": "2026-10-25T03:00:00Z"}},
            )
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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
    monkeypatch.delenv("GRCHERO_API_TOKEN", raising=False)
    monkeypatch.delenv("GRCHERO_ACCESS_TOKEN", raising=False)
    yield
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "web").mkdir(parents=True)
    (root / "web" / "package-lock.json").write_text(PACKAGE_LOCK)
    (root / "requirements.txt").write_text(REQUIREMENTS)
    (root / "Gemfile.lock").write_text(GEMFILE)
    return root


def test_normalization_and_prefixes() -> None:
    assert normalize("PyPI", "Zope.Interface__x") == "zope-interface-x"
    assert normalize("npm", "@Babel/Core") == "@babel/core"
    assert normalize("crates.io", "Serde_JSON") == "serde-json"
    assert normalize("Go", "github.com/Foo/Bar") == "github.com/Foo/Bar"
    assert normalize("RubyGems", "Rails") == "Rails"
    assert normalize("Packagist", "Monolog/Monolog") == "monolog/monolog"
    assert normalize("NuGet", "Newtonsoft.Json") == "newtonsoft.json"
    assert prefix("npm", "Lodash") == hashlib.sha256(b"lodash").hexdigest()[:4]
    assert prefix("PyPI", "Django_REST") == hashlib.sha256(b"django-rest").hexdigest()[:4]


def test_queries_are_sorted_unique_and_chunked() -> None:
    packages = {Package("npm", f"pkg-{index}", "1.0.0"): ["a"] for index in range(30_000)}
    packages[Package("PyPI", "requests", "2.0.0")] = ["b"]
    packages[Package("PyPI", "requests", "2.1.0")] = ["b"]
    bodies = build_queries(packages)
    assert len(bodies) > 1
    npm = [
        v for b in bodies for q in b["queries"] if q["ecosystem"] == "npm" for v in q["prefixes"]
    ]
    assert all(len(query["prefixes"]) <= MAX_PREFIXES for b in bodies for query in b["queries"])
    assert len(npm) == len(set(npm))
    first = bodies[0]["queries"]
    assert [query["ecosystem"] for query in first] == ["npm", "PyPI"]
    assert first[0]["prefixes"] == sorted(first[0]["prefixes"])
    assert first[1]["prefixes"] == [prefix("PyPI", "requests")]


def test_request_contains_only_hash_prefixes(server, project: Path, capsys) -> None:
    assert main.main(["deps", str(project)]) == 0
    assert len(REQUESTS) == 1
    raw = REQUESTS[0].decode()
    body = json.loads(raw)
    assert set(body) == {"queries"}
    sent = {query["ecosystem"]: query["prefixes"] for query in body["queries"]}
    assert sent == {
        "npm": sorted({prefix("npm", "lodash"), prefix("npm", "evil-pkg")}),
        "PyPI": [prefix("PyPI", "django")],
        "RubyGems": [prefix("RubyGems", "rails")],
    }
    for query in body["queries"]:
        assert set(query) == {"ecosystem", "prefixes"}
        assert all(re.fullmatch(r"[0-9a-f]{4}", value) for value in query["prefixes"])
    for secret in SECRETS:
        assert secret not in raw
    assert "package-lock" not in raw and "requirements" not in raw


def test_text_output(server, project: Path, capsys) -> None:
    assert main.main(["deps", str(project)]) == 0
    out = capsys.readouterr().out
    assert "· Dependency check" in out
    assert "3 lockfiles · 4 packages (npm 2, PyPI 1, RubyGems 1)" in out
    assert "3 affected · 1 possibly affected" in out
    assert "requirements.txt: 1 requirement(s) without an exact == pin" in out
    assert "[HIGH] lodash 4.17.20 · GHSA-35jh-r3h4-6jhm (CVE-2021-23337)" in out
    assert "Command injection in [31mlodash template" in out and "\x1b" not in out
    assert "Fix: upgrade to 4.17.21" in out
    assert "  web/package-lock.json" in out
    assert "[CRITICAL] evil-pkg 1.0.0 · MAL-2026-1" in out
    assert "Malicious package: remove it and rotate any credentials it could reach." in out
    assert "[MEDIUM] django 4.2.1 · GHSA-dj" in out
    assert "Fix: upgrade to 4.2.2" in out
    assert "[LOW] rails 7.0.4 · GHSA-rails" in out and "Possibly affected" in out
    for dropped in ("GHSA-old", "GHSA-other", "GHSA-wrong-eco"):
        assert dropped not in out
    assert out.index("MAL-2026-1") < out.index("GHSA-35jh") < out.index("GHSA-dj")
    assert (
        "Only hashed name prefixes left this machine. "
        "Advisories: OSV.dev, as mirrored by grcHero (updated 2026-10-25)." in out
    )


def test_fail_on_thresholds(server, project: Path, capsys) -> None:
    (project / "web" / "package-lock.json").unlink()
    assert main.main(["deps", str(project), "--fail-on", "high"]) == 0
    assert main.main(["deps", str(project), "--fail-on", "medium"]) == 1
    assert main.main(["deps", str(project), "--fail-on", "none"]) == 0
    (project / "web" / "package-lock.json").write_text(PACKAGE_LOCK)
    assert main.main(["deps", str(project), "--fail-on", "critical"]) == 1


def test_json_report_and_output_file(server, project: Path, tmp_path: Path, capsys) -> None:
    output = tmp_path / "deps.json"
    assert main.main(["deps", str(project), "--format", "json", "--output", str(output)]) == 0
    printed = json.loads(capsys.readouterr().out)
    saved = json.loads(output.read_text())
    assert printed == saved
    assert saved["schema_version"] == 1 and saved["kind"] == "dependency-check"
    assert saved["packages"] == {"npm": 2, "PyPI": 1, "RubyGems": 1}
    assert saved["database"] == {"source": "OSV.dev", "updated_at": "2026-10-25T03:00:00Z"}
    malicious = next(item for item in saved["findings"] if item["advisory_id"] == "MAL-2026-1")
    assert malicious["malicious"] is True and malicious["severity"] == "critical"
    assert malicious["status"] == "affected" and malicious["fixed_in"] is None
    rails = next(item for item in saved["findings"] if item["package"] == "rails")
    assert rails["status"] == "possibly_affected"
    # Never overwrite an existing report, and refuse before contacting grcHero.
    REQUESTS.clear()
    assert main.main(["deps", str(project), "--output", str(output)]) == 2
    assert "does not already exist" in capsys.readouterr().err
    assert REQUESTS == []


def test_sarif_shape(server, project: Path, capsys) -> None:
    assert main.main(["deps", str(project), "--format", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"MAL-2026-1", "GHSA-35jh-r3h4-6jhm", "GHSA-dj", "GHSA-rails"}
    assert rules["MAL-2026-1"]["properties"]["security-severity"] == "9.5"
    lodash = next(item for item in run["results"] if item["ruleId"] == "GHSA-35jh-r3h4-6jhm")
    assert lodash["level"] == "error"
    location = lodash["locations"][0]["physicalLocation"]
    assert location == {
        "artifactLocation": {"uri": "web/package-lock.json", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 1},
    }
    expected = hashlib.sha256(b"npm\x1flodash\x1fGHSA-35jh-r3h4-6jhm").hexdigest()[:32]
    assert lodash["partialFingerprints"] == {"grcheroDependency/v1": expected}
    assert "Upgrade to 4.17.21." in lodash["message"]["text"]
    levels = {item["ruleId"]: item["level"] for item in run["results"]}
    assert levels["GHSA-dj"] == "warning" and levels["GHSA-rails"] == "note"


def test_package_json_without_lockfile_is_not_guessed(server, tmp_path: Path, capsys) -> None:
    root = tmp_path / "bare"
    root.mkdir()
    (root / "package.json").write_text('{"dependencies": {"lodash": "^4.17.20"}}')
    assert main.main(["deps", str(root)]) == 0
    out = capsys.readouterr().out
    assert "No supported lockfiles found." in out
    assert "package.json: no lockfile, versions unknown. Skipped." in out
    assert REQUESTS == []


def test_server_errors_and_bad_responses(server, project: Path, capsys) -> None:
    STATE["response"] = (403, {"error": {"message": "This workspace cannot run checks."}})
    assert main.main(["deps", str(project)]) == 2
    assert "This workspace cannot run checks." in capsys.readouterr().err
    STATE["response"] = (200, {"advisories": "nope"})
    assert main.main(["deps", str(project)]) == 2
    assert "invalid advisory response" in capsys.readouterr().err


def test_requires_sign_in(tmp_path: Path, project: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("GRCHERO_CONFIG_DIR", str(tmp_path / "empty"))
    monkeypatch.delenv("GRCHERO_API_TOKEN", raising=False)
    monkeypatch.delenv("GRCHERO_ACCESS_TOKEN", raising=False)
    assert main.main(["deps", str(project)]) == 2
    assert "grchero login" in capsys.readouterr().err
