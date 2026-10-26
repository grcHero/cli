"""Command interface for local reviews. Report files contain observations, not source."""

import argparse
import json
import os
import platform
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .auth import authorize_scan, load_credentials, login, logout
from .deployment import deployment_defaults
from .evidence import add_evidence
from .results import existing_findings, fingerprint, to_sarif
from .scanner import applicable_rule_ids, inspect_files
from .scope import CliError, collect, load_configuration, read_text
from .submit import submit as submit_report
from .work import display as display_work
from .work import run_work

RULES = [
    (
        "secret-in-env",
        "high",
        "Non-placeholder credential-like assignments in .env, .env.local, .env.production",
    ),
    ("production-debug", "medium", "DEBUG enabled in .env.production or .env.prod"),
    ("workflow-write-all", "medium", "Broad write-all permissions in GitHub Actions YAML"),
    (
        "workflow-pull-request-target",
        "medium",
        "Privileged pull_request_target event in GitHub Actions YAML",
    ),
    ("docker-user-review", "low", "Dockerfile without an explicit USER directive"),
    ("literal-credential", "high", "Credential-like literals in selected source files"),
    ("dynamic-evaluation", "medium", "Dynamic eval call in selected source files"),
]
SEVERITY = {"none": 4, "high": 3, "medium": 2, "low": 1}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="grchero",
        description="Run authenticated, local security reviews with grcHero.",
    )
    result.add_argument("--version", action="version", version=f"grchero {__version__}")
    commands = result.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Run a bounded local configuration review")
    scan.add_argument(
        "path", nargs="?", default=".", help="Project directory (default: current directory)"
    )
    scan.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Replace configured includes; repeat to add patterns",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Add an exclusion; exclusions always win",
    )
    scan.add_argument(
        "--dry-run", action="store_true", help="Show selected file paths without running rules"
    )
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument(
        "--baseline",
        metavar="FILE",
        help="An earlier JSON report; only new observations count for --fail-on",
    )
    scan.add_argument(
        "--output",
        metavar="FILE",
        help="Save a JSON report to a new file; existing files are never overwritten",
    )
    scan.add_argument(
        "--fail-on",
        choices=list(SEVERITY),
        default="none",
        help="CI threshold; exit 1 for findings at or above this severity",
    )
    commands.add_parser("rules", help="List supported checks and their scope")
    commands.add_parser("doctor", help="Check the local runtime and available capabilities")
    sign_in = commands.add_parser("login", help="Sign in through the browser")
    sign_in.add_argument("--api-url", default=os.getenv("GRCHERO_API_URL", ""))
    sign_in.add_argument("--issuer", default=os.getenv("GRCHERO_ISSUER_URL", ""))
    sign_in.add_argument("--client-id", default=os.getenv("GRCHERO_CLIENT_ID", ""))
    sign_in.add_argument("--audience", default=os.getenv("GRCHERO_AUDIENCE", ""))
    sign_in.add_argument("--organization", default="", help="Workspace ID or slug")
    commands.add_parser("logout", help="Remove the saved CLI session")
    commands.add_parser("whoami", help="Show the active grcHero workspace")
    evidence = commands.add_parser("evidence", help="Add evidence to your workspace")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    add = evidence_commands.add_parser(
        "add", help="Preview and, after confirmation, upload one evidence file"
    )
    add.add_argument("path", help="A PDF, DOCX, XLSX, CSV, TXT, PNG or JPEG file")
    add.add_argument("--name", help="Evidence name (default: the file name)")
    add.add_argument("--control", metavar="CODE_OR_ID", help="Link it to this control")
    add.add_argument("--project", metavar="UUID", help="Add it to a project")
    add.add_argument("--note", default="", help="Why this file supports the control")
    add.add_argument("--expires", metavar="YYYY-MM-DD", help="When the evidence goes stale")
    add.add_argument("--yes", action="store_true", help="Confirm without prompting")
    work = commands.add_parser("work", help="List the open work assigned to you")
    work.add_argument("--project", metavar="UUID", help="Only work in this project")
    work.add_argument("--format", choices=["text", "json"], default="text")
    report = commands.add_parser("report", help="Read an existing local JSON report")
    report.add_argument("path", help="Path to a saved report")
    report.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    send = commands.add_parser(
        "submit", help="Preview and, after confirmation, send a saved report to your workspace"
    )
    send.add_argument("path", help="Path to a report saved with --output")
    send.add_argument("--project", metavar="UUID", help="Attach the report to a project")
    send.add_argument("--title", help="Report title (default: derived from the scan date)")
    send.add_argument("--yes", action="store_true", help="Confirm without prompting")
    return result


def display(report: dict[str, Any], existing: set[str] | None = None) -> str:
    files = report["files"]
    findings = report["findings"]
    lines = [
        f"grcHero CLI {__version__} · Local configuration review",
        "",
        f"{len(files)} files reviewed · {len(findings)} observations",
        "Scope: selected configuration only. "
        "A clean result does not establish security or compliance.",
    ]
    applicable = report.get("applicable_rules")
    if isinstance(applicable, list):
        lines.append("Checks applied: " + (", ".join(applicable) if applicable else "none"))
    if not findings:
        lines.append("No observations from the enabled rules.")
    if existing is not None:
        new = sum(fingerprint(finding) not in existing for finding in findings)
        lines.append(f"Compared with the baseline: {new} new, {len(findings) - new} existing.")
    for finding in findings:
        marker = (
            " (in baseline)" if existing is not None and fingerprint(finding) in existing else ""
        )
        lines.extend(
            [
                "",
                f"[{finding['severity'].upper()}] {finding['title']}{marker}",
                f"  {finding['path']}:{finding['line']} · {finding['rule_id']}",
                f"  {finding['observation']}",
                f"  Next: {finding['recommendation']}",
            ]
        )
    lines.extend(
        ["", "Files stay on this machine. Reports omit source text and detected credential values."]
    )
    return "\n".join(lines)


def read_report(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > 2_097_152:
        raise CliError("Report must be an existing JSON file smaller than 2 MiB.")
    try:
        report = json.loads(read_text(path, 2_097_152))
        if (
            not isinstance(report, dict)
            or type(report.get("schema_version")) is not int
            or report.get("schema_version") != 1
        ):
            raise ValueError
        if not isinstance(report.get("files"), list) or not isinstance(
            report.get("findings"), list
        ):
            raise ValueError
        applicable = report.get("applicable_rules")
        if applicable is not None and (
            not isinstance(applicable, list)
            or len(applicable) > len(RULES)
            or len(set(applicable)) != len(applicable)
            or any(
                not isinstance(rule, str) or rule not in {item[0] for item in RULES}
                for rule in applicable
            )
        ):
            raise ValueError
        if (
            len(report["files"]) > 40
            or len(report["findings"]) > 100
            or not all(
                isinstance(file, str)
                and file
                and len(file) <= 300
                and not any(ord(character) < 32 for character in file)
                for file in report["files"]
            )
        ):
            raise ValueError
        for finding in report["findings"]:
            if not isinstance(finding, dict) or not all(
                isinstance(finding.get(key), str)
                for key in ["severity", "title", "path", "rule_id", "observation", "recommendation"]
            ):
                raise ValueError
            if (
                type(finding.get("line")) is not int
                or finding["line"] < 1
                or finding["severity"]
                not in {
                    "high",
                    "medium",
                    "low",
                }
            ):
                raise ValueError
            if any(
                ord(character) < 32
                for key in ["severity", "title", "path", "rule_id", "observation", "recommendation"]
                for character in finding[key]
            ):
                raise ValueError
    except (OSError, UnicodeError, ValueError, TypeError) as cause:
        raise CliError(
            "Invalid report. Use a schema_version 1 report created by grchero scan."
        ) from cause
    return report


def run(args: argparse.Namespace) -> int:
    if args.command == "login":
        # Flags and GRCHERO_* variables win; a release build supplies the rest.
        stamped = deployment_defaults()
        credentials = login(
            args.api_url or stamped.get("api_url", ""),
            args.issuer or stamped.get("issuer_url", ""),
            args.client_id or stamped.get("client_id", ""),
            args.audience or stamped.get("audience", ""),
            args.organization,
        )
        print(f"Signed in to {credentials.organization_name}.")
        return 0
    if args.command == "logout":
        logout()
        print("Signed out of grcHero CLI.")
        return 0
    if args.command == "whoami":
        credentials = load_credentials()
        kind = "API token" if credentials.is_api_token else "signed-in person"
        print(
            f"Workspace: {credentials.organization_name}\nAPI: {credentials.api_url}\n"
            f"Access: {kind}"
        )
        return 0
    if args.command == "evidence":
        url = add_evidence(
            Path(args.path),
            name=args.name,
            control=args.control,
            project=args.project,
            note=args.note,
            expires=args.expires,
            assume_yes=args.yes,
            stdin_is_terminal=sys.stdin.isatty(),
        )
        print(f"\nEvidence added for review:\n  {url}")
        return 0
    if args.command == "work":
        kinds, workspace = run_work(args.project)
        print(
            json.dumps({"workspace": workspace, "work": kinds}, indent=2)
            if args.format == "json"
            else display_work(kinds, workspace)
        )
        return 0
    if args.command == "rules":
        print("grcHero local checks\n")
        for rule, severity, description in RULES:
            print(f"{rule} [{severity}]\n  {description}")
        return 0
    if args.command == "doctor":
        api_url = deployment_defaults().get("api_url")
        print(
            f"grcHero CLI {__version__}\nPython {platform.python_version()}\n"
            f"Sign-in: {f'built in for {api_url}' if api_url else 'needs flags (source build)'}\n"
            "Local scanner: available after grcHero sign-in\n"
            "Source upload: disabled\nWorkspace reports: `grchero submit` after confirmation\n"
            "Documentation: /docs/cli"
        )
        return 0
    if args.command == "submit":
        report = read_report(Path(args.path))
        url = submit_report(
            report,
            title=args.title or f"CLI review {str(report.get('created_at', ''))[:10]}".strip(),
            project_id=args.project,
            assume_yes=args.yes,
            stdin_is_terminal=sys.stdin.isatty(),
        )
        print(f"\nDraft report created. Open it to review and edit:\n  {url}")
        return 0
    # Read the baseline first, so a bad file fails before a review is authorized.
    baseline = getattr(args, "baseline", None)
    existing = existing_findings(read_report(Path(baseline))) if baseline else None
    if args.command == "report":
        report = read_report(Path(args.path))
    else:
        if args.dry_run and (args.output or args.fail_on != "none" or args.baseline):
            raise CliError(
                "--dry-run previews scope only. "
                "Remove --output, --fail-on and --baseline when previewing."
            )
        if args.dry_run and args.format == "sarif":
            raise CliError("--dry-run has no observations to report. Use text or json.")
        root = Path(args.path).resolve()
        if not root.is_dir():
            raise CliError("Project directory does not exist. Pass a directory to grchero scan.")
        include, exclude = load_configuration(root)
        files = collect(root, args.include or include, exclude + args.exclude)
        if not files:
            raise CliError(
                "No files matched. Run from the project root or use --include 'path/to/Dockerfile'."
            )
        authorization = authorize_scan(__version__)
        if args.dry_run:
            manifest = {
                "mode": "local-preview",
                "files": [file.path for file in files],
                "applicable_rules": list(applicable_rule_ids([file.path for file in files])),
                "upload": False,
                "authorization_id": authorization.get("authorization_id"),
            }
            print(
                json.dumps(manifest, indent=2)
                if args.format == "json"
                else "Local review preview (nothing is uploaded)\n"
                + "\n".join(f"  {file.path}" for file in files)
            )
            return 0
        findings = inspect_files(files)
        applicable = list(applicable_rule_ids([file.path for file in files]))
        report = {
            "schema_version": 1,
            "cli_version": __version__,
            "rules_version": "2026.1",
            "mode": "local",
            "created_at": datetime.now(UTC).isoformat(),
            "files": [file.path for file in files],
            "applicable_rules": applicable,
            "findings": [asdict(finding) for finding in findings],
            "limitations": "Selected configuration heuristics only; "
            "not a full security or compliance assessment.",
        }
        if args.output:
            try:
                with Path(args.output).open("x", encoding="utf-8") as stream:
                    stream.write(json.dumps(report, indent=2) + "\n")
            except OSError as cause:
                raise CliError(
                    "Cannot create report. Choose a writable path that does not already exist."
                ) from cause
    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(report, RULES, __version__, existing), indent=2))
    else:
        print(display(report, existing))
    counted = [
        finding
        for finding in report["findings"]
        if existing is None or fingerprint(finding) not in existing
    ]
    if args.command == "scan" and any(
        SEVERITY[finding["severity"]] >= SEVERITY[args.fail_on] for finding in counted
    ):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (CliError, OSError) as cause:
        message = (
            str(cause)
            if isinstance(cause, CliError)
            else "Cannot read the selected project. Check permissions and try again."
        )
        print(f"grchero: {message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("grchero: Review cancelled.", file=sys.stderr)
        return 130
