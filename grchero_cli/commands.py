"""Workspace commands: `grchero <area> <verb>` for every area people work in (ADR 0017).

This module holds the everyday areas and joins them with the assurance, operations and
administration areas into one `COMMANDS` list; `catalog` holds the framework.
"""

import argparse
from collections.abc import Callable
from typing import Any

from . import catalog
from . import evidence as evidence_module
from .admin import COMMANDS as ADMIN
from .assurance import COMMANDS as ASSURANCE
from .catalog import (
    DECISION_NOTE,
    EXIT_CODES,
    ID,
    LIMIT,
    NOTE,
    VERSION,
    Arg,
    Command,
    Output,
    as_day,
    as_id,
    as_moment,
    clean,
    current_version,
    done,
    label,
    now,
    pages,
    person,
    record,
    table,
    workflow,
    workspace,
)
from .operations import COMMANDS as OPERATIONS
from .scope import CliError
from .workspace import (
    NO_PROJECT,
    Workspace,
    find_project,
    open_workspace,
    organizations,
    save_project,
    saved_project,
    use_organization,
)

__all__ = ["COMMANDS", "EXIT_CODES", "clean", "describe", "install", "run"]

# Organizations


def org_list(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    items = [
        {**item, "current": "yes" if str(item.get("id")) == ws.organization_id else ""}
        for item in organizations(ws.credentials)
    ]
    columns = [("name", "Workspace"), ("slug", "Slug"), ("current", "Current"), ("id", "ID")]
    return Output(items, table(items, columns, "No workspaces for this account."))


def org_view(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    item = ws.get("/organizations/current")
    saved = saved_project(ws.organization_id)
    text = record(item, [("name", "Workspace"), ("slug", "Slug"), ("id", "ID")])
    if saved:
        text += f"\nDefault project: {clean(saved['name'])}"
    return Output(item, text)


def org_use(args: argparse.Namespace) -> Output:
    credentials = use_organization(args.workspace)
    data = {"id": credentials.organization_id, "name": credentials.organization_name}
    return Output(data, f"Now using {clean(credentials.organization_name)}.")


# Projects

PROJECT_COLUMNS = [
    ("name", "Project"),
    ("status", "Status"),
    ("open_findings", "Open findings"),
    ("default", "Default"),
    ("id", "ID"),
]
PROJECT_FIELDS = [
    ("name", "Project"),
    ("status", "Status"),
    ("description", "Description"),
    ("asset_count", "Assets"),
    ("checklist_implemented", "Checklist done"),
    ("checklist_applicable", "Checklist items"),
    ("open_findings", "Open findings"),
    ("overdue_evidence_requests", "Overdue requests"),
    ("id", "ID"),
]


def project_list(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    saved = saved_project(ws.organization_id)
    items = [
        {**item, "default": "yes" if saved and str(item.get("id")) == saved["id"] else ""}
        for item in ws.get("/projects", include_archived=args.archived)
        if isinstance(item, dict)
    ]
    return Output(items, table(items, PROJECT_COLUMNS, "No projects yet."))


def project_view(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, args.id)
    if not ws.project_id:
        raise CliError("Name a project, or set one with `grchero project use`.")
    item = ws.get(f"/projects/{ws.project_id}")
    return Output(item, record(item, PROJECT_FIELDS, ws.page("/workspace/projects")))


def project_create(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    item = ws.call("POST", "/projects", {"name": args.name, "description": args.description or ""})
    if args.use:
        save_project(ws.organization_id, item)
    message = "Project created" + (" and set as the default." if args.use else ".")
    return done(item, message, [("name", "Project"), ("id", "ID")], "")


def project_use(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    if args.clear:
        save_project(ws.organization_id, None)
        return Output({"project": None}, "Commands now act on the whole workspace.")
    if not args.project_name:
        raise CliError("Name a project, or pass --clear to stop using one.")
    item = find_project(ws.credentials, args.project_name)
    save_project(ws.organization_id, item)
    return Output(
        {"project": {"id": item["id"], "name": item["name"]}},
        f"Commands in this workspace now use {clean(item['name'])}. "
        "Pass --project none to act on the whole workspace.",
    )


# Inbox


def inbox_list(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    items = pages(ws, "/notifications/inbox", args.limit or 50, unread=args.unread)
    rows = [{**item, "state": "read" if item.get("read_at") else "unread"} for item in items]
    columns = [("subject", "Message"), ("state", "State"), ("created_at", "Sent"), ("id", "ID")]
    return Output(items, table(rows, columns, "Your inbox is empty."))


def inbox_read(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    if args.all:
        return Output(ws.call("POST", "/notifications/read-all", {}), "Marked every message read.")
    if not args.id:
        raise CliError("Give a message ID, or --all.")
    item = ws.call("POST", f"/notifications/{as_id(args.id)}/read", {"read": True})
    return Output(item, f"Marked read: {clean(item.get('subject'))}")


# Findings

FINDING_COLUMNS = [
    ("title", "Finding"),
    ("severity", "Severity"),
    ("effective_status", "Status"),
    ("owner_name", "Owner"),
    ("due_date", "Due"),
    ("id", "ID"),
]
FINDING_FIELDS = [
    ("title", "Finding"),
    ("severity", "Severity"),
    ("effective_status", "Status"),
    ("description", "Description"),
    ("owner_name", "Owner"),
    ("reviewer_name", "Reviewer"),
    ("due_date", "Due"),
    ("remediation_plan", "Plan"),
    ("test_procedure", "Test"),
    ("exception_expires_on", "Exception until"),
    ("version", "Version"),
    ("id", "ID"),
]


def _finding_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/findings?finding={item.get('id')}")


def finding_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = pages(
        ws,
        "/findings",
        args.limit or 50,
        project_id=ws.project_id,
        mine=args.mine,
        active_only=not args.all,
    )
    return Output(items, table(items, FINDING_COLUMNS, "No open findings."))


def finding_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/findings/{as_id(args.id)}")
    return Output(item, record(item, FINDING_FIELDS, _finding_link(ws, item)))


def finding_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "title": args.title,
        "description": args.description or "",
        "severity": args.severity,
        "project_id": ws.project_id,
        "affected_asset_id": as_id(args.asset, "--asset") if args.asset else None,
    }
    item = ws.call("POST", "/findings", body)
    return done(item, "Finding recorded.", FINDING_FIELDS, _finding_link(ws, item))


def finding_edit(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    path = f"/findings/{as_id(args.id)}"
    current = ws.get(path)
    owner = person(ws, "/findings/assignees", args.owner) if args.owner else current.get("owner_id")
    if not owner:
        raise CliError("This finding has no owner yet. Pass --owner me or a person.")
    reviewer = (
        person(ws, "/findings/assignees", args.reviewer)
        if args.reviewer
        else current.get("reviewer_id")
    )
    body = {
        "expected_version": args.version if args.version is not None else current["version"],
        "project_id": current.get("project_id"),
        "owner_id": owner,
        "reviewer_id": reviewer,
        "due_date": as_day(args.due, "--due") or current.get("due_date"),
        "affected_asset_id": current.get("affected_asset_id"),
        "remediation_plan": args.plan if args.plan is not None else current.get("remediation_plan"),
        "test_procedure": args.test if args.test is not None else current.get("test_procedure"),
        "control_id": current.get("control_id"),
        "note": args.note or "",
    }
    item = ws.call("PATCH", path, {key: value for key, value in body.items() if value is not None})
    return done(item, "Finding updated.", FINDING_FIELDS, _finding_link(ws, item))


def _finding_transition(action: str) -> Callable[[argparse.Namespace], Output]:
    def run(args: argparse.Namespace) -> Output:
        ws = workspace(args)
        path = f"/findings/{as_id(args.id)}"
        body = {
            "expected_version": current_version(ws, path, args.version),
            "action": action,
            "note": args.note,
        }
        item = ws.call("POST", f"{path}/transitions", body)
        message = f"Finding is now {label(item.get('effective_status'))}."
        return done(item, message, FINDING_FIELDS[:3], _finding_link(ws, item))

    return run


def finding_decide(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    path = f"/findings/{as_id(args.id)}"
    body = {
        "expected_version": current_version(ws, path, args.version),
        "outcome": args.outcome,
        "note": args.note,
        "expires_on": as_day(args.expires, "--expires"),
    }
    item = ws.call("POST", f"{path}/decisions", body)
    return done(item, "Decision recorded.", FINDING_FIELDS[:3], _finding_link(ws, item))


# Risks

RISK_COLUMNS = [("title", "Risk"), ("status", "Status"), ("target_type", "About"), ("id", "ID")]
RISK_FIELDS = [
    ("title", "Risk"),
    ("status", "Status"),
    ("description", "Description"),
    ("target_type", "About"),
    ("updated_at", "Updated"),
    ("id", "ID"),
]


def risk_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = [i for i in ws.get("/risks", project_id=ws.project_id) if isinstance(i, dict)]
    return Output(items, table(items, RISK_COLUMNS, "No risks recorded."))


def risk_view(args: argparse.Namespace) -> Output:
    ws = open_workspace(args.org, NO_PROJECT)
    wanted = as_id(args.id)
    risks = [i for i in ws.get("/risks") if isinstance(i, dict)]
    item = next((i for i in risks if i.get("id") == wanted), None)
    if item is None:
        raise CliError("No risk with that ID in this workspace.", 1)
    return Output(item, record(item, RISK_FIELDS, ws.page("/workspace/risks")))


def risk_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "title": args.title,
        "description": args.description or "",
        "status": args.status or "open",
        "project_id": ws.project_id,
    }
    item = ws.call("POST", "/risks", body)
    return done(item, "Risk recorded.", RISK_FIELDS, ws.page("/workspace/risks"))


# Evidence

EVIDENCE_COLUMNS = [
    ("name", "Evidence"),
    ("kind", "Kind"),
    ("scan_status", "Scan"),
    ("expires_on", "Expires"),
    ("id", "ID"),
]


def evidence_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = [i for i in ws.get("/evidence", project_id=ws.project_id) if isinstance(i, dict)]
    return Output(items, table(items, EVIDENCE_COLUMNS, "No evidence yet."))


def evidence_search(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    hits = [
        hit
        for hit in ws.get("/evidence/search", q=args.query, project_id=ws.project_id)
        if isinstance(hit, dict)
    ]
    rows = [{**(hit.get("record") or {}), "snippet": hit.get("snippet", "")} for hit in hits]
    columns = [("name", "Evidence"), ("snippet", "Match"), ("id", "ID")]
    return Output(hits, table(rows, columns, "No evidence matches."))


def evidence_link(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    control = evidence_module._control(ws.credentials, args.control, ws.project_id)
    body = {
        "evidence_id": as_id(args.id),
        "control_id": str(control["id"]),
        "note": (args.note or "")[:2000],
    }
    value = ws.call("POST", "/evidence/links", body)
    return Output(
        value or body,
        f"Linked to {clean(control.get('code'))} {clean(control.get('title'))}, for review.",
    )


# Exceptions

EXCEPTION_COLUMNS = [
    ("title", "Exception"),
    ("kind", "Kind"),
    ("state", "State"),
    ("expires_on", "Expires"),
    ("owner_name", "Owner"),
    ("id", "ID"),
]
EXCEPTION_FIELDS = [
    ("title", "Exception"),
    ("kind", "Kind"),
    ("state", "State"),
    ("target_label", "Applies to"),
    ("reason", "Reason"),
    ("compensating_measures", "Measures"),
    ("owner_name", "Owner"),
    ("expires_on", "Expires"),
    ("decided_by_name", "Decided by"),
    ("decision_note", "Decision note"),
    ("version", "Version"),
    ("id", "ID"),
]


def _exception_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/exceptions?exception={item.get('id')}")


def exception_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    target = as_id(args.target, "--target") if args.target else None
    items = [
        item
        for item in ws.get("/exceptions", project_id=ws.project_id, target_id=target)
        if isinstance(item, dict)
    ]
    return Output(items, table(items, EXCEPTION_COLUMNS, "No exceptions."))


def exception_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/exceptions/{as_id(args.id)}")
    return Output(item, record(item, EXCEPTION_FIELDS, _exception_link(ws, item)))


def exception_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "kind": args.kind,
        "title": args.title,
        "target_id": as_id(args.target, "--target") if args.target else None,
        "project_id": ws.project_id,
        "reason": args.reason,
        "compensating_measures": args.measures,
        "owner_id": person(ws, "/exceptions/people", args.owner),
        "expires_on": as_day(args.expires, "--expires"),
        "renews_id": as_id(args.renews, "--renews") if args.renews else None,
    }
    item = ws.call("POST", "/exceptions", body)
    return done(
        item,
        "Exception drafted. Submit it for approval with `grchero exception submit ID`.",
        EXCEPTION_FIELDS,
        _exception_link(ws, item),
    )


# Change records

CHANGE_COLUMNS = [
    ("title", "Change"),
    ("change_type", "Type"),
    ("status", "Status"),
    ("risk", "Risk"),
    ("release_identifier", "Release"),
    ("id", "ID"),
]
CHANGE_FIELDS = [
    ("title", "Change"),
    ("change_type", "Type"),
    ("path", "Path"),
    ("status", "Status"),
    ("risk", "Risk"),
    ("release_identifier", "Release"),
    ("environments", "Environments"),
    ("summary", "Summary"),
    ("planned_start", "Planned start"),
    ("outcome", "Outcome"),
    ("owner_name", "Owner"),
    ("approvals", "Approvals"),
    ("approvals_needed", "Approvals needed"),
    ("version", "Version"),
    ("id", "ID"),
]


def _change_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/changes?change={item.get('id')}")


def change_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = [i for i in ws.get("/changes", project_id=ws.project_id) if isinstance(i, dict)]
    return Output(items, table(items, CHANGE_COLUMNS, "No change records."))


def change_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/changes/{as_id(args.id)}")
    text = record(item, CHANGE_FIELDS, _change_link(ws, item))
    issues = [issue for issue in item.get("issues") or [] if isinstance(issue, dict)]
    if issues:
        text += "\n\nIssues\n" + "\n".join(
            f"  {label(issue.get('impact'))}: {clean(issue.get('description'))[:160]}"
            for issue in issues
        )
    return Output(item, text)


def change_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "title": args.title,
        "summary": args.summary,
        "change_type": args.type,
        "path": args.path or "normal",
        "risk": args.risk,
        "project_id": ws.project_id,
        "release_identifier": args.release or "",
        "environments": args.env,
        "runtime": args.runtime or "",
        "planned_start": as_moment(args.start, "--start"),
        "planned_end": as_moment(args.end, "--end"),
        "test_summary": args.tests or "",
        "rollback_plan": args.rollback or "",
        "communication": args.communication or "",
        "references": [{"url": url} for url in args.reference],
        "owner_id": person(ws, "/changes/people", args.owner),
    }
    item = ws.call("POST", "/changes", body)
    return done(
        item,
        "Change record drafted. Submit it for approval with `grchero change submit ID`.",
        CHANGE_FIELDS,
        _change_link(ws, item),
    )


def change_issue(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "description": args.description,
        "impact": args.impact,
        "occurred_at": as_moment(args.occurred, "--occurred"),
        "resolution": args.resolution or "",
        "finding_id": as_id(args.finding, "--finding") if args.finding else None,
        "incident_id": as_id(args.incident, "--incident") if args.incident else None,
    }
    item = ws.call("POST", f"/changes/{as_id(args.id)}/issues", body)
    return done(item, "Issue recorded on the change.", CHANGE_FIELDS[:4], _change_link(ws, item))


# The catalog

EXCEPTION_SHORT = EXCEPTION_FIELDS[:3]
CHANGE_SHORT = CHANGE_FIELDS[:4]

WORKSPACE: list[Command] = [
    Command("org", "list", "List your workspaces", "read", org_list, project=False),
    Command("org", "view", "Show the workspace commands act in", "read", org_view, project=False),
    Command(
        "org",
        "use",
        "Switch the saved sign-in to another of your workspaces",
        "local",
        org_use,
        (Arg("workspace", "Workspace ID or slug", metavar="WORKSPACE"),),
        "grchero org use acme",
        project=False,
    ),
    Command(
        "project",
        "list",
        "List projects",
        "read",
        project_list,
        (Arg("--archived", "Include archived projects", flag=True),),
        project=False,
    ),
    Command(
        "project",
        "view",
        "Show a project's progress",
        "read",
        project_view,
        (
            Arg(
                "id",
                "Project ID or name (default: the saved project)",
                metavar="PROJECT",
                optional=True,
            ),
        ),
        project=False,
    ),
    Command(
        "project",
        "create",
        "Create a project",
        "write",
        project_create,
        (
            Arg("--name", "Project name", required=True),
            Arg("--description", "One-line description"),
            Arg("--use", "Make it the default project", flag=True),
        ),
        'grchero project create --name "Customer portal" --use',
        project=False,
    ),
    Command(
        "project",
        "use",
        "Make commands in this workspace use one project",
        "local",
        project_use,
        (
            Arg("project_name", "Project ID or name", metavar="PROJECT", optional=True),
            Arg("--clear", "Act on the whole workspace again", flag=True),
        ),
        'grchero project use "Customer portal"',
        project=False,
    ),
    Command(
        "inbox",
        "list",
        "List your messages",
        "read",
        inbox_list,
        (Arg("--unread", "Only unread messages", flag=True), LIMIT),
        project=False,
    ),
    Command(
        "inbox",
        "read",
        "Mark a message, or every message, read",
        # Your own inbox state: grcHero counts it as reading.
        "read",
        inbox_read,
        (
            Arg("id", "Message ID", metavar="ID", optional=True),
            Arg("--all", "Mark every message read", flag=True),
        ),
        project=False,
    ),
    Command(
        "finding",
        "list",
        "List open findings",
        "read",
        finding_list,
        (
            Arg("--mine", "Only findings you own or review", flag=True),
            Arg("--all", "Include closed findings", flag=True),
            LIMIT,
        ),
        "grchero finding list --mine --json",
    ),
    Command("finding", "view", "Show a finding", "read", finding_view, (ID,)),
    Command(
        "finding",
        "create",
        "Record a finding",
        "write",
        finding_create,
        (
            Arg("--title", "Short title", required=True),
            Arg(
                "--severity",
                "Severity",
                required=True,
                choices=("low", "medium", "high", "critical"),
            ),
            Arg("--description", "What was found"),
            Arg("--asset", "Affected asset ID"),
        ),
        'grchero finding create --title "Admin panel without MFA" --severity high',
    ),
    Command(
        "finding",
        "edit",
        "Assign a finding and plan its fix",
        "write",
        finding_edit,
        (
            ID,
            Arg("--owner", "Owner: me, a name or a user ID"),
            Arg("--reviewer", "Reviewer: a name or a user ID"),
            Arg("--due", "Due date, YYYY-MM-DD"),
            Arg("--plan", "Remediation plan"),
            Arg("--test", "How the fix will be tested"),
            NOTE,
            VERSION,
        ),
        "grchero finding edit ID --owner me --due 2026-12-01",
    ),
    *[
        Command(
            "finding",
            verb,
            summary,
            "write",
            _finding_transition(verb),
            (ID, Arg("--note", "What changed (3 characters or more)", required=True), VERSION),
        )
        for verb, summary in (
            ("start", "Start work on a finding"),
            ("submit", "Submit a fix for review"),
            ("reopen", "Reopen a finding"),
        )
    ],
    Command(
        "finding",
        "decide",
        "Decide a submitted fix, accept the risk or mark it a false positive",
        "decide",
        finding_decide,
        (
            ID,
            Arg(
                "--outcome",
                "Decision",
                required=True,
                choices=("approve_fix", "request_changes", "accept_risk", "false_positive"),
            ),
            Arg("--note", "Why (8 characters or more)", required=True),
            Arg("--expires", "For accept_risk: when to look again, YYYY-MM-DD"),
            VERSION,
        ),
        'grchero finding decide ID --outcome approve_fix --note "Retest passed"',
    ),
    Command("risk", "list", "List risks", "read", risk_list),
    Command("risk", "view", "Show a risk", "read", risk_view, (ID,), project=False),
    Command(
        "risk",
        "create",
        "Record a risk",
        "write",
        risk_create,
        (
            Arg("--title", "Short title", required=True),
            Arg("--description", "Cause, event and impact"),
            Arg("--status", "Status (default open)", choices=("open", "mitigated", "closed")),
        ),
        'grchero risk create --title "Single admin account for billing"',
    ),
    Command("evidence", "list", "List evidence", "read", evidence_list),
    Command(
        "evidence",
        "search",
        "Search evidence names and text",
        "read",
        evidence_search,
        (Arg("query", "Words to find", metavar="QUERY"),),
    ),
    Command(
        "evidence",
        "link",
        "Link evidence to a control, for review",
        "write",
        evidence_link,
        (
            Arg("id", "Evidence ID", metavar="EVIDENCE"),
            Arg("--control", "Control code or ID", required=True),
            Arg("--note", "Why it supports the control"),
        ),
        "grchero evidence link ID --control AC-2",
    ),
    Command(
        "exception",
        "list",
        "List exceptions",
        "read",
        exception_list,
        (Arg("--target", "Only exceptions for this risk, control or finding ID"),),
    ),
    Command("exception", "view", "Show an exception", "read", exception_view, (ID,)),
    Command(
        "exception",
        "create",
        "Draft a time-limited exception",
        "write",
        exception_create,
        (
            Arg(
                "--kind",
                "Kind",
                required=True,
                choices=("policy", "control", "risk_acceptance", "finding_deadline"),
            ),
            Arg("--title", "Short title", required=True),
            Arg("--reason", "Why it is needed", required=True),
            Arg("--measures", "Compensating measures", required=True),
            Arg("--expires", "End date, YYYY-MM-DD", required=True),
            Arg("--target", "The risk, control or finding ID it covers"),
            Arg("--owner", "Owner: me (default), a name or a user ID"),
            Arg("--renews", "The exception this one renews"),
        ),
        'grchero exception create --kind policy --title "Laptop rollout" '
        '--reason "Hardware arrives in December" --measures "Remote wipe" --expires 2027-01-31',
    ),
    Command(
        "exception",
        "submit",
        "Submit an exception for approval",
        "write",
        workflow(
            "exceptions", "submission", "Submitted for approval.", EXCEPTION_SHORT, _exception_link
        ),
        (ID, VERSION),
    ),
    Command(
        "exception",
        "withdraw",
        "Withdraw a submitted exception",
        "write",
        workflow("exceptions", "withdrawal", "Withdrawn.", EXCEPTION_SHORT, _exception_link),
        (ID, VERSION),
    ),
    *[
        Command(
            "exception",
            verb,
            f"{verb.title()} an exception",
            "decide",
            workflow(
                "exceptions",
                "decisions",
                "Decision recorded.",
                EXCEPTION_SHORT,
                _exception_link,
                lambda args, verb=verb: {"decision": verb, "note": args.note or ""},
            ),
            (ID, DECISION_NOTE, VERSION),
            f'grchero exception {verb} ID --note "Reviewed with the owner"',
        )
        for verb in ("approve", "reject")
    ],
    Command(
        "exception",
        "revoke",
        "Revoke an approved exception",
        "decide",
        workflow(
            "exceptions",
            "revocation",
            "Revoked.",
            EXCEPTION_SHORT,
            _exception_link,
            lambda args: {"reason": args.reason},
        ),
        (ID, Arg("--reason", "Why it ends early", required=True), VERSION),
    ),
    Command("change", "list", "List change records", "read", change_list),
    Command("change", "view", "Show a change record and its issues", "read", change_view, (ID,)),
    Command(
        "change",
        "create",
        "Document a release or change",
        "write",
        change_create,
        (
            Arg("--title", "Short title", required=True),
            Arg("--summary", "What changes and why", required=True),
            Arg(
                "--type",
                "Kind of change",
                required=True,
                choices=(
                    "release",
                    "configuration",
                    "infrastructure",
                    "vendor",
                    "access",
                    "data",
                    "other",
                ),
            ),
            Arg("--risk", "Risk", required=True, choices=("low", "medium", "high")),
            Arg("--path", "Approval path (default normal)", choices=("normal", "emergency")),
            Arg("--release", "Release, build or version identifier"),
            Arg("--env", "An environment; repeat for more", multiple=True),
            Arg("--runtime", "Runtime or platform"),
            Arg("--start", "Planned start, ISO time"),
            Arg("--end", "Planned end, ISO time"),
            Arg("--tests", "How it was tested"),
            Arg("--rollback", "How to roll it back"),
            Arg("--communication", "Who is told and how"),
            Arg("--reference", "A link people can follow; repeat for more", multiple=True),
            Arg("--owner", "Owner: me (default), a name or a user ID"),
        ),
        'grchero change create --title "Release 2.4" --type release --risk medium '
        '--summary "New billing page" --release v2.4.0 --env production',
    ),
    Command(
        "change",
        "submit",
        "Submit a change for approval",
        "write",
        workflow("changes", "submission", "Submitted for approval.", CHANGE_SHORT, _change_link),
        (ID, VERSION),
    ),
    *[
        Command(
            "change",
            verb,
            f"{verb.title()} a change",
            "decide",
            workflow(
                "changes",
                "decisions",
                "Decision recorded.",
                CHANGE_SHORT,
                _change_link,
                lambda args, verb=verb: {"decision": verb, "note": args.note or ""},
            ),
            (ID, DECISION_NOTE, VERSION),
        )
        for verb in ("approve", "reject")
    ],
    Command(
        "change",
        "implement",
        "Record how the change went",
        "write",
        workflow(
            "changes",
            "implementation",
            "Implementation recorded.",
            CHANGE_SHORT,
            _change_link,
            lambda args: {
                "started_at": as_moment(args.started, "--started") or now(),
                "ended_at": as_moment(args.ended, "--ended"),
                "outcome": args.outcome,
                "outcome_note": args.note or "",
            },
        ),
        (
            ID,
            Arg(
                "--outcome",
                "Outcome",
                required=True,
                choices=("successful", "successful_with_issues", "rolled_back", "failed"),
            ),
            Arg("--started", "When it started, ISO time (default now)"),
            Arg("--ended", "When it ended, ISO time"),
            NOTE,
            VERSION,
        ),
        "grchero change implement ID --outcome successful",
    ),
    Command(
        "change",
        "issue",
        "Record an issue the change had",
        "write",
        change_issue,
        (
            ID,
            Arg("--description", "What happened", required=True),
            Arg("--impact", "Impact", required=True, choices=("low", "medium", "high")),
            Arg("--occurred", "When, ISO time"),
            Arg("--resolution", "How it was resolved"),
            Arg("--finding", "Related finding ID"),
            Arg("--incident", "Related incident ID"),
        ),
    ),
    Command(
        "change",
        "close",
        "Close a change after its review",
        "decide",
        workflow(
            "changes",
            "closure",
            "Closed.",
            CHANGE_SHORT,
            _change_link,
            lambda args: {"review_note": args.note},
        ),
        (ID, Arg("--note", "Post-change review", required=True), VERSION),
    ),
    Command(
        "change",
        "cancel",
        "Cancel a change",
        "write",
        workflow(
            "changes",
            "cancellation",
            "Cancelled.",
            CHANGE_SHORT,
            _change_link,
            lambda args: {"reason": args.reason},
        ),
        (ID, Arg("--reason", "Why", required=True), VERSION),
    ),
]


COMMANDS: list[Command] = [*WORKSPACE, *ASSURANCE, *OPERATIONS, *ADMIN]
BY_NAME = {command.name: command for command in COMMANDS}
assert len(BY_NAME) == len(COMMANDS), "two commands share a name"


def install(subparsers: Any, existing: dict[str, Any]) -> None:
    catalog.install(COMMANDS, subparsers, existing)


def run(args: argparse.Namespace) -> Output:
    return catalog.run(BY_NAME[args.catalog], args)


def describe(parser: argparse.ArgumentParser, tiers: dict[str, str]) -> list[dict[str, Any]]:
    return catalog.describe(parser, BY_NAME, tiers)
