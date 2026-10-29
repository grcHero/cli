"""Operations commands: assets, incidents, continuity plans and exercises, and privacy records.

Closing an incident is an independent review: the decision waits for the person's browser
confirmation and answers the newest resolution submission.
"""

import argparse
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from .catalog import (
    ID,
    LIMIT,
    VERSION,
    Arg,
    Command,
    Output,
    as_id,
    as_moment,
    done,
    items_of,
    listing,
    pages,
    record,
    workflow,
    workspace,
)
from .scope import CliError
from .workspace import Workspace

# Assets

ASSET_TYPES = (
    "hardware",
    "software",
    "infrastructure",
    "cloud_resource",
    "repository",
    "endpoint",
    "network_component",
    "other",
)
LIFECYCLE = ("planned", "active", "maintenance", "retired")
ASSET_COLUMNS = [
    ("name", "Asset"),
    ("type", "Type"),
    ("criticality", "Criticality"),
    ("lifecycle_status", "Lifecycle"),
    ("id", "ID"),
]
ASSET_FIELDS = [
    ("name", "Asset"),
    ("type", "Type"),
    ("description", "Description"),
    ("criticality", "Criticality (1 to 5)"),
    ("lifecycle_status", "Lifecycle"),
    ("tags", "Tags"),
    ("id", "ID"),
]


def _asset_link(ws: Workspace, _item: dict[str, Any]) -> str:
    return ws.page("/workspace/inventory")


def _criticality(value: int | None) -> int | None:
    if value is not None and not 1 <= value <= 5:
        raise CliError("--criticality must be 1 (lowest) to 5 (highest).")
    return value


def asset_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(
        ws.get("/assets", query=args.query, type=args.type, lifecycle_status=args.lifecycle)
    )
    return listing(items, ASSET_COLUMNS, "No assets match.")


def asset_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/assets/{as_id(args.id)}")
    return Output(item, record(item, ASSET_FIELDS, _asset_link(ws, item)))


def asset_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body: dict[str, Any] = {
        "name": args.name,
        "type": args.type,
        "description": args.description or "",
        "lifecycle_status": args.lifecycle or "active",
        "tags": args.tag,
    }
    if args.criticality is not None:
        body["criticality"] = _criticality(args.criticality)
    item = ws.call("POST", "/assets", body)
    if ws.project_id:
        # A new asset joins the project in use, as it does when added inside a project.
        ws.call("PUT", f"/projects/{ws.project_id}/assets/{item['id']}", {})
    return done(item, "Asset added.", ASSET_FIELDS, _asset_link(ws, item))


def asset_edit(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    changes = {
        "name": args.name,
        "type": args.type,
        "description": args.description,
        "criticality": _criticality(args.criticality),
        "lifecycle_status": args.lifecycle,
        "tags": args.tag or None,
    }
    body = {key: value for key, value in changes.items() if value is not None}
    if not body:
        raise CliError("Nothing to change. Pass the fields to update, for example --lifecycle.")
    item = ws.call("PATCH", f"/assets/{as_id(args.id)}", body)
    return done(item, "Asset updated.", ASSET_FIELDS, _asset_link(ws, item))


# Incidents

INCIDENT_COLUMNS = [
    ("title", "Incident"),
    ("severity", "Severity"),
    ("status", "Status"),
    ("owner_name", "Owner"),
    ("id", "ID"),
]
INCIDENT_FIELDS = [
    ("title", "Incident"),
    ("severity", "Severity"),
    ("status", "Status"),
    ("description", "Description"),
    ("owner_name", "Owner"),
    ("reviewer_name", "Closure reviewer"),
    ("impact", "Impact"),
    ("containment", "Containment"),
    ("recovery", "Recovery"),
    ("root_cause", "Root cause"),
    ("lessons", "Lessons"),
    ("version", "Version"),
    ("id", "ID"),
]


def _incident_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/operations/incidents?incident={item.get('id')}")


def incident_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = pages(ws, "/incidents/response", args.limit or 50, project_id=ws.project_id)
    return listing(items, INCIDENT_COLUMNS, "No incidents.")


def incident_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/incidents/{as_id(args.id)}/response")
    return Output(item, record(item, INCIDENT_FIELDS, _incident_link(ws, item)))


def incident_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "title": args.title,
        "description": args.description or "",
        "severity": args.severity,
        "project_id": ws.project_id,
        "affected_asset_id": as_id(args.asset, "--asset") if args.asset else None,
    }
    item = ws.call("POST", "/incidents", body)
    fields = [*INCIDENT_FIELDS[:3], ("id", "ID")]
    return done(item, "Incident recorded.", fields, _incident_link(ws, item))


def _transition(action: str) -> Callable[[argparse.Namespace], Output]:
    def extra(args: argparse.Namespace) -> dict[str, Any]:
        body: dict[str, Any] = {"action": action, "note": args.note}
        if action == "resolve":
            # A resolution is a submission for independent review; the key makes a retry safe.
            body["submission_key"] = args.key or str(uuid4())
            body["evidence_ids"] = [as_id(item, "--evidence") for item in args.evidence]
        return body

    return workflow(
        "incidents",
        "transitions",
        f"Incident updated: {action}.",
        INCIDENT_FIELDS[:3],
        _incident_link,
        extra,
        detail="/response",
    )


def _timeline(args: argparse.Namespace) -> dict[str, Any]:
    body: dict[str, Any] = {"note": args.note}
    if args.at:
        body["occurred_at"] = as_moment(args.at, "--at")
    return body


TRANSITION_NOTE = Arg("--note", "What happened (12 characters or more)", required=True)

# Continuity and privacy

PLAN_COLUMNS = [
    ("name", "Plan"),
    ("plan_type", "Type"),
    ("status", "Status"),
    ("rto_minutes", "RTO min"),
    ("rpo_minutes", "RPO min"),
    ("id", "ID"),
]
EXERCISE_FIELDS = [
    ("plan_name", "Plan"),
    ("exercise_kind", "Kind"),
    ("status", "Status"),
    ("scheduled_on", "Scheduled"),
    ("scenario", "Scenario"),
    ("success_criteria", "Success criteria"),
    ("outcome", "Outcome"),
    ("owner_name", "Owner"),
    ("reviewer_name", "Reviewer"),
    ("version", "Version"),
    ("id", "ID"),
]
PROCESSING_FIELDS = [
    ("name", "Processing"),
    ("purpose", "Purpose"),
    ("legal_basis", "Legal basis"),
    ("data_subjects", "Data subjects"),
    ("data_categories", "Data categories"),
    ("retention_period", "Retention"),
    ("id", "ID"),
]


def plan_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get("/continuity/plans", project_id=ws.project_id))
    return listing(items, PLAN_COLUMNS, "No continuity plans yet.")


def plan_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "name": args.name,
        "plan_type": args.type,
        "scope": args.scope or "",
        "rto_minutes": args.rto,
        "rpo_minutes": args.rpo,
        "project_id": ws.project_id,
    }
    item = ws.call("POST", "/continuity/plans", body)
    return done(item, "Plan drafted.", PLAN_COLUMNS, ws.page("/workspace/operations/continuity"))


def exercise_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = pages(ws, "/continuity/exercise-runs", args.limit or 50, project_id=ws.project_id)
    columns = [
        ("plan_name", "Plan"),
        ("exercise_kind", "Kind"),
        ("status", "Status"),
        ("scheduled_on", "Scheduled"),
        ("id", "ID"),
    ]
    return listing(items, columns, "No exercises scheduled.")


def exercise_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/continuity/exercise-runs/{as_id(args.id)}")
    link = ws.page(f"/workspace/operations/continuity?exercise={item.get('id')}")
    return Output(item, record(item, EXERCISE_FIELDS, link))


def privacy_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get("/privacy/processing", project_id=ws.project_id))
    columns = [("name", "Processing"), ("legal_basis", "Legal basis"), ("id", "ID")]
    return listing(items, columns, "No processing activities recorded.")


def privacy_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "name": args.name,
        "purpose": args.purpose,
        "legal_basis": args.legal_basis,
        "data_subjects": args.subject,
        "data_categories": args.category,
        "retention_period": args.retention or "",
        "project_id": ws.project_id,
    }
    item = ws.call("POST", "/privacy/processing", body)
    link = ws.page("/workspace/operations/privacy")
    return done(item, "Processing activity recorded.", PROCESSING_FIELDS, link)


def privacy_processors(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    columns = [
        ("name", "Processor"),
        ("service_description", "Service"),
        ("dpa_reference", "DPA"),
        ("id", "ID"),
    ]
    return listing(items_of(ws.get("/privacy/processors")), columns, "No processors recorded.")


COMMANDS: list[Command] = [
    Command(
        "asset",
        "list",
        "List assets",
        "read",
        asset_list,
        (
            Arg("--query", "Words in the name or description"),
            Arg("--type", "Only this type", choices=ASSET_TYPES),
            Arg("--lifecycle", "Only this lifecycle state", choices=LIFECYCLE),
        ),
        project=False,
    ),
    Command("asset", "view", "Show an asset", "read", asset_view, (ID,), project=False),
    Command(
        "asset",
        "create",
        "Add an asset, to the project in use if there is one",
        "write",
        asset_create,
        (
            Arg("--name", "Asset name", required=True),
            Arg("--type", "Type", required=True, choices=ASSET_TYPES),
            Arg("--description", "What it is"),
            Arg("--criticality", "1 (lowest) to 5 (highest); default 3", integer=True),
            Arg("--lifecycle", "Lifecycle state (default active)", choices=LIFECYCLE),
            Arg("--tag", "A tag; repeat for more", multiple=True),
        ),
        'grchero asset create --name "Billing API" --type software --criticality 4',
    ),
    Command(
        "asset",
        "edit",
        "Change an asset",
        "write",
        asset_edit,
        (
            ID,
            Arg("--name", "New name"),
            Arg("--type", "New type", choices=ASSET_TYPES),
            Arg("--description", "New description"),
            Arg("--criticality", "1 (lowest) to 5 (highest)", integer=True),
            Arg("--lifecycle", "Lifecycle state", choices=LIFECYCLE),
            Arg("--tag", "Replace the tags; repeat for more", multiple=True),
        ),
        project=False,
    ),
    Command("incident", "list", "List incidents", "read", incident_list, (LIMIT,)),
    Command("incident", "view", "Show an incident's response", "read", incident_view, (ID,)),
    Command(
        "incident",
        "create",
        "Record an incident",
        "write",
        incident_create,
        (
            Arg("--title", "Short title", required=True),
            Arg(
                "--severity",
                "Severity",
                required=True,
                choices=("low", "medium", "high", "critical"),
            ),
            Arg("--description", "What happened"),
            Arg("--asset", "Affected asset ID"),
        ),
        'grchero incident create --title "Phishing email reported" --severity medium',
    ),
    *[
        Command(
            "incident",
            action,
            summary,
            "write",
            _transition(action),
            (ID, TRANSITION_NOTE, VERSION),
        )
        for action, summary in (
            ("investigate", "Start investigating an incident"),
            ("contain", "Record that an incident is contained"),
            ("reopen", "Reopen an incident"),
        )
    ],
    Command(
        "incident",
        "resolve",
        "Submit an incident's resolution for independent review",
        "write",
        _transition("resolve"),
        (
            ID,
            TRANSITION_NOTE,
            Arg("--evidence", "Evidence ID; repeat for more", multiple=True),
            Arg("--key", "Submission key from an earlier attempt, to retry it safely"),
            VERSION,
        ),
    ),
    Command(
        "incident",
        "note",
        "Add a timeline update",
        "write",
        workflow(
            "incidents",
            "timeline",
            "Timeline updated.",
            INCIDENT_FIELDS[:3],
            _incident_link,
            _timeline,
            detail="/response",
        ),
        (ID, TRANSITION_NOTE, Arg("--at", "When it happened, ISO time (default now)"), VERSION),
    ),
    Command(
        "incident",
        "decide",
        "Accept a resolution and close the incident, or ask for changes",
        "decide",
        workflow(
            "incidents",
            "closure-decisions",
            "Decision recorded.",
            INCIDENT_FIELDS[:3],
            _incident_link,
            lambda args: {"decision": args.decision, "note": args.note},
            detail="/response",
            submission=True,
        ),
        (
            ID,
            Arg("--decision", "Decision", required=True, choices=("accept", "request_changes")),
            Arg("--note", "Why (12 characters or more)", required=True),
            VERSION,
        ),
    ),
    Command("continuity", "list", "List continuity and recovery plans", "read", plan_list),
    Command(
        "continuity",
        "create",
        "Draft a continuity or recovery plan",
        "write",
        plan_create,
        (
            Arg("--name", "Plan name", required=True),
            Arg(
                "--type",
                "Kind of plan",
                required=True,
                choices=("business_continuity", "disaster_recovery"),
            ),
            Arg("--rto", "Recovery time objective, minutes", required=True, integer=True),
            Arg("--rpo", "Recovery point objective, minutes", required=True, integer=True),
            Arg("--scope", "What the plan covers"),
        ),
        'grchero continuity create --name "Billing recovery" --type disaster_recovery '
        "--rto 240 --rpo 60",
    ),
    Command(
        "continuity",
        "exercises",
        "List scheduled and finished exercises",
        "read",
        exercise_list,
        (LIMIT,),
    ),
    Command("continuity", "exercise", "Show an exercise", "read", exercise_view, (ID,)),
    Command("privacy", "list", "List processing activities", "read", privacy_list),
    Command(
        "privacy",
        "create",
        "Record a processing activity",
        "write",
        privacy_create,
        (
            Arg("--name", "Processing activity", required=True),
            Arg("--purpose", "Why the data is processed", required=True),
            Arg(
                "--legal-basis",
                "Legal basis",
                required=True,
                choices=(
                    "consent",
                    "contract",
                    "legal_obligation",
                    "vital_interests",
                    "public_task",
                    "legitimate_interests",
                ),
            ),
            Arg("--subject", "A group of data subjects; repeat for more", multiple=True),
            Arg("--category", "A category of personal data; repeat for more", multiple=True),
            Arg("--retention", "How long the data is kept"),
        ),
    ),
    Command(
        "privacy",
        "processors",
        "List processors",
        "read",
        privacy_processors,
        project=False,
    ),
]
