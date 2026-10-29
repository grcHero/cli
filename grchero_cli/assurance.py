"""Assurance commands: controls, frameworks, vendors and their reviews, evidence requests,
documents and their reviews, questionnaires, assessments and access reviews.

Reviews are decided by people: every decision here waits for the person's browser
confirmation and answers the newest submission, so an older one is never accepted by mistake.
Access reviews administer the workspace in grcHero, so agents never run them.
"""

import argparse
from typing import Any
from uuid import uuid4

from .catalog import (
    ID,
    LIMIT,
    VERSION,
    Arg,
    Command,
    Output,
    as_day,
    as_id,
    done,
    find,
    items_of,
    listing,
    pages,
    person,
    record,
    table,
    workflow,
    workspace,
)
from .workspace import Workspace

MINE = Arg("--mine", "Only work assigned to you", flag=True)
ALL = Arg("--all", "Include finished work", flag=True)


# Controls and frameworks

CONTROL_COLUMNS = [("code", "Code"), ("title", "Control"), ("id", "ID")]
CONTROL_FIELDS = [
    ("code", "Code"),
    ("title", "Control"),
    ("description", "Description"),
    ("id", "ID"),
]


def _control_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/controls?control={item.get('id')}")


def control_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get("/controls", project_id=ws.project_id))
    return listing(items, CONTROL_COLUMNS, "No controls yet.")


def control_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = find(items_of(ws.get("/controls")), as_id(args.id), "control")
    return Output(item, record(item, CONTROL_FIELDS, _control_link(ws, item)))


def control_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "code": args.code,
        "title": args.title,
        "description": args.description or "",
        "project_id": ws.project_id,
    }
    item = ws.call("POST", "/controls", body)
    return done(item, "Control added.", CONTROL_FIELDS, _control_link(ws, item))


def control_evidence(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get(f"/controls/{as_id(args.id)}/evidence"))
    columns = [
        ("name", "Evidence"),
        ("review_current", "Reviewed"),
        ("expires_on", "Expires"),
        ("id", "ID"),
    ]
    return listing(items, columns, "No evidence is linked to this control.")


def framework_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    columns = [
        ("name", "Framework"),
        ("version", "Version"),
        ("publisher", "Publisher"),
        ("id", "ID"),
    ]
    return listing(items_of(ws.get("/frameworks")), columns, "No frameworks yet.")


def framework_requirements(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get(f"/frameworks/{as_id(args.id)}/requirements"))
    columns = [("code", "Code"), ("title", "Requirement"), ("id", "ID")]
    return listing(items, columns, "This framework has no requirements.")


# Vendors and vendor reviews

VENDOR_COLUMNS = [
    ("name", "Vendor"),
    ("criticality", "Criticality"),
    ("review_due_date", "Review due"),
    ("id", "ID"),
]
VENDOR_FIELDS = [
    ("name", "Vendor"),
    ("criticality", "Criticality"),
    ("description", "Description"),
    ("contract_reference", "Contract"),
    ("dpa_reference", "DPA"),
    ("review_due_date", "Review due"),
    ("id", "ID"),
]
VENDOR_REVIEW_COLUMNS = [
    ("vendor_name", "Vendor"),
    ("status", "Status"),
    ("owner_name", "Owner"),
    ("reviewer_name", "Reviewer"),
    ("due_date", "Due"),
    ("id", "ID"),
]
VENDOR_REVIEW_FIELDS = [
    ("vendor_name", "Vendor"),
    ("status", "Status"),
    ("scope", "Scope"),
    ("owner_name", "Owner"),
    ("reviewer_name", "Reviewer"),
    ("due_date", "Due"),
    ("inherent_risk", "Inherent risk"),
    ("residual_risk", "Residual risk"),
    ("recommendation", "Recommendation"),
    ("conditions", "Conditions"),
    ("decision_note", "Decision note"),
    ("version", "Version"),
    ("id", "ID"),
]


def _vendor_link(ws: Workspace, _item: dict[str, Any]) -> str:
    return ws.page("/workspace/inventory?section=vendors")


def _vendor_review_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/findings?mine=1&work=vendors&review={item.get('id')}")


def vendor_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get("/vendors", project_id=ws.project_id))
    return listing(items, VENDOR_COLUMNS, "No vendors yet.")


def vendor_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = find(items_of(ws.get("/vendors")), as_id(args.id), "vendor")
    return Output(item, record(item, VENDOR_FIELDS, _vendor_link(ws, item)))


def vendor_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    body = {
        "name": args.name,
        "description": args.description or "",
        "criticality": args.criticality or "medium",
        "contract_reference": args.contract,
        "dpa_reference": args.dpa,
        "review_due_date": as_day(args.review_due, "--review-due"),
        "project_id": ws.project_id,
    }
    item = ws.call("POST", "/vendors", body)
    return done(item, "Vendor added.", VENDOR_FIELDS, _vendor_link(ws, item))


def vendor_review_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = pages(
        ws,
        "/vendor-reviews",
        args.limit or 50,
        project_id=ws.project_id,
        mine=args.mine,
        active_only=not args.all,
    )
    return listing(items, VENDOR_REVIEW_COLUMNS, "No vendor reviews.")


def vendor_review_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/vendor-reviews/{as_id(args.id)}")
    return Output(item, record(item, VENDOR_REVIEW_FIELDS, _vendor_review_link(ws, item)))


# Evidence requests

REQUEST_COLUMNS = [
    ("title", "Request"),
    ("effective_status", "Status"),
    ("owner_name", "Owner"),
    ("due_date", "Due"),
    ("id", "ID"),
]
REQUEST_FIELDS = [
    ("title", "Request"),
    ("effective_status", "Status"),
    ("instructions", "Instructions"),
    ("owner_name", "Owner"),
    ("reviewer_name", "Reviewer"),
    ("due_date", "Due"),
    ("renew_on", "Renew on"),
    ("version", "Version"),
    ("id", "ID"),
]


def _request_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/evidence?request={item.get('id')}")


def request_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = pages(
        ws,
        "/evidence-requests",
        args.limit or 50,
        project_id=ws.project_id,
        mine=args.mine,
        active_only=not args.all,
    )
    return listing(items, REQUEST_COLUMNS, "No evidence requests.")


def request_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/evidence-requests/{as_id(args.id)}")
    return Output(item, record(item, REQUEST_FIELDS, _request_link(ws, item)))


def request_create(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    # The browser picks owners and reviewers from the same list of people.
    people = "/findings/assignees"
    body = {
        "title": args.title,
        "instructions": args.instructions,
        "owner_id": person(ws, people, args.owner),
        "reviewer_id": person(ws, people, args.reviewer),
        "due_date": as_day(args.due, "--due"),
        "renew_on": as_day(args.renew, "--renew"),
        "project_id": ws.project_id,
        "control_id": as_id(args.control, "--control") if args.control else None,
    }
    item = ws.call("POST", "/evidence-requests", body)
    return done(item, "Evidence requested.", REQUEST_FIELDS, _request_link(ws, item))


def _submission(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "note": args.note,
        "evidence_ids": [as_id(item, "--evidence") for item in args.evidence],
        # grcHero treats a repeated key as the same submission, so `--key` makes a retry safe.
        "submission_key": args.key or str(uuid4()),
    }


# Documents and document reviews

DOCUMENT_COLUMNS = [
    ("title", "Document"),
    ("document_type", "Type"),
    ("status", "Status"),
    ("version", "Version"),
    ("id", "ID"),
]
DOCUMENT_FIELDS = [
    ("title", "Document"),
    ("document_type", "Type"),
    ("status", "Status"),
    ("version", "Version"),
    ("updated_at", "Updated"),
    ("id", "ID"),
]
DOCUMENT_REVIEW_COLUMNS = [
    ("title", "Document"),
    ("status", "Status"),
    ("reviewer_name", "Reviewer"),
    ("effective_on", "Effective"),
    ("id", "ID"),
]
DOCUMENT_REVIEW_FIELDS = [
    ("title", "Document"),
    ("status", "Status"),
    ("submitter_name", "Submitted by"),
    ("reviewer_name", "Reviewer"),
    ("note", "Note"),
    ("decision", "Decision"),
    ("decision_note", "Decision note"),
    ("effective_on", "Effective"),
    ("review_on", "Review on"),
    ("version", "Version"),
    ("id", "ID"),
]


def _document_review_link(ws: Workspace, item: dict[str, Any]) -> str:
    return ws.page(f"/workspace/documents/assurance?review={item.get('id')}")


def document_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get("/documents/library", project_id=ws.project_id))
    return listing(items, DOCUMENT_COLUMNS, "No documents yet.")


def document_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/documents/{as_id(args.id)}")
    return Output(item, record(item, DOCUMENT_FIELDS, ws.page("/workspace/documents")))


def document_versions(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get(f"/documents/{as_id(args.id)}/versions"))
    columns = [("version", "Version"), ("status", "Status"), ("created_at", "Saved")]
    return listing(items, columns, "No saved versions.")


def document_review_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = pages(
        ws,
        "/document-assurance",
        args.limit or 50,
        project_id=ws.project_id,
        mine=args.mine,
        active_only=not args.all,
    )
    return listing(items, DOCUMENT_REVIEW_COLUMNS, "No document reviews.")


def document_review_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.get(f"/document-assurance/{as_id(args.id)}")
    return Output(item, record(item, DOCUMENT_REVIEW_FIELDS, _document_review_link(ws, item)))


def _publication(args: argparse.Namespace) -> dict[str, Any]:
    ws = workspace(args)
    return {
        "note": args.note,
        "effective_on": as_day(args.effective, "--effective"),
        "review_on": as_day(args.review_on, "--review-on"),
        "review_owner_id": person(ws, "/document-assurance/assignees", args.review_owner),
    }


# Questionnaires and assessments


def questionnaire_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    columns = [
        ("name", "Questionnaire"),
        ("version", "Version"),
        ("revision", "Revision"),
        ("id", "ID"),
    ]
    items = items_of(ws.get("/questionnaires", project_id=ws.project_id))
    return listing(items, columns, "No questionnaires yet.")


def questionnaire_questions(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get(f"/questionnaires/{as_id(args.id)}/questions"))
    columns = [("code", "Code"), ("prompt", "Question"), ("question_type", "Type"), ("id", "ID")]
    return listing(items, columns, "This questionnaire has no questions.")


def assessment_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    columns = [("name", "Assessment"), ("status", "Status"), ("due_date", "Due"), ("id", "ID")]
    items = items_of(ws.get("/assessments", project_id=ws.project_id))
    return listing(items, columns, "No assessments yet.")


def assessment_findings(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    items = items_of(ws.get(f"/assessments/{as_id(args.id)}/findings"))
    columns = [("title", "Finding"), ("severity", "Severity"), ("status", "Status"), ("id", "ID")]
    return listing(items, columns, "This assessment has no findings.")


# Access reviews

ACCESS_COLUMNS = [
    ("status", "Status"),
    ("opened_at", "Opened"),
    ("decided", "Decided"),
    ("total", "Of"),
    ("id", "ID"),
]


def access_review_list(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    overview = ws.get("/access-reviews")
    reviews = [item for item in overview.get("reviews", []) if isinstance(item, dict)]
    text = table(reviews, ACCESS_COLUMNS, "No access reviews yet.")
    if overview.get("next_due_on"):
        text += f"\nNext review due {overview['next_due_on']}."
    return Output(overview, text)


def _access(ws: Workspace, item: dict[str, Any], message: str = "") -> Output:
    fields = [("status", "Status"), ("decided", "Decided"), ("total", "Of"), ("id", "ID")]
    rows = [
        {**row, "decision": row.get("decision") or "undecided"}
        for row in item.get("items", [])
        if isinstance(row, dict)
    ]
    columns = [("label", "Access"), ("detail", "Detail"), ("decision", "Decision"), ("id", "ID")]
    text = record(item, fields, ws.page("/workspace/access-reviews"))
    text += "\n\n" + table(rows, columns, "Nothing to review.")
    return Output(item, f"{message}\n{text}" if message else text)


def access_review_view(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    return _access(ws, ws.get(f"/access-reviews/{as_id(args.id)}"))


def access_review_start(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    return _access(ws, ws.call("POST", "/access-reviews", {}), "Access review started.")


def access_review_decide(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    path = f"/access-reviews/{as_id(args.id)}/items/{as_id(args.item, '--item')}"
    item = ws.call("PUT", path, {"decision": args.decision, "note": args.note or ""})
    return _access(ws, item, "Decision recorded. Access changes only when you change it.")


def access_review_complete(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.call("POST", f"/access-reviews/{as_id(args.id)}/completion", {})
    return _access(ws, item, "Review completed and kept as evidence.")


COMMANDS: list[Command] = [
    Command("control", "list", "List controls", "read", control_list),
    Command("control", "view", "Show a control", "read", control_view, (ID,), project=False),
    Command(
        "control",
        "create",
        "Add a control",
        "write",
        control_create,
        (
            Arg("--code", "Control code, for example AC-2", required=True),
            Arg("--title", "Short title", required=True),
            Arg("--description", "What the control does"),
        ),
        'grchero control create --code AC-2 --title "Account management"',
    ),
    Command(
        "control",
        "evidence",
        "List evidence linked to a control",
        "read",
        control_evidence,
        (ID,),
        project=False,
    ),
    Command("framework", "list", "List frameworks", "read", framework_list, project=False),
    Command(
        "framework",
        "requirements",
        "List a framework's requirements",
        "read",
        framework_requirements,
        (ID,),
        project=False,
    ),
    Command("vendor", "list", "List vendors", "read", vendor_list),
    Command("vendor", "view", "Show a vendor", "read", vendor_view, (ID,), project=False),
    Command(
        "vendor",
        "create",
        "Add a vendor",
        "write",
        vendor_create,
        (
            Arg("--name", "Vendor name", required=True),
            Arg(
                "--criticality",
                "Criticality (default medium)",
                choices=("low", "medium", "high", "critical"),
            ),
            Arg("--description", "What they provide"),
            Arg("--contract", "Contract reference"),
            Arg("--dpa", "Data processing agreement reference"),
            Arg("--review-due", "Next review date, YYYY-MM-DD"),
        ),
        'grchero vendor create --name "Acme Mail" --criticality high',
    ),
    Command(
        "vendor-review",
        "list",
        "List vendor reviews",
        "read",
        vendor_review_list,
        (MINE, ALL, LIMIT),
    ),
    Command(
        "vendor-review",
        "view",
        "Show a vendor review and its submissions",
        "read",
        vendor_review_view,
        (ID,),
    ),
    Command(
        "vendor-review",
        "decide",
        "Accept the submitted assessment or ask for changes",
        "decide",
        workflow(
            "vendor-reviews",
            "decisions",
            "Decision recorded.",
            VENDOR_REVIEW_FIELDS[:2],
            _vendor_review_link,
            lambda args: {
                "decision": args.decision,
                "note": args.note,
                "recommendation": args.recommendation,
                "residual_risk": args.residual_risk,
                "conditions": args.conditions or "",
                "next_review_on": as_day(args.next_review, "--next-review"),
            },
            submission=True,
        ),
        (
            ID,
            Arg("--decision", "Decision", required=True, choices=("accept", "request_changes")),
            Arg("--note", "Why (12 characters or more)", required=True),
            Arg(
                "--recommendation",
                "When accepting",
                choices=("proceed", "conditional", "do_not_proceed"),
            ),
            Arg(
                "--residual-risk",
                "When accepting",
                choices=("low", "medium", "high", "critical", "unknown"),
            ),
            Arg("--conditions", "Conditions of a conditional recommendation"),
            Arg("--next-review", "Next review date, YYYY-MM-DD"),
            VERSION,
        ),
        "grchero vendor-review decide ID --decision accept --recommendation proceed "
        '--residual-risk low --note "SOC 2 report and DPA checked"',
    ),
    Command(
        "evidence-request",
        "list",
        "List evidence requests",
        "read",
        request_list,
        (MINE, ALL, LIMIT),
    ),
    Command(
        "evidence-request",
        "view",
        "Show an evidence request and its submissions",
        "read",
        request_view,
        (ID,),
    ),
    Command(
        "evidence-request",
        "create",
        "Ask someone for evidence",
        "write",
        request_create,
        (
            Arg("--title", "What is needed", required=True),
            Arg("--instructions", "How to provide it (12 characters or more)", required=True),
            Arg("--reviewer", "Who reviews it: a name or a user ID", required=True),
            Arg("--due", "Due date, YYYY-MM-DD", required=True),
            Arg("--owner", "Who provides it: me (default), a name or a user ID"),
            Arg("--renew", "When to ask again, YYYY-MM-DD"),
            Arg("--control", "The control it supports (ID)"),
        ),
    ),
    Command(
        "evidence-request",
        "submit",
        "Submit evidence for a request",
        "write",
        workflow(
            "evidence-requests",
            "submissions",
            "Submitted for review.",
            REQUEST_FIELDS[:2],
            _request_link,
            _submission,
        ),
        (
            ID,
            Arg("--evidence", "Evidence ID; repeat for more", required=True, multiple=True),
            Arg("--note", "What you are submitting (8 characters or more)", required=True),
            Arg("--key", "Submission key from an earlier attempt, to retry it safely"),
            VERSION,
        ),
    ),
    Command(
        "evidence-request",
        "decide",
        "Accept the submitted evidence or ask for changes",
        "decide",
        workflow(
            "evidence-requests",
            "decisions",
            "Decision recorded.",
            REQUEST_FIELDS[:2],
            _request_link,
            lambda args: {"decision": args.decision, "note": args.note},
            submission=True,
        ),
        (
            ID,
            Arg("--decision", "Decision", required=True, choices=("accept", "request_changes")),
            Arg("--note", "Why (8 characters or more)", required=True),
            VERSION,
        ),
    ),
    Command("document", "list", "List documents", "read", document_list),
    Command("document", "view", "Show a document", "read", document_view, (ID,), project=False),
    Command(
        "document",
        "versions",
        "List a document's saved versions",
        "read",
        document_versions,
        (ID,),
        project=False,
    ),
    Command(
        "document-review",
        "list",
        "List document reviews",
        "read",
        document_review_list,
        (MINE, ALL, LIMIT),
    ),
    Command(
        "document-review",
        "view",
        "Show a document review",
        "read",
        document_review_view,
        (ID,),
    ),
    Command(
        "document-review",
        "decide",
        "Approve a document or ask for changes",
        "decide",
        workflow(
            "document-assurance",
            "decisions",
            "Decision recorded.",
            DOCUMENT_REVIEW_FIELDS[:2],
            _document_review_link,
            lambda args: {"decision": args.decision, "note": args.note},
        ),
        (
            ID,
            Arg("--decision", "Decision", required=True, choices=("approve", "request_changes")),
            Arg("--note", "Why (8 characters or more)", required=True),
            VERSION,
        ),
    ),
    Command(
        "document-review",
        "publish",
        "Publish an approved document",
        "decide",
        workflow(
            "document-assurance",
            "publish",
            "Published.",
            DOCUMENT_REVIEW_FIELDS[:2],
            _document_review_link,
            _publication,
        ),
        (
            ID,
            Arg("--effective", "Effective date, YYYY-MM-DD", required=True),
            Arg("--review-on", "Next review date, YYYY-MM-DD", required=True),
            Arg("--note", "Publication note (8 characters or more)", required=True),
            Arg("--review-owner", "Who reviews it next: me (default), a name or a user ID"),
            VERSION,
        ),
    ),
    Command("questionnaire", "list", "List questionnaires", "read", questionnaire_list),
    Command(
        "questionnaire",
        "questions",
        "List a questionnaire's questions",
        "read",
        questionnaire_questions,
        (ID,),
        project=False,
    ),
    Command("assessment", "list", "List assessments", "read", assessment_list),
    Command(
        "assessment",
        "findings",
        "List an assessment's findings",
        "read",
        assessment_findings,
        (ID,),
        project=False,
    ),
    Command(
        "access-review",
        "list",
        "List access reviews and when the next is due",
        "read",
        access_review_list,
        project=False,
    ),
    Command(
        "access-review",
        "view",
        "Show an access review and every access in it",
        "read",
        access_review_view,
        (ID,),
        project=False,
    ),
    Command(
        "access-review",
        "start",
        "Start an access review",
        "administer",
        access_review_start,
        project=False,
    ),
    Command(
        "access-review",
        "decide",
        "Keep, change or remove one person's or token's access",
        "administer",
        access_review_decide,
        (
            ID,
            Arg("--item", "The access to decide (ID from `access-review view`)", required=True),
            Arg("--decision", "Decision", required=True, choices=("keep", "change", "remove")),
            Arg("--note", "Why"),
        ),
        "grchero access-review decide ID --item ITEM --decision keep",
        project=False,
    ),
    Command(
        "access-review",
        "complete",
        "Complete a review once every access is decided",
        "administer",
        access_review_complete,
        (ID,),
        project=False,
    ),
]
