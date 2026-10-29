"""Administration commands: members, API tokens and what AI agents may do.

Every change here administers the workspace, so grcHero runs it only after the person confirms
the one request in the browser, and never for an agent. Creating API tokens stays in the
browser, so a token's secret is never printed into a terminal or an agent's context; invitation
links are sent by email and left out of the output for the same reason.
"""

import argparse
from typing import Any

from .catalog import ID, Arg, Command, Output, as_id, items_of, record, table, workspace
from .scope import CliError

ROLES = ("admin", "compliance_manager", "reviewer", "contributor", "viewer")
LEVELS = ("off", "read", "write")
MEMBER = Arg("id", "Member ID (from `member list`)", metavar="ID")


def member_list(args: argparse.Namespace) -> Output:
    team = workspace(args).get("/organizations/current/team")
    columns = [("display_name", "Name"), ("email", "Email"), ("role", "Role"), ("id", "ID")]
    text = table(items_of(team.get("members")), columns, "No members.")
    invitations = items_of(team.get("invitations"))
    if invitations:
        text += "\n\n" + table(invitations, [("email", "Invited"), ("role", "Role")], "")
    if team.get("next_cursor"):
        text += "\n\nMore members are listed in the workspace under Settings, Team."
    return Output(team, text)


def member_invite(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    result = ws.call(
        "POST", "/organizations/current/invitations", {"email": args.email, "role": args.role}
    )
    # The invitation link admits whoever holds it, so it travels by email only.
    shown = {key: value for key, value in result.items() if key != "invite_url"}
    return Output(shown, f"Invited {args.email} as {args.role.replace('_', ' ')}.")


def member_role(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    path = f"/organizations/current/team/{as_id(args.id)}"
    item = ws.call("PATCH", path, {"role": args.role})
    fields = [("display_name", "Name"), ("email", "Email"), ("role", "Role")]
    return Output(item, "Role changed.\n" + record(item, fields))


def member_remove(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    ws.call("DELETE", f"/organizations/current/team/{as_id(args.id)}")
    return Output({"removed": args.id}, "Member removed from the workspace.")


def token_list(args: argparse.Namespace) -> Output:
    items = items_of(workspace(args).get("/api-tokens", everyone=args.everyone))
    columns = [
        ("name", "Token"),
        ("kind", "Kind"),
        ("status", "Status"),
        ("owner_name", "Owner"),
        ("expires_at", "Expires"),
        ("id", "ID"),
    ]
    return Output(items, table(items, columns, "No API tokens."))


def token_revoke(args: argparse.Namespace) -> Output:
    ws = workspace(args)
    item = ws.call("POST", f"/api-tokens/{as_id(args.id)}/revoke", {})
    return Output(item, f"Revoked {item.get('name', 'the token')}. It stops working at once.")


def _policy_text(policy: dict[str, Any]) -> str:
    meaning = {"off": "off", "read": "read only", "write": "read and draft"}
    return (
        f"Agents using the CLI: {meaning.get(policy.get('cli', ''), policy.get('cli'))}\n"
        f"AI apps using MCP: {meaning.get(policy.get('mcp', ''), policy.get('mcp'))}"
    )


def agents_view(args: argparse.Namespace) -> Output:
    policy = workspace(args).get("/organizations/current/agent-policy")
    return Output(policy, _policy_text(policy))


def agents_set(args: argparse.Namespace) -> Output:
    if args.cli is None and args.mcp is None:
        raise CliError("Pass --cli, --mcp or both.")
    ws = workspace(args)
    current = ws.get("/organizations/current/agent-policy")
    body = {"cli": args.cli or current["cli"], "mcp": args.mcp or current["mcp"]}
    policy = ws.call("PUT", "/organizations/current/agent-policy", body)
    return Output(policy, "Agent setting saved.\n" + _policy_text(policy))


COMMANDS: list[Command] = [
    Command(
        "member",
        "list",
        "List members and pending invitations",
        "read",
        member_list,
        project=False,
    ),
    Command(
        "member",
        "invite",
        "Invite someone by email",
        "administer",
        member_invite,
        (
            Arg("--email", "Their email address", required=True),
            Arg("--role", "Role", required=True, choices=ROLES),
        ),
        "grchero member invite --email ada@example.com --role contributor",
        project=False,
    ),
    Command(
        "member",
        "role",
        "Change a member's role",
        "administer",
        member_role,
        (MEMBER, Arg("--role", "New role", required=True, choices=ROLES)),
        project=False,
    ),
    Command(
        "member",
        "remove",
        "Remove a member from the workspace",
        "administer",
        member_remove,
        (MEMBER,),
        project=False,
    ),
    Command(
        "token",
        "list",
        "List API tokens",
        "read",
        token_list,
        (Arg("--everyone", "Include other people's tokens (owners and admins)", flag=True),),
        project=False,
    ),
    Command(
        "token",
        "revoke",
        "Revoke an API token",
        "administer",
        token_revoke,
        (ID,),
        project=False,
    ),
    Command(
        "agents",
        "view",
        "Show what AI agents may do in this workspace",
        "read",
        agents_view,
        project=False,
    ),
    Command(
        "agents",
        "set",
        "Choose what AI agents may do: off, read, or write (read and draft)",
        "administer",
        agents_set,
        (
            Arg("--cli", "Agents using the CLI", choices=LEVELS),
            Arg("--mcp", "AI apps using MCP", choices=LEVELS),
        ),
        "grchero agents set --cli read",
        project=False,
    ),
]
