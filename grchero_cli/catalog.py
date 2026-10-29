"""The framework behind `grchero <area> <verb>` (ADR 0017 in grcHero).

A command is data: its area, verb, tier, arguments and handler. The same list builds the
argument parser and `grchero help --json`, so the help an agent reads is the parser it runs.
Each command names its tier: read and write run at once; decide and administer wait for the
person to confirm the one request in the browser (grcHero enforces this, the tier here only
describes it, and grcHero's tests pin each call's tier).

Workflow verbs read the record first and send its current version, so a change made in the
meantime is refused rather than overwritten; `--version N` pins the version you reviewed.
"""

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID

from .scope import CliError
from .workspace import Workspace, open_workspace

EXIT_CODES = {
    0: "done",
    1: "failed: grcHero refused the request or could not be reached",
    2: "usage or local problem",
    3: "waiting for your confirmation in the browser",
    4: "not allowed for this sign-in, role or agent setting",
}


@dataclass(frozen=True)
class Arg:
    name: str
    help: str
    required: bool = False
    choices: tuple[str, ...] | None = None
    metavar: str | None = None
    multiple: bool = False
    flag: bool = False
    integer: bool = False
    # A positional that may be left out, so `--all`, `--clear` and saved defaults work.
    optional: bool = False


@dataclass(frozen=True)
class Output:
    data: Any
    text: str


@dataclass(frozen=True)
class Command:
    area: str
    verb: str
    summary: str
    tier: str
    run: Callable[[argparse.Namespace], Output]
    args: tuple[Arg, ...] = ()
    example: str = ""
    # Accepts --project; lists filter by it and new records join it.
    project: bool = True

    @property
    def name(self) -> str:
        return f"{self.area} {self.verb}"


ID = Arg("id", "Record ID", metavar="ID")
NOTE = Arg("--note", "Note for the record")
DECISION_NOTE = Arg("--note", "Why you decide this")
VERSION = Arg("--version", "Act only on this version (default: the current one)", integer=True)
LIMIT = Arg("--limit", "Most items to show (default 50)", integer=True)


# Rendering


def clean(value: Any) -> str:
    # Server text is shown in a terminal: drop control characters so it cannot inject escapes.
    return "".join(c for c in str("" if value is None else value) if ord(c) >= 32)


def label(value: Any) -> str:
    return clean(value).replace("_", " ")


def table(items: list[dict[str, Any]], columns: list[tuple[str, str]], empty: str) -> str:
    if not items:
        return empty
    rows = [[label(item.get(key))[:60] for key, _ in columns] for item in items]
    widths = [
        max(len(heading), *(len(row[index]) for row in rows))
        for index, (_, heading) in enumerate(columns)
    ]
    lines = ["  ".join(h.ljust(w) for (_, h), w in zip(columns, widths, strict=True)).rstrip()]
    lines += [
        "  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip() for row in rows
    ]
    return "\n".join(lines)


def record(item: dict[str, Any], fields: list[tuple[str, str]], link: str = "") -> str:
    shown = [
        (heading, item.get(key))
        for key, heading in fields
        if item.get(key) not in (None, "", [], {})
    ]
    if link:
        shown.append(("Open", link))
    width = max((len(heading) for heading, _ in shown), default=0)
    lines = []
    for heading, value in shown:
        text = ", ".join(label(v) for v in value) if isinstance(value, list) else label(value)
        lines.append(f"{heading.ljust(width)}  {text}")
    return "\n".join(lines)


def done(item: dict[str, Any], message: str, fields: list[tuple[str, str]], link: str) -> Output:
    return Output(item, f"{message}\n{record(item, fields, link)}".rstrip())


def listing(items: list[dict[str, Any]], columns: list[tuple[str, str]], empty: str) -> Output:
    return Output(items, table(items, columns, empty))


# Values


def as_id(value: str, what: str = "ID") -> str:
    try:
        return str(UUID(value))
    except ValueError:
        raise CliError(f"{what} must be a UUID, not {value!r}.") from None


def as_day(value: str | None, flag: str) -> str | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        raise CliError(f"{flag} must be a date like 2027-01-31.") from None


def as_moment(value: str | None, flag: str) -> str | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise CliError(f"{flag} must be a time like 2026-11-02T14:00 or 2026-11-02.") from None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).isoformat()


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


# Calls


def workspace(args: argparse.Namespace) -> Workspace:
    return open_workspace(args.org, getattr(args, "project", None))


def items_of(value: Any) -> list[dict[str, Any]]:
    """A list response, or the items of a page."""
    raw = value.get("items", []) if isinstance(value, dict) else value
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def current_version(ws: Workspace, path: str, pinned: int | None) -> int:
    if pinned is not None:
        return pinned
    current = ws.get(path)
    if not isinstance(current, dict) or not isinstance(current.get("version"), int):
        raise CliError("grcHero returned a record without a version.", 1)
    return current["version"]


def latest_submission(current: dict[str, Any]) -> str:
    """The newest submission of a review (grcHero lists them newest first)."""
    submissions = current.get("submissions") or []
    if not submissions or not isinstance(submissions[0], dict):
        raise CliError("Nothing has been submitted for review yet.", 1)
    return str(submissions[0]["id"])


def person(ws: Workspace, path: str, wanted: str | None) -> str:
    """`me` (the default), a user ID, or a name from the area's list of people."""
    people = items_of(ws.get(path))
    if not wanted or wanted == "me":
        match = [item for item in people if item.get("is_current_user")]
    else:
        match = [
            item
            for item in people
            if str(item.get("user_id")) == wanted
            or str(item.get("display_name", "")).lower() == wanted.lower()
        ]
    if len(match) != 1:
        raise CliError(f"No single person {wanted or 'me'!r} here. Use their user ID.")
    return str(match[0]["user_id"])


def pages(ws: Workspace, path: str, limit: int, **query: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    while len(items) < limit:
        value = ws.get(path, cursor=cursor, **query)
        items += items_of(value)
        cursor = value.get("next_cursor") if isinstance(value, dict) else None
        if not cursor:
            break
    return items[:limit]


def find(items: list[dict[str, Any]], wanted: str, what: str) -> dict[str, Any]:
    """One record from a list endpoint, for areas without a single-record route."""
    match = next((item for item in items if str(item.get("id")) == wanted), None)
    if match is None:
        raise CliError(f"No {what} with that ID in this workspace.", 1)
    return match


def workflow(
    area: str,
    action: str,
    message: str,
    fields: list[tuple[str, str]],
    link: Callable[[Workspace, dict[str, Any]], str],
    extra: Callable[[argparse.Namespace], dict[str, Any]] = lambda _args: {},
    *,
    detail: str = "",
    submission: bool = False,
) -> Callable[[argparse.Namespace], Output]:
    """POST /{area}/{id}/{action} with the record's current (or pinned) version.

    ``detail`` is appended to /{area}/{id} when the record is read from a sub-path;
    ``submission`` adds the newest submission's ID, which review decisions answer.
    """

    def run(args: argparse.Namespace) -> Output:
        ws = workspace(args)
        path = f"/{area}/{as_id(args.id)}"
        if submission:
            current = ws.get(path + detail)
            pinned = args.version if args.version is not None else current.get("version")
            body = {"expected_version": pinned, "submission_id": latest_submission(current)}
        else:
            body = {"expected_version": current_version(ws, path + detail, args.version)}
        item = ws.call("POST", f"{path}/{action}", {**body, **extra(args)})
        item = item if isinstance(item, dict) else {}
        return done(item, message, fields, link(ws, item))

    return run


# Parser and help


def add_common(parser: argparse.ArgumentParser, project: bool) -> None:
    parser.add_argument("--json", action="store_true", help="Print JSON for scripts and agents")
    parser.add_argument("--org", metavar="WORKSPACE", help="Workspace ID or slug for this command")
    if project:
        parser.add_argument(
            "--project",
            metavar="PROJECT",
            help="Project ID or name, or none (default: `grchero project use`)",
        )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="If confirmation is needed, print the link and exit 3 instead of waiting",
    )
    parser.add_argument(
        "--confirmation",
        metavar="ID",
        help="Run again after confirming in the browser; waits until it is confirmed",
    )


def _add_arg(parser: argparse.ArgumentParser, arg: Arg) -> None:
    if not arg.name.startswith("--"):
        parser.add_argument(arg.name, nargs="?", help=arg.help, metavar=arg.metavar)
        return
    options: dict[str, Any] = {"help": arg.help}
    if arg.flag:
        options["action"] = "store_true"
    else:
        options["required"] = arg.required
        if arg.choices:
            options["choices"] = arg.choices
        if arg.multiple:
            options["action"] = "append"
            options["default"] = []
        if arg.integer:
            options["type"] = int
    parser.add_argument(arg.name, **options)


def install(commands: Sequence[Command], subparsers: Any, existing: dict[str, Any]) -> None:
    """Add every command to the top-level subparsers.

    ``existing`` maps an area that already has hand-written verbs (``evidence add``) to its
    subparsers, so catalog verbs sit beside them.
    """
    areas: dict[str, Any] = dict(existing)
    for command in commands:
        if command.area not in areas:
            area = subparsers.add_parser(command.area, help=f"Work with {command.area} records")
            areas[command.area] = area.add_subparsers(dest=f"{command.area}_command", required=True)
        verb = areas[command.area].add_parser(
            command.verb,
            help=command.summary,
            description=f"{command.summary}. Tier: {command.tier}.",
        )
        for arg in command.args:
            _add_arg(verb, arg)
        add_common(verb, command.project)
        verb.set_defaults(catalog=command.name)


def run(command: Command, args: argparse.Namespace) -> Output:
    for arg in command.args:
        if arg.name.startswith("--") or arg.optional:
            continue
        if getattr(args, arg.name, None) in (None, ""):
            raise CliError(f"`grchero {command.name}` needs {arg.metavar or arg.name}.")
    return command.run(args)


def describe(
    parser: argparse.ArgumentParser, by_name: dict[str, Command], tiers: dict[str, str]
) -> list[dict[str, Any]]:
    """Every command as data, for `grchero help --json`; read from the parser itself."""

    def walk(node: argparse.ArgumentParser, prefix: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for action in node._actions:
            if not isinstance(action, argparse._SubParsersAction):
                continue
            helps = {choice.dest: choice.help or "" for choice in action._choices_actions}
            for name, child in action.choices.items():
                full = f"{prefix} {name}".strip()
                nested = walk(child, full)
                if nested:
                    found += nested
                    continue
                command = by_name.get(full)
                entry: dict[str, Any] = {
                    "name": full,
                    "summary": helps.get(name, ""),
                    "tier": command.tier if command else tiers.get(full, "local"),
                    "arguments": [
                        {
                            "name": item.option_strings[-1] if item.option_strings else item.dest,
                            "help": item.help or "",
                            "required": bool(item.required),
                            **({"choices": list(item.choices)} if item.choices else {}),
                            **({"repeatable": True} if item.default == [] else {}),
                        }
                        for item in child._actions
                        if not isinstance(item, argparse._HelpAction)
                    ],
                }
                if command and command.example:
                    entry["example"] = command.example
                found.append(entry)
        return found

    return walk(parser, "")
