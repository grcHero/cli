# Contributor instructions

Require a live grcHero account and workspace authorization before every scan,
including scope previews. Analysis still runs locally: never upload source files,
execute reviewed source or include detected credentials in terminal/JSON/SARIF output.
`grchero evidence add` is the only file upload: one file the person names, of a type the
workspace accepts as evidence (never source code or folders), after a preview and
confirmation (`--yes` in CI). It lands as unreviewed evidence; never mark it reviewed.
`grchero deps` sends only 4-hex-character prefixes of sha256(normalized package name),
grouped by ecosystem; never send package names, versions or lockfiles, and match
advisories to versions locally.
Every authenticated request to grcHero sends `X-Grchero-Client` and, when known,
`X-Grchero-Agent` (from `GRCHERO_AGENT`, or Claude Code when `CLAUDECODE=1`); never send them to
the sign-in server, and never treat them as a permission.
When grcHero answers `confirmation_required`, open only its `/confirm/` HTTPS link, wait for the
person's answer and repeat the identical request once with `X-Grchero-Confirmation`; never
confirm on the person's behalf. `grchero api` paths stay relative to the workspace API.
Workspace commands (`grchero <area> <verb>`) live in the `COMMANDS` catalog in
`grchero_cli/commands.py`, which builds both the parser and `grchero help --json`; never add one
outside it. Each command's tier must match grcHero's `action_tier()` for its request (the backend
lists every CLI call in `tests/test_agent_access.py`). Keep exit codes fixed (0 done, 1 failed, 2
usage, 3 waiting for confirmation, 4 not allowed), keep `--json` output as grcHero returns it,
strip control characters from server text in terminal output, and never prompt outside a
terminal. Workflow verbs send the record's current version; never retry a refused version.
`context.json` holds only workspace and project IDs and names.
Area modules (`commands.py`, `assurance.py`, `operations.py`, `admin.py`) import only from
`catalog.py`. Never create API tokens from the CLI or print an invitation link or any other
secret grcHero returns. Review decisions answer the newest submission.
`grchero mcp` (`grchero_cli/mcp.py`) writes only protocol messages to stdout (everything else
to stderr), names itself `grchero-mcp/VERSION` with the app's name, never waits for a browser
confirmation and offers no tool that decides or administers; drafts must create draft or open
records only. Mark every result as untrusted data and keep the size limits.
Keep help, rule documentation and existing-report reading available without login.
Preserve bounded file reads, symlink exclusions, explicit source scope and
non-overwriting report creation.

The grcHero backend consumes this package's scanner from a pinned commit. Treat
scanner signatures, rule identifiers and report schema as integration contracts.
Document compatibility changes and run the CLI tests before publishing.

Use Conventional Commits. Before every push, review this file and the README for
necessary updates. Do not copy private application history, credentials, local
reports, or backend implementation into this public repository.
