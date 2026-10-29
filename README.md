# grcHero CLI

Review selected project files locally with deterministic security checks. A grcHero account and workspace authorization are required before each scan. Source files remain local; the authorization request contains no source, paths, findings or file hashes.

Python 3.11 or newer is required. The scanner itself has no third-party runtime dependencies.

## Install

```bash
# macOS and Linux
curl -fsSL https://grchero.dev/install.sh | sh
# Windows PowerShell
irm https://grchero.dev/install.ps1 | iex

grchero login
```

The installer needs no Python setup or administrator rights, checks every download against
its published SHA-256 sum and re-running it updates. Release builds already know where to
sign in, so `grchero login` takes no options. The installer and release files are served by
the grcHero deployment, not GitHub (grcHero ADR 0014).

### From source (contributors)

```bash
git clone https://github.com/grcHero/cli.git
cd cli
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
grchero doctor
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. A source install has no
built-in sign-in values: pass them to `grchero login` as shown below.

## First review

```bash
# Source installs only; an installed release needs just `grchero login`
grchero login \
  --api-url https://app.example.com \
  --issuer https://auth.example.com \
  --client-id '<native device client ID>' \
  --audience '<grcHero project ID>'
grchero scan /path/to/project --dry-run
grchero scan /path/to/project
grchero scan /path/to/project --output review.json --fail-on medium
grchero report review.json
grchero rules
```

Login uses OAuth 2.0 Device Authorization in the browser. The access token is
written to the user-only CLI configuration file. Run `grchero logout` to remove
it, or `grchero whoami` to see the selected workspace. Expired sessions require a
new login. Production distributions will provide the trusted endpoint and client
configuration; explicit flags keep development and self-hosted installations clear.

CI should use a grcHero API token: create a service token under Settings, API tokens
with the "Command line scans" permission, then provide `GRCHERO_API_TOKEN`,
`GRCHERO_ORGANIZATION_ID` and `GRCHERO_API_URL` through its secret store. No issuer URL
is needed. A token can run scans and `whoami`; `submit` needs a signed-in person and
refuses a token. Mask the token and never commit it. `GRCHERO_ACCESS_TOKEN` with
`GRCHERO_ISSUER_URL` still works for a signed-in user's access token.

The default scope includes Dockerfiles and GitHub Actions workflows. Environment and source files require an explicit `--include`, for example `--include 'src/auth.ts'`. A `.grchero.json` at the project root can hold repeatable `include` and `exclude` arrays. Patterns use Python `fnmatch`, not gitignore semantics; exclusions always win.

Limits: 40 files, 256 KiB per file, 1 MiB total UTF-8 text, and 100 observations. Symlinks and common dependency/generated directories are skipped. The scanner does not execute project code or install project dependencies.

## More commands

```bash
# Code scanning: SARIF for GitHub and other tools; fail only on new observations
grchero scan . --format sarif > grchero.sarif
grchero scan . --baseline baseline.json --fail-on medium

# Your assigned work from the workspace
grchero work

# Add a file as evidence for a control (unreviewed until a person reviews it)
grchero evidence add test-results.pdf --control CC6.1 --note "Nightly test run"
```

## Dependency check

```bash
grchero deps                      # the current folder
grchero deps path/to/project --fail-on high
grchero deps . --format sarif > deps.sarif
grchero deps . --output deps.json # JSON report, never overwrites
```

`grchero deps` reads exact versions from lockfiles: `package-lock.json`,
`npm-shrinkwrap.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml`, `requirements*.txt`
(`name==version` pins only), `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.sum`,
`Cargo.lock`, `Gemfile.lock`, `composer.lock` and NuGet `packages.lock.json`. A
`package.json` without a lockfile is listed as "versions unknown" and skipped, never guessed.
Discovery follows the scan rules: no symlinks, dependency and build folders skipped, at most
200 lockfiles of 20 MiB each.

Only the first four hex characters of the SHA-256 of each normalized package name leave the
machine, grouped by ecosystem. grcHero returns every advisory in those buckets (OSV.dev data),
and the CLI keeps the ones for your packages and compares versions locally. Package names,
versions and lockfiles are never sent. When a version cannot be compared with an advisory's
data, the advisory is shown as possibly affected rather than dropped. Malicious packages are
always reported as critical.

`--fail-on low|medium|high|critical` exits `1` for advisories at or above that severity,
including possibly affected ones; advisories without a severity count only at `low`. The
check needs a signed-in workspace or API token, like `scan`. JSON output is
`{"schema_version": 1, "kind": "dependency-check", ...}`. A clean result means only that no
known advisory matched the locked versions.

## Reports and CI

`--format json` writes report schema version 1 to stdout. `--output FILE` creates a JSON report without overwriting an existing file. Reports include selected relative paths, applicable rule IDs, observations and file hashes; they exclude source text and detected credential values. A report may still reveal sensitive project information. Keep it private unless you deliberately choose to share it.

Exit codes: `0` completed below threshold, `1` observations at/above `--fail-on`, `2` invalid input or I/O, `130` interrupted. The threshold defaults to `none`.

There are seven narrow text heuristics: credential-like assignments in environment or source files, dynamic evaluation, production debug settings, broad workflow permissions, privileged pull-request workflow events, and Dockerfile user review. A clean result means only that these rules found nothing in the selected files. It does not establish security or compliance.

## Workspace compatibility

The report's `schema_version` and `rules_version` are explicit so the grcHero API can validate observations without receiving source code. Each scan obtains a short server authorization for the selected workspace. Report upload remains a separate, explicit action: `grchero submit review.json [--project UUID] [--title TEXT]` previews the workspace, project, paths and observations, asks for confirmation (or `--yes`), then prints the draft URL. File hashes, source and detected values are never sent. Retrying the same command is safe because the import ID is derived from the workspace and content. Browser import still works, and nothing is uploaded unless you run `submit`. See [the report contract](docs/REPORT_FORMAT.md).

## Any API call

`grchero api METHOD PATH` calls any grcHero endpoint for the signed-in workspace and prints
the JSON, like `gh api`. Add text fields with `-f key=value`, typed ones with
`-F key=JSON`, or a whole body with `--input FILE`:

```bash
grchero api GET /exceptions
grchero api POST /exceptions/ID/decisions -f decision=approve -F expected_version=3
```

Reading and writing run at once. Anything that decides (approve, reject, close, publish) or
administers (members, tokens, settings) needs you to confirm that one request in the browser:
the CLI prints and opens a link, you check what it will do and sign in again, and the CLI then
repeats the identical request once. A declined or expired request does nothing. API tokens
cannot decide or administer.

## Agents

AI agents can run the CLI like a person. Every request to grcHero names the client
(`grchero/VERSION`) and, when known, the agent driving it, so the workspace audit log and CLI
page show who acted and through what. Set `GRCHERO_AGENT` to name the agent, for example
`GRCHERO_AGENT="Release pipeline"`; inside Claude Code it is named automatically. These names
never grant access: owners choose in workspace Settings what agents may do (off, read only, or
read and draft), and approving, publishing and administering stay in the workspace for people.

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
```

`python scripts/build_release.py --deployment values.json [--native]` builds the release
files (single-file app, native program with PyInstaller as a build tool, checksums and
manifest). `values.json` holds the deployment's public `api_url`, `issuer_url`, `client_id`
and `audience`. The `Release` workflow builds every platform on a `v*` tag, reading those
values from repository variables.

The scanner and report contract are maintained here. Backend integration should consume a pinned release and test rule parity before upgrading. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
