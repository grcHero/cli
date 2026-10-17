# grcHero CLI

Review selected project files locally with deterministic security checks. A grcHero account and workspace authorization are required before each scan. Source files remain local; the authorization request contains no source, paths, findings or file hashes.

Python 3.11 or newer is required. The scanner itself has no third-party runtime dependencies.

## Install from source

```bash
git clone https://github.com/grcHero/cli.git
cd cli
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
grchero doctor
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. The package has not yet been published to PyPI; install from a reviewed tag or commit when using it in CI.

## First review

```bash
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

CI may provide `GRCHERO_ACCESS_TOKEN`, `GRCHERO_ORGANIZATION_ID`,
`GRCHERO_API_URL`, and `GRCHERO_ISSUER_URL` through its secret store. Use a
dedicated least-privilege grcHero user, mask the token, and never commit it.

The default scope includes Dockerfiles and GitHub Actions workflows. Environment and source files require an explicit `--include`, for example `--include 'src/auth.ts'`. A `.grchero.json` at the project root can hold repeatable `include` and `exclude` arrays. Patterns use Python `fnmatch`, not gitignore semantics; exclusions always win.

Limits: 40 files, 256 KiB per file, 1 MiB total UTF-8 text, and 100 observations. Symlinks and common dependency/generated directories are skipped. The scanner does not execute project code or install project dependencies.

## Reports and CI

`--format json` writes report schema version 1 to stdout. `--output FILE` creates a JSON report without overwriting an existing file. Reports include selected relative paths, applicable rule IDs, observations and file hashes; they exclude source text and detected credential values. A report may still reveal sensitive project information. Keep it private unless you deliberately choose to share it.

Exit codes: `0` completed below threshold, `1` observations at/above `--fail-on`, `2` invalid input or I/O, `130` interrupted. The threshold defaults to `none`.

There are seven narrow text heuristics: credential-like assignments in environment or source files, dynamic evaluation, production debug settings, broad workflow permissions, privileged pull-request workflow events, and Dockerfile user review. A clean result means only that these rules found nothing in the selected files. It does not establish security or compliance.

## Workspace compatibility

The report's `schema_version` and `rules_version` are explicit so the grcHero API can validate observations without receiving source code. Each scan obtains a short server authorization for the selected workspace. Report upload remains a separate, explicit action: `grchero submit review.json [--project UUID] [--title TEXT]` previews the workspace, project, paths and observations, asks for confirmation (or `--yes`), then prints the draft URL. File hashes, source and detected values are never sent. Retrying the same command is safe because the import ID is derived from the workspace and content. Browser import still works, and nothing is uploaded unless you run `submit`. See [the report contract](docs/REPORT_FORMAT.md).

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
```

The scanner and report contract are maintained here. Backend integration should consume a pinned release and test rule parity before upgrading. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
