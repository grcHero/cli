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
Keep help, rule documentation and existing-report reading available without login.
Preserve bounded file reads, symlink exclusions, explicit source scope and
non-overwriting report creation.

The grcHero backend consumes this package's scanner from a pinned commit. Treat
scanner signatures, rule identifiers and report schema as integration contracts.
Document compatibility changes and run the CLI tests before publishing.

Use Conventional Commits. Before every push, review this file and the README for
necessary updates. Do not copy private application history, credentials, local
reports, or backend implementation into this public repository.
