# Contributor instructions

Keep the CLI usable without an account or network access for local scans. Never
execute reviewed source or include detected credentials in terminal/JSON output.
Preserve bounded file reads, symlink exclusions, explicit source scope and
non-overwriting report creation.

The grcHero backend consumes this package's scanner from a pinned commit. Treat
scanner signatures, rule identifiers and report schema as integration contracts.
Document compatibility changes and run the CLI tests before publishing.

Use Conventional Commits. Before every push, review this file and the README for
necessary updates. Do not copy private application history, credentials, local
reports, or backend implementation into this public repository.
