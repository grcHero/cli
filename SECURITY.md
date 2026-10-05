# Security policy

Please do not disclose a CLI vulnerability in a public issue. Use GitHub's **Report a vulnerability** feature in this repository's Security tab, or contact grcHero maintainers through an established private channel. Include the affected version, reproduction steps using synthetic data, and likely impact. Do not include real credentials or customer source.

The CLI processes potentially sensitive local project files. `scan` contacts the
configured grcHero API to authenticate and authorize usage before local analysis.
That request sends the CLI version, a random idempotency key and the selected
workspace ID; it does not send source, paths, findings or file hashes. `rules`,
`doctor`, and `report` do not require authentication. A saved report contains paths
and observations and should be handled as sensitive project metadata.

Device login sends credentials only to the explicitly configured ZITADEL issuer;
API bearer tokens are sent only to the explicitly configured grcHero API origin.
Non-loopback endpoints must use HTTPS. The credential file is created with user-only
permissions. Do not commit it or copy it into project directories.
For CI, inject `GRCHERO_ACCESS_TOKEN` through the runner's secret store and use a
dedicated least-privilege workspace account. Environment tokens take precedence
over the local credential file and are never written by the CLI.

Supported security updates target the latest released minor version. Until the first tagged release, use a pinned reviewed commit.
