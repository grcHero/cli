# Security policy

Please do not disclose a CLI vulnerability in a public issue. Use GitHub's **Report a vulnerability** feature in this repository's Security tab, or contact grcHero maintainers through an established private channel. Include the affected version, reproduction steps using synthetic data, and likely impact. Do not include real credentials or customer source.

The CLI processes potentially sensitive local project files. Its normal `scan`, `rules`, `doctor`, and `report` commands do not send data over a network. A saved report contains paths and observations and should be handled as sensitive project metadata.

Supported security updates target the latest released minor version. Until the first tagged release, use a pinned reviewed commit.
