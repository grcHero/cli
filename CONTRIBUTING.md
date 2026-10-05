# Contributing to grcHero CLI

Issues and pull requests are welcome. Start with a small, reproducible issue and explain the selected file, expected observation, and actual output. Do not post real secrets, private source, workspace reports, access tokens, or customer information.

Set up Python 3.11+ with `python -m pip install -e '.[dev]'`. Run `python -m pytest`, `ruff check .`, and `ruff format --check .` before opening a pull request.

Scanner changes need a focused positive and negative fixture. Preserve the default local behavior, bounded file collection, no execution of project code, no secret values in output, and the report schema contract. A rule behavior change needs a `rules_version` review; a breaking report change needs a new `schema_version` and migration guidance.

By submitting a contribution you agree that it is distributed under this repository's MIT license. Security reports should follow [SECURITY.md](SECURITY.md), not a public issue.
