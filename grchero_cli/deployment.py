"""Sign-in defaults a release build stamps in, so `grchero login` needs no flags.

A release writes ``deployment.json`` next to this module with the deployment's public
sign-in values (API URL, issuer, CLI client ID, project audience). None of them is a
secret. Source checkouts have no such file, so their sign-in still needs flags or
``GRCHERO_*`` environment variables, which always take precedence.
"""

import json
from importlib import resources

FIELDS = ("api_url", "issuer_url", "client_id", "audience")


def deployment_defaults() -> dict[str, str]:
    try:
        text = resources.files(__package__).joinpath("deployment.json").read_text("utf-8")
        data = json.loads(text)
    except (FileNotFoundError, OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {field: str(data[field]) for field in FIELDS if isinstance(data.get(field), str)}
