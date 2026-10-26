"""Finding identity across runs (baselines) and SARIF output for code-scanning tools."""

import hashlib
from typing import Any

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def fingerprint(finding: dict[str, Any]) -> str:
    """Stable across runs: rule, file and observation, but not the line, which moves with edits."""
    key = "\x1f".join(str(finding.get(field, "")) for field in ("rule_id", "path", "observation"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def existing_findings(baseline: dict[str, Any]) -> set[str]:
    return {fingerprint(finding) for finding in baseline["findings"]}


def to_sarif(
    report: dict[str, Any],
    rules: list[tuple[str, str, str]],
    version: str,
    existing: set[str] | None = None,
) -> dict[str, Any]:
    """SARIF 2.1.0 so GitHub code scanning and other tools show observations inline."""
    titles = {finding["rule_id"]: finding["title"] for finding in report["findings"]}
    results = []
    for finding in report["findings"]:
        print_id = fingerprint(finding)
        result: dict[str, Any] = {
            "ruleId": finding["rule_id"],
            "level": LEVEL[finding["severity"]],
            "message": {"text": f"{finding['observation']} Next: {finding['recommendation']}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["path"],
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": finding["line"]},
                    }
                }
            ],
            "partialFingerprints": {"grcheroFinding/v1": print_id},
        }
        if existing is not None:
            result["baselineState"] = "unchanged" if print_id in existing else "new"
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "grcHero CLI",
                        "version": version,
                        "semanticVersion": version,
                        "informationUri": "https://grchero.dev/docs/cli/rules",
                        "rules": [
                            {
                                "id": rule,
                                "name": rule,
                                "shortDescription": {"text": titles.get(rule, description)},
                                "fullDescription": {"text": description},
                                "helpUri": "https://grchero.dev/docs/cli/rules",
                                "defaultConfiguration": {"level": LEVEL[severity]},
                                "properties": {"security-severity": SECURITY_SEVERITY[severity]},
                            }
                            for rule, severity, description in rules
                        ],
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


# GitHub orders code-scanning alerts by this score: high 7.0+, medium 4.0+, low below.
SECURITY_SEVERITY = {"high": "7.5", "medium": "5.0", "low": "2.0"}
