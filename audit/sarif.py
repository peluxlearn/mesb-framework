from typing import Any, Dict, List


SARIF_VERSION = "2.1.0"

SARIF_SCHEMA = (
    "https://json.schemastore.org/"
    "sarif-2.1.0.json"
)


def severity_to_sarif_level(
    severity: str
) -> str:

    normalized = (
        severity
        or ""
    ).upper()

    if normalized in {
        "CRITICAL",
        "HIGH"
    }:
        return "error"

    if normalized == "MEDIUM":
        return "warning"

    return "note"


def create_sarif_document(
    tool_name: str,
    tool_version: str,
    results: List[Dict[str, Any]],
    properties: Dict[str, Any] | None = None
) -> Dict[str, Any]:

    sarif_results = []

    for result in results:

        rule_id = str(
            result.get(
                "rule_id",
                "MESB"
            )
        )

        message = str(
            result.get(
                "message",
                ""
            )
        )

        severity = str(
            result.get(
                "severity",
                "LOW"
            )
        )

        sarif_result = {
            "ruleId": rule_id,
            "level":
                severity_to_sarif_level(
                    severity
                ),
            "message": {
                "text": message
            },
            "properties": {
                "mesbSeverity":
                    severity,
                **result.get(
                    "properties",
                    {}
                )
            }
        }

        locations = result.get(
            "locations",
            []
        )

        if locations:

            sarif_result[
                "locations"
            ] = locations

        sarif_results.append(
            sarif_result
        )


    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri":
                    "https://mesb.local"
            }
        },
        "results": sarif_results
    }


    if properties:

        run["properties"] = (
            properties
        )


    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            run
        ]
    }