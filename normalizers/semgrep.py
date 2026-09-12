import json

from models import MesbFinding


def normalize_semgrep(report_path: str) -> list[MesbFinding]:
    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    for index, result in enumerate(report.get("results", []), start=1):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {})

        cwe_values = metadata.get("cwe", [])
        owasp_values = metadata.get("owasp", [])

        finding = MesbFinding(
            id=f"SAST-{index:03}",
            source="semgrep",
            category="sast",

            title=extra.get(
                "message",
                result.get("check_id", "Semgrep finding")
            ),

            description=extra.get("message", ""),

            severity=extra.get("severity", "UNKNOWN"),

            file=result.get("path"),
            line=start.get("line"),

            rule_id=result.get("check_id"),

            cwe=", ".join(cwe_values)
            if isinstance(cwe_values, list)
            else str(cwe_values),

            owasp=", ".join(owasp_values)
            if isinstance(owasp_values, list)
            else str(owasp_values),

            evidence=extra.get("lines")
        )

        findings.append(finding)

    return findings