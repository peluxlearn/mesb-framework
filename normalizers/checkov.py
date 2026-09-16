import json

from models import MesbFinding


def normalize_checkov(report_path: str) -> list[MesbFinding]:

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    # Checkov can return either one result object
    # or a list of result objects for multiple frameworks.
    reports = report if isinstance(report, list) else [report]

    finding_index = 1

    for checkov_report in reports:

        results = checkov_report.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for result in failed_checks:

            check_id = result.get(
                "check_id",
                "Unknown Checkov check"
            )

            check_name = result.get(
                "check_name",
                check_id
            )

            file_path = result.get("file_path")

            line = _extract_line(
                result.get("file_line_range")
            )

            guideline = result.get("guideline")

            finding = MesbFinding(
                id=f"IAC-{finding_index:03}",
                source="checkov",
                category="iac",

                title=check_name,
                description=check_name,

                # Checkov failed checks do not provide
                # a universal CVSS-style severity.
                severity="UNKNOWN",

                file=file_path,
                line=line,

                rule_id=check_id,

                evidence=guideline
            )

            findings.append(finding)

            finding_index += 1

    return findings


def _extract_line(line_range):

    if not line_range:
        return None

    if isinstance(line_range, list):
        return line_range[0]

    return None