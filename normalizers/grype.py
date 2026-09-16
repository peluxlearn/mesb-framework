import json

from models import MesbFinding


def normalize_grype(report_path: str) -> list[MesbFinding]:

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    matches = report.get("matches", [])

    for index, match in enumerate(matches, start=1):

        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vulnerability_id = vulnerability.get(
            "id",
            "Unknown vulnerability"
        )

        severity = vulnerability.get(
            "severity",
            "UNKNOWN"
        )

        description = vulnerability.get(
            "description",
            ""
        )

        component = artifact.get("name")
        version = artifact.get("version")

        cvss = _extract_cvss(vulnerability)

        cve = (
            vulnerability_id
            if vulnerability_id.startswith("CVE-")
            else None
        )

        locations = artifact.get("locations", [])

        file_path = None

        if locations:
            file_path = locations[0].get("path")

        finding = MesbFinding(
            id=f"CONTAINER-{index:03}",
            source="grype",
            category="container",

            title=vulnerability_id,
            description=description,

            severity=severity,

            file=file_path,

            component=component,
            version=version,

            cve=cve,
            cvss=cvss,

            evidence=(
                f"{component}@{version}"
                if component and version
                else component
            )
        )

        findings.append(finding)

    return findings


def _extract_cvss(vulnerability: dict):

    cvss_entries = vulnerability.get("cvss", [])

    if not cvss_entries:
        return None

    scores = []

    for entry in cvss_entries:

        metrics = entry.get("metrics", {})

        base_score = metrics.get("baseScore")

        if base_score is not None:
            try:
                scores.append(float(base_score))
            except (TypeError, ValueError):
                continue

    if not scores:
        return None

    # If multiple CVSS sources/versions exist,
    # preserve the highest technical score.
    return max(scores)