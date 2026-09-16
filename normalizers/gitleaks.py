import json

from models import MesbFinding


def normalize_gitleaks(report_path: str) -> list[MesbFinding]:

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    # Gitleaks JSON is normally an array of findings.
    if not isinstance(report, list):
        raise ValueError(
            "Invalid Gitleaks report: expected a JSON array"
        )

    for index, result in enumerate(report, start=1):

        rule_id = result.get("RuleID")
        description = result.get(
            "Description",
            "Potential secret detected"
        )

        file_path = result.get("File")
        line = result.get("StartLine")

        secret = result.get("Secret")
        match = result.get("Match")

        # Never propagate the complete secret into the MESB output.
        evidence = _mask_secret(
            secret if secret else match
        )

        finding = MesbFinding(
            id=f"SECRET-{index:03}",
            source="gitleaks",
            category="secrets",

            title=description,
            description=description,

            severity="HIGH",

            file=file_path,
            line=line,

            rule_id=rule_id,

            evidence=evidence
        )

        findings.append(finding)

    return findings


def _mask_secret(value):

    if not value:
        return None

    value = str(value)

    if len(value) <= 4:
        return "****"

    return f"{value[:2]}***{value[-2:]}"