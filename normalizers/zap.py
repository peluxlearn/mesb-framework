import json

from models import MesbFinding


def normalize_zap(report_path: str) -> list[MesbFinding]:

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    sites = report.get("site", [])

    finding_index = 1

    for site in sites:

        alerts = site.get("alerts", [])

        for alert in alerts:

            title = alert.get(
                "name",
                alert.get("alert", "ZAP finding")
            )

            description = alert.get(
                "desc",
                ""
            )

            severity = _normalize_risk(
                alert.get("riskcode"),
                alert.get("riskdesc")
            )

            rule_id = str(
                alert.get("pluginid", "")
            ) or None

            cwe = alert.get("cweid")

            if cwe and str(cwe) != "-1":
                cwe = f"CWE-{cwe}"
            else:
                cwe = None

            instances = alert.get("instances", [])

            # One ZAP alert can affect multiple endpoints.
            # Keep one MESB finding per alert and preserve
            # the first affected endpoint as its primary endpoint.
            endpoint = None
            evidence = None

            if instances:

                first_instance = instances[0]

                endpoint = first_instance.get("uri")

                method = first_instance.get("method")
                parameter = first_instance.get("param")
                attack = first_instance.get("attack")
                evidence_value = first_instance.get("evidence")

                evidence_parts = []

                if method:
                    evidence_parts.append(
                        f"method={method}"
                    )

                if parameter:
                    evidence_parts.append(
                        f"parameter={parameter}"
                    )

                if attack:
                    evidence_parts.append(
                        f"attack={attack}"
                    )

                if evidence_value:
                    evidence_parts.append(
                        f"evidence={evidence_value}"
                    )

                if evidence_parts:
                    evidence = "; ".join(
                        evidence_parts
                    )

            finding = MesbFinding(
                id=f"DAST-{finding_index:03}",
                source="zap",
                category="dast",

                title=title,
                description=description,

                severity=severity,

                endpoint=endpoint,

                rule_id=rule_id,
                cwe=cwe,

                evidence=evidence
            )

            findings.append(finding)

            finding_index += 1

    return findings


def _normalize_risk(risk_code, risk_description):

    risk_mapping = {
        "0": "INFO",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH"
    }

    if risk_code is not None:
        severity = risk_mapping.get(
            str(risk_code)
        )

        if severity:
            return severity

    if risk_description:

        description = str(
            risk_description
        ).upper()

        if "HIGH" in description:
            return "HIGH"

        if "MEDIUM" in description:
            return "MEDIUM"

        if "LOW" in description:
            return "LOW"

        if "INFORMATIONAL" in description:
            return "INFO"

    return "UNKNOWN"