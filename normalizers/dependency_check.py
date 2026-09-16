import json

from models import MesbFinding


def normalize_dependency_check(report_path: str) -> list[MesbFinding]:

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = []

    dependencies = report.get("dependencies", [])

    finding_index = 1

    for dependency in dependencies:

        vulnerabilities = dependency.get("vulnerabilities", [])

        if not vulnerabilities:
            continue

        component = dependency.get("fileName")
        file_path = dependency.get("filePath")

        # Dependency-Check may identify one or more software identifiers.
        packages = dependency.get("packages", [])

        version = None

        if packages:
            package = packages[0]

            # Package IDs commonly look like:
            # pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.24
            package_id = package.get("id", "")

            if "@" in package_id:
                version = package_id.rsplit("@", 1)[-1]

        for vulnerability in vulnerabilities:

            vulnerability_name = vulnerability.get(
                "name",
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

            cvss = _extract_cvss(vulnerability)

            cwes = vulnerability.get("cwes", [])

            finding = MesbFinding(
                id=f"SCA-{finding_index:03}",
                source="dependency-check",
                category="sca",

                title=vulnerability_name,
                description=description,

                severity=severity,

                file=file_path,

                component=component,
                version=version,

                cve=(
                    vulnerability_name
                    if vulnerability_name.startswith("CVE-")
                    else None
                ),

                cvss=cvss,

                cwe=", ".join(cwes)
                if isinstance(cwes, list)
                else str(cwes),

                evidence=dependency.get("fileName")
            )

            findings.append(finding)

            finding_index += 1

    return findings


def _extract_cvss(vulnerability: dict):

    cvss_v4 = vulnerability.get("cvssv4")

    if cvss_v4:
        score = cvss_v4.get("baseScore")

        if score is not None:
            return float(score)

    cvss_v3 = vulnerability.get("cvssv3")

    if cvss_v3:
        score = cvss_v3.get("baseScore")

        if score is not None:
            return float(score)

    cvss_v2 = vulnerability.get("cvssv2")

    if cvss_v2:
        score = cvss_v2.get("score")

        if score is not None:
            return float(score)

    return None