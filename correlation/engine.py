from collections import defaultdict

from models.correlated_issue import CorrelatedIssue


SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "INFO": 1,
    "WARNING": 2,
    "LOW": 3,
    "MEDIUM": 4,
    "HIGH": 5,
    "CRITICAL": 6,
}


def normalize_value(value):
    if value is None:
        return ""

    return str(value).strip().lower()


def correlation_key(finding):
    """
    Generate a deterministic correlation key.

    Priority:
    1. CVE
    2. Rule + affected asset
    3. Individual finding
    """

    # ---------------------------------------------------------
    # Rule 1: Same CVE
    # ---------------------------------------------------------

    cve = normalize_value(finding.get("cve"))

    if cve:
        return (
            "CVE",
            cve
        )

    # ---------------------------------------------------------
    # Rule 2: Same rule + affected asset
    # ---------------------------------------------------------

    rule_id = normalize_value(
        finding.get("rule_id")
    )

    file = normalize_value(
        finding.get("file")
    )

    component = normalize_value(
        finding.get("component")
    )

    endpoint = normalize_value(
        finding.get("endpoint")
    )

    affected_asset = (
        file
        or component
        or endpoint
    )

    if rule_id and affected_asset:
        return (
            "RULE_ASSET",
            rule_id,
            affected_asset
        )

    # ---------------------------------------------------------
    # Rule 3: Keep finding independent
    # ---------------------------------------------------------

    return (
        "FINDING",
        finding.get("id")
    )


def highest_severity(findings):
    return max(
        (
            finding.get("severity", "UNKNOWN")
            for finding in findings
        ),
        key=lambda severity: SEVERITY_ORDER.get(
            str(severity).upper(),
            0
        )
    )


def correlate_findings(findings):
    groups = defaultdict(list)

    # ---------------------------------------------------------
    # Group findings
    # ---------------------------------------------------------

    for finding in findings:
        key = correlation_key(finding)

        groups[key].append(finding)

    # ---------------------------------------------------------
    # Convert groups into MESB issues
    # ---------------------------------------------------------

    correlated_issues = []

    for index, (_, group) in enumerate(
        groups.items(),
        start=1
    ):
        first = group[0]

        issue = CorrelatedIssue(
            id=f"MESB-ISSUE-{index:03}",

            title=first.get(
                "title",
                "Security Issue"
            ),

            category=first.get(
                "category",
                "UNKNOWN"
            ),

            severity=highest_severity(group),

            finding_ids=[
                finding.get("id")
                for finding in group
            ],

            sources=sorted(
                {
                    finding.get("source")
                    for finding in group
                    if finding.get("source")
                }
            ),

            occurrences=len(group),

            file=first.get("file"),
            component=first.get("component"),
            endpoint=first.get("endpoint"),

            cve=first.get("cve"),
            cwe=first.get("cwe"),
            rule_id=first.get("rule_id")
        )

        correlated_issues.append(issue)

    return correlated_issues