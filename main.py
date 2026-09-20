import argparse
import json
import os
import sys

from normalizers import (
    normalize_semgrep,
    normalize_dependency_check,
    normalize_gitleaks,
    normalize_grype,
    normalize_checkov,
    normalize_zap
)

from correlation.engine import correlate_findings

def main():

    parser = argparse.ArgumentParser(
        description="MESB Security Findings Normalizer"
    )

    parser.add_argument(
        "--semgrep",
        help="Path to Semgrep JSON report"
    )

    parser.add_argument(
        "--sca",
        help="Path to OWASP Dependency-Check JSON report"
    )

    parser.add_argument(
        "--gitleaks",
        help="Path to Gitleaks JSON report"
    )

    parser.add_argument(
        "--grype",
        help="Path to Grype JSON report"
    )

    parser.add_argument(
        "--checkov",
        help="Path to Checkov JSON report"
    )

    parser.add_argument(
        "--zap",
        help="Path to OWASP ZAP JSON report"
    )

    parser.add_argument(
        "--zap-api",
        help="Path to OWASP ZAP API Scan JSON report"
    )

    parser.add_argument(
        "--correlated-output",
        default="output/correlated_findings.json",
        help="Output path for correlated MESB security issues"
    )

    parser.add_argument(
        "--output",
        default="output/findings_normalized.json",
        help="Output path for normalized findings"
    )

    args = parser.parse_args()

    findings = []

    # -------------------------
    # SAST - Semgrep
    # -------------------------

    if args.semgrep:

        if not os.path.exists(args.semgrep):
            print(
                f"[ERROR] Semgrep report not found: "
                f"{args.semgrep}"
            )
            sys.exit(1)

        semgrep_findings = normalize_semgrep(
            args.semgrep
        )

        findings.extend(
            semgrep_findings
        )

        print(
            f"[MESB] Semgrep findings normalized: "
            f"{len(semgrep_findings)}"
        )

    # -------------------------
    # SCA - Dependency-Check
    # -------------------------

    if args.sca:

        if not os.path.exists(args.sca):
            print(
                f"[ERROR] Dependency-Check report not found: "
                f"{args.sca}"
            )
            sys.exit(1)

        sca_findings = normalize_dependency_check(
            args.sca
        )

        findings.extend(
            sca_findings
        )

        print(
            f"[MESB] Dependency-Check findings normalized: "
            f"{len(sca_findings)}"
        )

    # -------------------------
    # Secrets - Gitleaks
    # -------------------------

    if args.gitleaks:

        if not os.path.exists(args.gitleaks):
            print(
                f"[ERROR] Gitleaks report not found: "
                f"{args.gitleaks}"
            )
            sys.exit(1)

        gitleaks_findings = normalize_gitleaks(
            args.gitleaks
        )

        findings.extend(
            gitleaks_findings
        )

        print(
            f"[MESB] Gitleaks findings normalized: "
            f"{len(gitleaks_findings)}"
        )

    # -------------------------
    # Container - Grype
    # -------------------------

    if args.grype:

        if not os.path.exists(args.grype):
            print(
                f"[ERROR] Grype report not found: "
                f"{args.grype}"
            )
            sys.exit(1)

        grype_findings = normalize_grype(
            args.grype
        )

        findings.extend(
            grype_findings
        )

        print(
            f"[MESB] Grype findings normalized: "
            f"{len(grype_findings)}"
        )

    # -------------------------
    # IaC - Checkov
    # -------------------------

    if args.checkov:

        if not os.path.exists(args.checkov):
            print(
                f"[ERROR] Checkov report not found: "
                f"{args.checkov}"
            )
            sys.exit(1)

        checkov_findings = normalize_checkov(
            args.checkov
        )

        findings.extend(
            checkov_findings
        )

        print(
            f"[MESB] Checkov findings normalized: "
            f"{len(checkov_findings)}"
        )


    # -------------------------
    # DAST - OWASP ZAP
    # -------------------------

    if args.zap:

        if not os.path.exists(args.zap):
            print(
                f"[ERROR] ZAP report not found: "
                f"{args.zap}"
            )
            sys.exit(1)

        zap_findings = normalize_zap(
            args.zap
        )

        findings.extend(
            zap_findings
        )

        print(
            f"[MESB] ZAP findings normalized: "
            f"{len(zap_findings)}"
        )

    if args.zap_api and os.path.exists(args.zap_api):
        print(f"[MESB] Normalizing ZAP API report: {args.zap_api}")
        zap_api_findings = normalize_zap(args.zap_api)

        # Rename IDs so they do not collide with the baseline ZAP findings.
        for index, finding in enumerate(zap_api_findings, start=1):
            finding.id = f"DAST-API-{index:03}"

        findings.extend(zap_api_findings)

        print(f"[MESB] ZAP API findings: {len(zap_api_findings)}")

    # -------------------------
    # MESB Output
    # -------------------------

    if not findings:
        print(
            "[WARNING] No security findings were "
            "provided to MESB"
        )

    output = {
        "framework": "MESB",
        "version": "0.1.0",
        "total_findings": len(findings),
        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    output_dir = os.path.dirname(
        args.output
    )

    if output_dir:
        os.makedirs(
            output_dir,
            exist_ok=True
        )

    with open(
        args.output,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    # -------------------------
    # MESB Correlation
    # -------------------------

    print()
    print("[MESB] Running correlation engine...")

    findings_dict = [
        finding.to_dict()
        for finding in findings
    ]

    correlated_issues = correlate_findings(
        findings_dict
    )

    correlated_output = {
        "framework": "MESB",
        "version": "0.1.0",
        "total_findings": len(findings),
        "total_correlated_issues": len(correlated_issues),
        "issues": [
            issue.to_dict()
            for issue in correlated_issues
        ]
    }

    correlated_output_dir = os.path.dirname(
        args.correlated_output
    )

    if correlated_output_dir:
        os.makedirs(
            correlated_output_dir,
            exist_ok=True
        )

    with open(
        args.correlated_output,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            correlated_output,
            file,
            indent=2,
            ensure_ascii=False
        )

    # -------------------------
    # Correlation Metrics
    # -------------------------

    total_findings = len(findings)
    total_issues = len(correlated_issues)

    correlated_groups = [
        issue
        for issue in correlated_issues
        if issue.occurrences > 1
    ]

    findings_in_correlated_groups = sum(
        issue.occurrences
        for issue in correlated_groups
    )

    if total_findings > 0:
        reduction_percentage = (
            (total_findings - total_issues)
            / total_findings
        ) * 100
    else:
        reduction_percentage = 0.0

    print()
    print(
        f"[MESB] Correlated issues: "
        f"{total_issues}"
    )

    print(
        f"[MESB] Multi-finding correlation groups: "
        f"{len(correlated_groups)}"
    )

    print(
        f"[MESB] Findings in correlation groups: "
        f"{findings_in_correlated_groups}"
    )

    print(
        f"[MESB] Correlation reduction: "
        f"{reduction_percentage:.2f}%"
    )

    print(
        f"[MESB] Correlated output: "
        f"{args.correlated_output}"
    )

    print()
    print("[MESB] Processing completed")

    print(
        f"[MESB] Normalized findings: "
        f"{len(findings)}"
    )

    print(
        f"[MESB] Correlated issues: "
        f"{len(correlated_issues)}"
    )

    print(
        f"[MESB] Normalized output: "
        f"{args.output}"
    )

    print(
        f"[MESB] Correlated output: "
        f"{args.correlated_output}"
    )


if __name__ == "__main__":
    main()