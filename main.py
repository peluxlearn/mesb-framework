import argparse
import json
import os
import sys

from normalizers import (
    normalize_semgrep,
    normalize_dependency_check,
    normalize_gitleaks
)


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

    print()
    print(
        f"[MESB] Total normalized findings: "
        f"{len(findings)}"
    )

    print(
        "[MESB] Normalization completed"
    )

    print(
        f"[MESB] Output: {args.output}"
    )


if __name__ == "__main__":
    main()