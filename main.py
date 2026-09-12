import argparse
import json
import os
import sys

from normalizers import normalize_semgrep


def main():
    parser = argparse.ArgumentParser(
        description="MESB Security Findings Normalizer"
    )

    parser.add_argument(
        "--semgrep",
        help="Path to Semgrep JSON report"
    )

    parser.add_argument(
        "--output",
        default="output/findings_normalized.json",
        help="Output path for normalized findings"
    )

    args = parser.parse_args()

    findings = []

    if args.semgrep:
        if not os.path.exists(args.semgrep):
            print(f"[ERROR] Semgrep report not found: {args.semgrep}")
            sys.exit(1)

        semgrep_findings = normalize_semgrep(args.semgrep)

        findings.extend(semgrep_findings)

        print(
            f"[MESB] Semgrep findings normalized: "
            f"{len(semgrep_findings)}"
        )

    if not findings:
        print("[WARNING] No findings were provided to MESB")

    output = {
        "framework": "MESB",
        "version": "0.1.0",
        "total_findings": len(findings),
        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    output_dir = os.path.dirname(args.output)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

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

    print(
        f"[MESB] Normalization completed"
    )

    print(
        f"[MESB] Output: {args.output}"
    )


if __name__ == "__main__":
    main()