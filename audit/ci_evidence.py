import argparse
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from audit.integrity import sha256_file
from audit.sarif import create_sarif_document


SCANNERS = {
    "semgrep": "reports/semgrep-report",
    "dependency-check": "reports/dependency-check-report",
    "gitleaks": "reports/gitleaks-report",
    "grype": "reports/grype-report",
    "checkov": "reports/checkov-report",
    "zap": "reports/zap-report",
    "sbom": "reports/sbom-report",
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Create MESB CI evidence pack."
    )

    parser.add_argument(
        "--reports",
        default="reports"
    )

    parser.add_argument(
        "--mesb-output",
        default="mesb-output"
    )

    parser.add_argument(
        "--output",
        default="mesb-evidence"
    )

    return parser.parse_args()


def copy_directory_if_exists(
    source: Path,
    destination: Path
):
    if not source.exists():
        return

    shutil.copytree(
        source,
        destination,
        dirs_exist_ok=True
    )


def load_json(path: Path):
    if not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return None


def count_json_items(data):
    if data is None:
        return None

    if isinstance(data, list):
        return len(data)

    if isinstance(data, dict):
        for key in (
            "findings",
            "items",
            "results",
            "correlated_issues"
        ):
            value = data.get(key)

            if isinstance(value, list):
                return len(value)

    return None


def create_mesb_sarif(
    normalized_path: Path,
    output_path: Path,
    execution_id: str
):
    data = load_json(
        normalized_path
    )

    results = []

    findings = []

    if isinstance(data, list):
        findings = data

    elif isinstance(data, dict):
        for key in (
            "findings",
            "items",
            "results"
        ):
            if isinstance(
                data.get(key),
                list
            ):
                findings = data[key]
                break

    for index, finding in enumerate(
        findings,
        start=1
    ):
        if not isinstance(
            finding,
            dict
        ):
            continue

        rule_id = (
            finding.get("id")
            or finding.get("rule_id")
            or finding.get("ruleId")
            or finding.get("vulnerability_id")
            or f"MESB-{index:04d}"
        )

        title = (
            finding.get("title")
            or finding.get("name")
            or finding.get("message")
            or finding.get("description")
            or "MESB security finding"
        )

        severity = (
            finding.get("severity")
            or "LOW"
        )

        results.append({
            "rule_id": str(rule_id),
            "message": str(title),
            "severity": str(severity),
            "properties": {
                "mesbFinding": finding
            }
        })

    document = create_sarif_document(
        tool_name="MESB Security Analysis",
        tool_version="1.0.0",
        results=results,
        properties={
            "executionId":
                execution_id,

            "source":
                "MESB normalized findings"
        }
    )

    output_path.write_text(
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def write_checksums(
    evidence_root: Path
):
    checksum_path = (
        evidence_root
        / "checksums.sha256"
    )

    lines = []

    files = sorted(
        path
        for path
        in evidence_root.rglob("*")
        if (
            path.is_file()
            and
            path.name
            != "checksums.sha256"
        )
    )

    for path in files:

        relative = (
            path.relative_to(
                evidence_root
            )
        )

        lines.append(
            f"{sha256_file(path)}  "
            f"{relative.as_posix()}"
        )

    checksum_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )


def main():

    args = parse_arguments()

    reports_root = Path(
        args.reports
    )

    mesb_output = Path(
        args.mesb_output
    )

    evidence_root = Path(
        args.output
    )

    evidence_root.mkdir(
        parents=True,
        exist_ok=True
    )

    # ----------------------------------
    # GitHub execution context
    # ----------------------------------

    run_id = os.getenv(
        "GITHUB_RUN_ID",
        "local"
    )

    run_attempt = os.getenv(
        "GITHUB_RUN_ATTEMPT",
        "1"
    )

    commit = os.getenv(
        "GITHUB_SHA"
    )

    branch = os.getenv(
        "GITHUB_REF_NAME"
    )

    event_name = os.getenv(
        "GITHUB_EVENT_NAME"
    )

    repository = os.getenv(
        "GITHUB_REPOSITORY"
    )

    workflow = os.getenv(
        "GITHUB_WORKFLOW"
    )

    execution_id = (
        f"MESB-CI-{run_id}-"
        f"{run_attempt}"
    )

    # ----------------------------------
    # Raw scanner evidence
    # ----------------------------------

    scanners_directory = (
        evidence_root
        / "scanners"
    )

    scanners_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    scanner_summary = {}

    for scanner, relative_path in (
        SCANNERS.items()
    ):

        source = Path(
            relative_path
        )

        destination = (
            scanners_directory
            / scanner
        )

        if source.exists():

            copy_directory_if_exists(
                source,
                destination
            )

            scanner_summary[
                scanner
            ] = {
                "executed": True,
                "evidencePresent": True
            }

        else:

            scanner_summary[
                scanner
            ] = {
                "executed": False,
                "evidencePresent": False
            }

    # ----------------------------------
    # MESB processed outputs
    # ----------------------------------

    processed_directory = (
        evidence_root
        / "processed"
    )

    processed_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    normalized_source = (
        mesb_output
        / "findings_normalized.json"
    )

    correlated_source = (
        mesb_output
        / "correlated_findings.json"
    )

    normalized_target = (
        processed_directory
        / "findings_normalized.json"
    )

    correlated_target = (
        processed_directory
        / "correlated_findings.json"
    )

    if normalized_source.exists():
        shutil.copy2(
            normalized_source,
            normalized_target
        )

    if correlated_source.exists():
        shutil.copy2(
            correlated_source,
            correlated_target
        )

    normalized_data = load_json(
        normalized_source
    )

    correlated_data = load_json(
        correlated_source
    )

    # ----------------------------------
    # SARIF projection
    # ----------------------------------

    sarif_path = (
        evidence_root
        / "mesb-results.sarif"
    )

    create_mesb_sarif(
        normalized_source,
        sarif_path,
        execution_id
    )

    # ----------------------------------
    # Manifest
    # ----------------------------------

    manifest = {
        "schema_version": "1.0.0",

        "execution_id":
            execution_id,

        "execution_type":
            "CI_SECURITY_ANALYSIS",

        "timestamp_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "project": {
            "name":
                "mesb-bank",

            "repository":
                repository,

            "git_commit":
                commit,

            "git_branch":
                branch
        },

        "ci": {
            "provider":
                "GitHub Actions",

            "workflow":
                workflow,

            "run_id":
                run_id,

            "run_attempt":
                run_attempt,

            "event":
                event_name
        },

        "engine": {
            "component":
                "MESB Framework",

            "component_version":
                "0.1.0",

            "ai_analysis_executed":
                False
        },

        "configuration": {
            "normalization":
                True,

            "correlation":
                True,

            "sarif_projection":
                True,

            "security_analysis_agent":
                False,

            "quality_gate":
                False
        },

        "scanners":
            scanner_summary,

        "outputs": {
            "normalized_findings":
                (
                    "processed/"
                    "findings_normalized.json"
                ),

            "correlated_findings":
                (
                    "processed/"
                    "correlated_findings.json"
                ),

            "sarif":
                "mesb-results.sarif"
        },

        "result_summary": {
            "normalized_findings":
                count_json_items(
                    normalized_data
                ),

            "correlated_issues":
                count_json_items(
                    correlated_data
                )
        }
    }

    manifest_path = (
        evidence_root
        / "execution-manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    # ----------------------------------
    # Integrity
    # ----------------------------------

    write_checksums(
        evidence_root
    )

    print(
        json.dumps({
            "success": True,
            "executionId":
                execution_id,
            "evidenceDirectory":
                str(
                    evidence_root
                ),
            "gitCommit":
                commit,
            "gitBranch":
                branch
        })
    )


if __name__ == "__main__":
    main()