import json
import shutil
import uuid

from datetime import (
    datetime,
    timezone
)

from pathlib import Path
from typing import Any, Dict, List, Optional

from audit.integrity import (
    sha256_file,
    sha256_text
)

from audit.manifest import (
    AuditArtifact,
    AuditEngine,
    AuditManifest,
    AuditProject,
    AuditRuleset
)


class AuditService:

    def __init__(
        self,
        audit_root: str | Path
    ):

        self.audit_root = Path(
            audit_root
        )

        self.audit_root.mkdir(
            parents=True,
            exist_ok=True
        )


    def create_execution_id(
        self,
        execution_type: str
    ) -> str:

        timestamp = (
            datetime.now(
                timezone.utc
            )
            .strftime(
                "%Y%m%dT%H%M%SZ"
            )
        )

        short_uuid = (
            uuid.uuid4()
            .hex[:8]
            .upper()
        )

        normalized_type = (
            execution_type
            .upper()
            .replace(
                " ",
                "_"
            )
        )

        return (
            f"MESB-{normalized_type}-"
            f"{timestamp}-{short_uuid}"
        )


    def create_execution_directory(
        self,
        execution_type: str,
        execution_id: str
    ) -> Path:

        directory = (
            self.audit_root
            / execution_type.lower()
            / execution_id
        )

        directory.mkdir(
            parents=True,
            exist_ok=False
        )

        return directory


    def snapshot_file(
        self,
        source: str | Path,
        destination_directory:
            str | Path,
        destination_name:
            Optional[str] = None
    ) -> AuditArtifact:

        source_path = Path(
            source
        )

        destination_directory = Path(
            destination_directory
        )

        destination_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        target_name = (
            destination_name
            or source_path.name
        )

        target_path = (
            destination_directory
            / target_name
        )

        shutil.copy2(
            source_path,
            target_path
        )

        return AuditArtifact(
            name=target_name,
            type="FILE",
            path=str(
                target_path
            ),
            sha256=sha256_file(
                target_path
            )
        )


    def snapshot_text(
        self,
        name: str,
        content: str,
        destination_directory:
            str | Path,
        artifact_type:
            str = "TEXT"
    ) -> AuditArtifact:

        destination_directory = Path(
            destination_directory
        )

        destination_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        target_path = (
            destination_directory
            / name
        )

        target_path.write_text(
            content,
            encoding="utf-8"
        )

        return AuditArtifact(
            name=name,
            type=artifact_type,
            path=str(
                target_path
            ),
            sha256=sha256_text(
                content
            )
        )


    def write_json(
        self,
        destination: str | Path,
        data: Any
    ) -> AuditArtifact:

        destination = Path(
            destination
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        destination.write_text(
            json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        return AuditArtifact(
            name=destination.name,
            type="JSON",
            path=str(
                destination
            ),
            sha256=sha256_file(
                destination
            )
        )


    def create_ruleset_snapshot(
        self,
        name: str,
        version: str,
        content: str,
        execution_directory:
            str | Path
    ) -> AuditRuleset:

        rules_directory = (
            Path(
                execution_directory
            )
            / "rules"
        )

        safe_name = (
            name.lower()
            .replace(
                " ",
                "-"
            )
        )

        filename = (
            f"{safe_name}.txt"
        )

        artifact = (
            self.snapshot_text(
                name=filename,
                content=content,
                destination_directory=
                    rules_directory,
                artifact_type=
                    "RULESET"
            )
        )

        return AuditRuleset(
            name=name,
            version=version,
            sha256=artifact.sha256
            or "",
            snapshot_file=str(
                Path("rules")
                / filename
            )
        )


    def create_manifest(
        self,
        *,
        execution_id: str,
        execution_type: str,
        project_name: str,
        component: str,
        component_version:
            str = "1.0.0",
        architecture_version:
            Optional[str] = None,
        git_commit:
            Optional[str] = None,
        git_branch:
            Optional[str] = None,
        provider:
            Optional[str] = None,
        model:
            Optional[str] = None,
        rulesets:
            Optional[
                List[AuditRuleset]
            ] = None,
        configuration:
            Optional[
                Dict[str, Any]
            ] = None,
        inputs:
            Optional[
                List[AuditArtifact]
            ] = None,
        outputs:
            Optional[
                List[AuditArtifact]
            ] = None,
        result_summary:
            Optional[
                Dict[str, Any]
            ] = None,
        parent_executions:
            Optional[List[str]] = None,
        metadata:
            Optional[
                Dict[str, Any]
            ] = None
    ) -> AuditManifest:

        return AuditManifest(

            execution_id=
                execution_id,

            execution_type=
                execution_type,

            timestamp_utc=
                datetime.now(
                    timezone.utc
                ).isoformat(),

            project=AuditProject(
                name=project_name,
                architecture_version=
                    architecture_version,
                git_commit=
                    git_commit,
                git_branch=
                    git_branch
            ),

            engine=AuditEngine(
                component=component,
                component_version=
                    component_version,
                provider=provider,
                model=model
            ),

            rulesets=
                rulesets or [],

            configuration=
                configuration or {},

            inputs=
                inputs or [],

            outputs=
                outputs or [],

            result_summary=
                result_summary or {},

            parent_executions=
                parent_executions or [],

            metadata=
                metadata or {}
        )


    def save_manifest(
        self,
        manifest: AuditManifest,
        execution_directory:
            str | Path
    ) -> Path:

        path = (
            Path(
                execution_directory
            )
            / "execution-manifest.json"
        )

        path.write_text(
            json.dumps(
                manifest.model_dump(
                    mode="json"
                ),
                indent=2,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        return path