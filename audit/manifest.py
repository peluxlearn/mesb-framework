from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuditArtifact(BaseModel):
    name: str

    type: str

    path: Optional[str] = None

    sha256: Optional[str] = None


class AuditProject(BaseModel):
    name: str

    architecture_version: Optional[str] = None

    git_commit: Optional[str] = None

    git_branch: Optional[str] = None


class AuditEngine(BaseModel):
    component: str

    component_version: str = "1.0.0"

    provider: Optional[str] = None

    model: Optional[str] = None


class AuditRuleset(BaseModel):
    name: str

    version: str

    sha256: str

    snapshot_file: Optional[str] = None


class AuditManifest(BaseModel):
    schema_version: str = "1.0.0"

    execution_id: str

    execution_type: str

    timestamp_utc: str

    project: AuditProject

    engine: AuditEngine

    rulesets: List[AuditRuleset] = Field(
        default_factory=list
    )

    configuration: Dict[str, Any] = Field(
        default_factory=dict
    )

    inputs: List[AuditArtifact] = Field(
        default_factory=list
    )

    outputs: List[AuditArtifact] = Field(
        default_factory=list
    )

    result_summary: Dict[str, Any] = Field(
        default_factory=dict
    )

    parent_executions: List[str] = Field(
        default_factory=list
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict
    )