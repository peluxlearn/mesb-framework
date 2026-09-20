from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class CorrelatedIssue:
    id: str
    title: str
    category: str

    severity: str

    finding_ids: List[str]
    sources: List[str]

    occurrences: int

    file: Optional[str] = None
    component: Optional[str] = None
    endpoint: Optional[str] = None

    cve: Optional[str] = None
    cwe: Optional[str] = None
    rule_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)