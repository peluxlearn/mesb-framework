from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class MesbFinding:
    id: str
    source: str
    category: str
    title: str
    description: str
    severity: str

    file: Optional[str] = None
    line: Optional[int] = None

    component: Optional[str] = None
    version: Optional[str] = None

    cve: Optional[str] = None
    cvss: Optional[float] = None

    endpoint: Optional[str] = None

    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None

    evidence: Optional[str] = None

    def to_dict(self):
        return asdict(self)