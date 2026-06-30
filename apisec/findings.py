"""Core finding data model — severity, OWASP category, evidence."""


import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "#ff2d55",
            "HIGH": "#ff6b35",
            "MEDIUM": "#ffd700",
            "LOW": "#30d158",
            "INFO": "#636366",
        }[self.value]

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


class OWASPCategory(str, Enum):
    API1_BOLA = "API1:2023 – Broken Object Level Authorization"
    API2_BROKEN_AUTH = "API2:2023 – Broken Authentication"
    API3_BOPLA = "API3:2023 – Broken Object Property Level Authorization"
    API4_RESOURCE_CONSUMPTION = "API4:2023 – Unrestricted Resource Consumption"
    API5_BFLA = "API5:2023 – Broken Function Level Authorization"
    API6_BUSINESS_FLOWS = "API6:2023 – Unrestricted Access to Sensitive Business Flows"
    API7_SSRF = "API7:2023 – Server Side Request Forgery"
    API8_MISCONFIG = "API8:2023 – Security Misconfiguration"
    API9_INVENTORY = "API9:2023 – Improper Inventory Management"
    API10_UNSAFE_CONSUMPTION = "API10:2023 – Unsafe Consumption of APIs"


@dataclass
class Evidence:
    """Captures the exact HTTP exchange that produced a finding."""

    request_method: str
    request_url: str
    request_headers: dict[str, str]
    request_body: Optional[Any]
    response_status: Optional[int]
    response_headers: Optional[dict[str, str]]
    response_body_snippet: Optional[str]
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body_snippet": self.response_body_snippet,
            "notes": self.notes,
        }

    @classmethod
    def synthetic(
        cls,
        method: str,
        url: str,
        status: int,
        body_snippet: str,
        notes: str = "",
    ) -> "Evidence":
        return cls(
            request_method=method,
            request_url=url,
            request_headers={"Authorization": "Bearer <token>", "Content-Type": "application/json"},
            request_body=None,
            response_status=status,
            response_headers={"Content-Type": "application/json"},
            response_body_snippet=body_snippet,
            notes=notes,
        )


@dataclass
class Finding:
    """A single confirmed or suspected vulnerability found during a scan."""

    title: str
    severity: Severity
    owasp_category: OWASPCategory
    endpoint: str
    method: str
    description: str
    remediation: str
    evidence: Evidence
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    cvss_score: Optional[float] = None
    confidence: str = "HIGH"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence.to_dict(),
            "timestamp": self.timestamp,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
        }


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.severity.order)
