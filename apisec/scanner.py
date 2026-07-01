"""Scan orchestrator."""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from apisec.checks import CHECK_REGISTRY
from apisec.config import ScanConfig
from apisec.findings import Finding, severity_counts, sort_by_severity
from apisec.http_client import APIClient
from apisec.payload_engine import PayloadEngine

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str
    duration_seconds: float
    finding_count: int
    error: str | None = None


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    check_results: list[CheckResult] = field(default_factory=list)
    endpoints_scanned: int = 0

    def to_dict(self) -> dict:
        sorted_findings = sort_by_severity(self.findings)
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "endpoints_scanned": self.endpoints_scanned,
            "summary": severity_counts(self.findings),
            "total_findings": len(self.findings),
            "check_results": [
                {
                    "name": c.name,
                    "duration_seconds": round(c.duration_seconds, 2),
                    "finding_count": c.finding_count,
                    "error": c.error,
                }
                for c in self.check_results
            ],
            "findings": [f.to_dict() for f in sorted_findings],
        }


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.client = APIClient(
            base_url=config.base_url,
            auth_headers=config.auth_headers,
            custom_headers=config.custom_headers,
            rate_limit_delay=config.rate_limit_delay,
            timeout=config.request_timeout,
            follow_redirects=config.follow_redirects,
            verify_ssl=config.verify_ssl,
        )
        self.payload_engine = PayloadEngine()

    def run(self, check_names: list[str] | None = None) -> ScanResult:
        check_names = check_names or self.config.scan_checks
        started = datetime.now(timezone.utc)
        start_perf = time.monotonic()

        findings: list[Finding] = []
        check_results: list[CheckResult] = []

        for name in check_names:
            check_cls = CHECK_REGISTRY.get(name)
            if check_cls is None:
                logger.warning("Unknown check '%s' — skipping", name)
                continue

            check = check_cls(self.config, self.payload_engine)
            check_start = time.monotonic()
            error: str | None = None

            try:
                logger.info("Running check: %s", name)
                check_findings = check.run(self.client, self.config.endpoints)
            except Exception as exc:  # noqa: BLE001 — checks must never crash the scan
                logger.exception("Check '%s' raised an exception", name)
                findings = []
                error = str(exc)

            duration = time.monotonic() - check_start
            findings.extend(check_findings)
            check_results.append(
                CheckResult(
                    name=name,
                    duration_seconds=duration,
                    finding_count=len(check_findings),
                    error=error,
                )
            )

        finished = datetime.now(timezone.utc)
        total_duration = time.monotonic() - start_perf

        return ScanResult(
            target=self.config.base_url,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_seconds=total_duration,
            findings=findings,
            check_results=check_results,
            endpoints_scanned=len(self.config.endpoints),
        )
