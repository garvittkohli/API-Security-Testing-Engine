"""YAML configuration loader with environment variable interpolation."""


import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class EndpointDef:
    """A single API endpoint to test against."""

    method: str
    path: str
    sample_params: dict[str, Any] = field(default_factory=dict)
    sample_body: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.method = self.method.upper()


@dataclass
class ScanConfig:
    base_url: str
    auth_headers: dict[str, str] = field(default_factory=dict)
    custom_headers: dict[str, str] = field(default_factory=dict)
    endpoints: list[EndpointDef] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    rate_limit_delay: float = 0.5
    request_timeout: int = 10
    follow_redirects: bool = True
    verify_ssl: bool = True
    max_findings_per_check: int = 20
    output_dir: str = "reports"
    scan_checks: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if not self.scan_checks:
            self.scan_checks = [
                "bola",
                "broken_auth",
                "mass_assignment",
                "rate_limit",
                "bfla",
                "ssrf",
                "injection",
                "misconfig",
                "shadow_endpoints",
            ]


def load_config(path: str | Path) -> ScanConfig:
    """Parse a YAML config file into a ScanConfig. Supports env var interpolation."""
    raw = Path(path).read_text()

    # Allow ${ENV_VAR} substitution so tokens stay out of the file
    for key, value in os.environ.items():
        raw = raw.replace(f"${{{key}}}", value)

    data = yaml.safe_load(raw)
    return _parse(data)


def _parse(data: dict) -> ScanConfig:
    auth_cfg = data.get("auth", {})
    auth_headers: dict[str, str] = {}

    if "bearer_token" in auth_cfg:
        auth_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"
    if "api_key" in auth_cfg:
        key_header = auth_cfg.get("api_key_header", "X-API-Key")
        auth_headers[key_header] = auth_cfg["api_key"]
    auth_headers.update(auth_cfg.get("extra_headers", {}))

    endpoints = [
        EndpointDef(
            method=ep.get("method", "GET"),
            path=ep["path"],
            sample_params=ep.get("sample_params", {}),
            sample_body=ep.get("sample_body", {}),
            tags=ep.get("tags", []),
        )
        for ep in data.get("endpoints", [])
    ]

    scan_cfg = data.get("scan", {})

    return ScanConfig(
        base_url=data["target"]["base_url"],
        auth_headers=auth_headers,
        custom_headers=data.get("headers", {}),
        endpoints=endpoints,
        excluded_paths=data.get("excluded_paths", []),
        rate_limit_delay=scan_cfg.get("rate_limit_delay", 0.5),
        request_timeout=scan_cfg.get("timeout", 10),
        follow_redirects=scan_cfg.get("follow_redirects", True),
        verify_ssl=scan_cfg.get("verify_ssl", True),
        max_findings_per_check=scan_cfg.get("max_findings_per_check", 20),
        output_dir=data.get("output", {}).get("dir", "reports"),
        scan_checks=scan_cfg.get("checks", []),
    )


def minimal_config(base_url: str, token: Optional[str] = None) -> ScanConfig:
    """Build a ScanConfig programmatically when no YAML file is available."""
    auth_headers = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"
    return ScanConfig(base_url=base_url, auth_headers=auth_headers)
