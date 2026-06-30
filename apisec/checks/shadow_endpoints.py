"""API9:2023 — Improper Inventory Management (shadow endpoint discovery + legacy version probing)."""


import re

from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_HIGH_SENSITIVITY_MARKERS = ("admin", "internal", "debug", "actuator", "env", "config", "dump", "backup")
_VERSION_PATTERN = re.compile(r"/v(\d+)/")


class ShadowEndpointCheck(BaseCheck):
    name = "shadow_endpoints"
    description = "Improper Inventory Management — shadow, debug, and legacy endpoints"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []
        probed: set[str] = set()

        # --- Common shadow paths ---
        for path in self.pe.shadow_endpoint_paths():
            if self._is_excluded(path) or path in probed:
                continue
            probed.add(path)

            resp = client.get(path)
            if resp is None:
                continue

            if resp.status_code in (200, 201, 204):
                sensitive = any(m in path.lower() for m in _HIGH_SENSITIVITY_MARKERS)
                sev = Severity.CRITICAL if sensitive else Severity.HIGH

                findings.append(
                    Finding(
                        title=f"Shadow Endpoint Exposed: {path}",
                        severity=sev,
                        owasp_category=OWASPCategory.API9_INVENTORY,
                        endpoint=path,
                        method="GET",
                        description=(
                            f"The undocumented path {path} returned HTTP {resp.status_code}. "
                            f"This endpoint is reachable but does not appear in the configured "
                            f"API inventory, suggesting it is either an internal/debug route "
                            f"that was accidentally exposed, or a documentation gap that means "
                            f"it isn't receiving the same security review as documented "
                            f"endpoints."
                        ),
                        remediation=(
                            "Maintain a single source of truth API inventory (OpenAPI spec) and "
                            "enforce that the API gateway only routes requests matching that "
                            "spec — return 404 for anything else. Remove debug/actuator "
                            "endpoints from production builds entirely. Audit all deployed "
                            "routes quarterly against the documented inventory."
                        ),
                        evidence=Evidence(
                            request_method="GET",
                            request_url=client._build_url(path),
                            request_headers=dict(client.session.headers),
                            request_body=None,
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_snippet=client.safe_body_snippet(resp),
                            notes="Discovered via shadow-endpoint wordlist probe",
                        ),
                        cvss_score=9.1 if sensitive else 7.5,
                    )
                )

            elif resp.status_code in (401, 403):
                # Endpoint exists and is protected — informational, helps map attack surface
                findings.append(
                    Finding(
                        title=f"Undocumented Endpoint Discovered (protected): {path}",
                        severity=Severity.INFO,
                        owasp_category=OWASPCategory.API9_INVENTORY,
                        endpoint=path,
                        method="GET",
                        description=(
                            f"The undocumented path {path} returned HTTP {resp.status_code}, "
                            f"confirming it exists and is not in the documented inventory. "
                            f"It is currently protected by an authorization check, but its "
                            f"existence should be tracked in the API inventory and reviewed."
                        ),
                        remediation=(
                            "Add this endpoint to the official OpenAPI specification with "
                            "appropriate documentation, or remove it if it is dead code."
                        ),
                        evidence=Evidence(
                            request_method="GET",
                            request_url=client._build_url(path),
                            request_headers=dict(client.session.headers),
                            request_body=None,
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_snippet=client.safe_body_snippet(resp, 150),
                            notes="Exists but access-controlled",
                        ),
                        cvss_score=0.0,
                        confidence="MEDIUM",
                    )
                )

            if len(findings) >= self.config.max_findings_per_check:
                return findings

        # --- Legacy API version probing ---
        for ep in endpoints:
            match = _VERSION_PATTERN.search(ep.path)
            if not match:
                continue

            current_version = int(match.group(1))
            for probe_version in range(1, current_version):
                legacy_path = _VERSION_PATTERN.sub(f"/v{probe_version}/", ep.path, count=1)

                if legacy_path in probed or self._is_excluded(legacy_path):
                    continue
                probed.add(legacy_path)

                resp = client.request(ep.method, legacy_path)
                if resp is None:
                    continue

                if resp.status_code in (200, 201, 202):
                    findings.append(
                        Finding(
                            title=f"Legacy API Version Still Active: {legacy_path}",
                            severity=Severity.MEDIUM,
                            owasp_category=OWASPCategory.API9_INVENTORY,
                            endpoint=legacy_path,
                            method=ep.method,
                            description=(
                                f"The current API exposes {ep.path}, but the older version "
                                f"{legacy_path} also returned HTTP {resp.status_code}. Legacy "
                                f"API versions often lack security patches and fixes applied "
                                f"to the current version, creating an inconsistent security "
                                f"posture across the same logical resource."
                            ),
                            remediation=(
                                "Decommission old API versions on a published deprecation "
                                "timeline. If a legacy version must remain available for "
                                "backward compatibility, ensure all security patches are "
                                "backported and apply identical authorization logic."
                            ),
                            evidence=Evidence(
                                request_method=ep.method,
                                request_url=client._build_url(legacy_path),
                                request_headers=dict(client.session.headers),
                                request_body=None,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_snippet=client.safe_body_snippet(resp),
                                notes=f"Current version path: {ep.path}",
                            ),
                            cvss_score=5.3,
                        )
                    )

            if len(findings) >= self.config.max_findings_per_check:
                return findings

        return findings
