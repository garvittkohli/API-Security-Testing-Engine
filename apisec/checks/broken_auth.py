"""API2:2023 — Broken Authentication."""


from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient


class BrokenAuthCheck(BaseCheck):
    name = "broken_auth"
    description = "Broken Authentication — missing/bypassed credential checks"

    _SEVERITY_MAP = {
        "No Authorization header": (Severity.CRITICAL, 9.1),
        "Empty Bearer token": (Severity.CRITICAL, 9.1),
        "Null string token": (Severity.HIGH, 7.5),
        "Algorithm=none JWT": (Severity.CRITICAL, 9.8),
        "HS256 weak secret JWT": (Severity.HIGH, 8.8),
    }

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []
        payloads = self.pe.auth_bypass_payloads()

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            for p in payloads:
                if p.name == "No Authorization header":
                    resp = client.unauthenticated_request(ep.method, ep.path)
                    headers_used: dict = {"Authorization": "<none>"}
                else:
                    override = p.payload if isinstance(p.payload, dict) else {}
                    resp = client.request(ep.method, ep.path, override_headers=override)
                    headers_used = override

                if resp is None:
                    continue

                if resp.status_code in (200, 201, 202, 206):
                    body = client.safe_body_snippet(resp)
                    sev, cvss = self._SEVERITY_MAP.get(p.name, (Severity.HIGH, 7.0))

                    findings.append(
                        Finding(
                            title=f"Broken Auth ({p.name}): {ep.path}",
                            severity=sev,
                            owasp_category=OWASPCategory.API2_BROKEN_AUTH,
                            endpoint=ep.path,
                            method=ep.method,
                            description=(
                                f"The endpoint returned HTTP {resp.status_code} when accessed "
                                f"using the auth bypass technique: '{p.name}'. "
                                f"This suggests the endpoint is not enforcing authentication "
                                f"properly or is accepting malformed/missing credentials."
                            ),
                            remediation=(
                                "Require a valid, unexpired token on every protected endpoint. "
                                "Validate the JWT algorithm server-side — reject any token with "
                                "alg=none. Use a strong, randomly generated signing secret "
                                "(≥256 bits) stored in a secret manager, not in source code. "
                                "Return HTTP 401 for missing credentials, 403 for insufficient "
                                "permissions."
                            ),
                            evidence=Evidence(
                                request_method=ep.method,
                                request_url=client._build_url(ep.path),
                                request_headers=headers_used,
                                request_body=None,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_snippet=body,
                                notes=p.description,
                            ),
                            cvss_score=cvss,
                        )
                    )

                if len(findings) >= self.config.max_findings_per_check:
                    return findings

        return findings
