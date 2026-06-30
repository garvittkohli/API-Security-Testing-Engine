"""API4:2023 — Unrestricted Resource Consumption (rate limiting)."""


from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_AUTH_PATHS = ("/login", "/auth", "/token", "/signin", "/signup", "/register", "/password")
_BURST_DEFAULT = 25
_BURST_AUTH = 40


class RateLimitCheck(BaseCheck):
    name = "rate_limit"
    description = "Unrestricted Resource Consumption — missing rate limiting"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            is_auth_ep = any(pat in ep.path.lower() for pat in _AUTH_PATHS)
            burst_count = _BURST_AUTH if is_auth_ep else _BURST_DEFAULT
            sev = Severity.HIGH if is_auth_ep else Severity.MEDIUM
            cvss = 7.5 if is_auth_ep else 5.3

            responses = client.burst_requests(ep.method, ep.path, count=burst_count)
            valid = [r for r in responses if r is not None]

            if not valid:
                continue

            status_codes = [r.status_code for r in valid]
            has_429 = 429 in status_codes
            has_503 = 503 in status_codes  # Some implementations return 503 when overwhelmed

            if has_429 or has_503:
                continue  # Rate limiting is in place — no finding

            success_count = sum(1 for s in status_codes if s < 400)
            success_rate = success_count / len(valid)

            if success_rate >= 0.9:
                findings.append(
                    Finding(
                        title=f"No Rate Limiting: {ep.path}",
                        severity=sev,
                        owasp_category=OWASPCategory.API4_RESOURCE_CONSUMPTION,
                        endpoint=ep.path,
                        method=ep.method,
                        description=(
                            f"{burst_count} rapid requests were sent to {ep.path} "
                            f"and {success_count} succeeded without triggering a 429 "
                            f"or 503 response. "
                            + (
                                "This endpoint appears to be an authentication endpoint, "
                                "making the absence of rate limiting a critical enabler "
                                "for credential stuffing and brute force attacks."
                                if is_auth_ep
                                else "Without rate limiting, this endpoint can be abused to "
                                "exhaust backend resources or perform enumeration attacks."
                            )
                        ),
                        remediation=(
                            "Implement rate limiting per IP and per user account. "
                            "Authentication endpoints should be limited to 5–10 requests "
                            "per minute. Return HTTP 429 with a Retry-After header when "
                            "limits are exceeded. For critical paths, add progressive "
                            "delays and CAPTCHA after repeated failures. Consider API "
                            "gateway-level rate limiting (AWS API Gateway, Kong, Nginx) "
                            "as a defence-in-depth measure."
                        ),
                        evidence=Evidence(
                            request_method=ep.method,
                            request_url=client._build_url(ep.path),
                            request_headers=dict(client.session.headers),
                            request_body=None,
                            response_status=status_codes[-1],
                            response_headers=dict(valid[-1].headers) if valid else {},
                            response_body_snippet=f"Status codes from {burst_count} requests: "
                            + str(sorted(set(status_codes))),
                            notes=f"{success_count}/{len(valid)} requests succeeded; no 429 observed",
                        ),
                        cvss_score=cvss,
                    )
                )

            if len(findings) >= self.config.max_findings_per_check:
                return findings

        return findings
