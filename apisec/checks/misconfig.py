"""API8:2023 — Security Misconfiguration (headers, CORS, verbose errors, banners)."""


from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_STACK_TRACE_MARKERS = [
    "Traceback (most recent call last)",
    "at java.",
    "System.Exception",
    "Microsoft.AspNetCore",
    "Stack trace:",
    "django.core",
    "rails",
    "Whoops\\Exception",
]


class MisconfigCheck(BaseCheck):
    name = "misconfig"
    description = "Security Misconfiguration — headers, CORS, verbose errors, banners"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []
        checked_global = False

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            resp = client.get(ep.path) if ep.method == "GET" else client.request(ep.method, ep.path)
            if resp is None:
                continue

            # --- Missing security headers (check once globally, report per first endpoint) ---
            if not checked_global:
                missing = [
                    h for h in self.pe.sensitive_headers_expected()
                    if h not in resp.headers
                ]
                if missing:
                    findings.append(
                        Finding(
                            title="Missing Security Headers",
                            severity=Severity.LOW,
                            owasp_category=OWASPCategory.API8_MISCONFIG,
                            endpoint=ep.path,
                            method=ep.method,
                            description=(
                                f"The following recommended security headers were not present "
                                f"in the response: {', '.join(missing)}. While individually "
                                f"low-severity, their absence weakens defence-in-depth against "
                                f"clickjacking, MIME-sniffing, and protocol downgrade attacks."
                            ),
                            remediation=(
                                "Add the missing headers at the API gateway or application "
                                "middleware level: Strict-Transport-Security "
                                "(max-age=31536000; includeSubDomains), X-Content-Type-Options: "
                                "nosniff, X-Frame-Options: DENY, Content-Security-Policy: "
                                "default-src 'none'."
                            ),
                            evidence=Evidence(
                                request_method=ep.method,
                                request_url=client._build_url(ep.path),
                                request_headers=dict(client.session.headers),
                                request_body=None,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_snippet=client.safe_body_snippet(resp, 200),
                                notes=f"Missing: {missing}",
                            ),
                            cvss_score=3.1,
                        )
                    )
                checked_global = True

            # --- Server banner disclosure ---
            server_header = resp.headers.get("Server", "")
            if any(c.isdigit() for c in server_header):
                findings.append(
                    Finding(
                        title=f"Server Version Disclosure: {server_header}",
                        severity=Severity.LOW,
                        owasp_category=OWASPCategory.API8_MISCONFIG,
                        endpoint=ep.path,
                        method=ep.method,
                        description=(
                            f"The Server header discloses version information: "
                            f"'{server_header}'. Attackers use this to identify known "
                            f"CVEs affecting the specific software version in use."
                        ),
                        remediation=(
                            "Suppress or genericize the Server header at the reverse proxy "
                            "(e.g. `server_tokens off;` in Nginx, "
                            "ServerTokens Prod in Apache)."
                        ),
                        evidence=Evidence(
                            request_method=ep.method,
                            request_url=client._build_url(ep.path),
                            request_headers=dict(client.session.headers),
                            request_body=None,
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body_snippet=client.safe_body_snippet(resp, 200),
                            notes=f"Server header: {server_header}",
                        ),
                        cvss_score=2.7,
                    )
                )

            # --- CORS misconfiguration ---
            for origin in self.pe.cors_origins_to_probe():
                cors_resp = client.request(
                    ep.method, ep.path, override_headers={"Origin": origin}
                )
                if cors_resp is None:
                    continue

                allow_origin = cors_resp.headers.get("Access-Control-Allow-Origin", "")
                allow_creds = cors_resp.headers.get("Access-Control-Allow-Credentials", "")

                if allow_origin == origin or allow_origin == "*":
                    sev = Severity.HIGH if (
                        allow_creds.lower() == "true" and allow_origin != "*"
                    ) else Severity.MEDIUM

                    findings.append(
                        Finding(
                            title=f"CORS Misconfiguration: {ep.path} reflects Origin '{origin}'",
                            severity=sev,
                            owasp_category=OWASPCategory.API8_MISCONFIG,
                            endpoint=ep.path,
                            method=ep.method,
                            description=(
                                f"When the Origin header was set to '{origin}', the server "
                                f"responded with Access-Control-Allow-Origin: {allow_origin}"
                                + (
                                    f" and Access-Control-Allow-Credentials: {allow_creds}. "
                                    "This combination allows any website to make authenticated "
                                    "cross-origin requests on behalf of a logged-in user and "
                                    "read the response, enabling full account takeover via CSRF "
                                    "+ data exfiltration."
                                    if allow_creds.lower() == "true"
                                    else ". A wildcard or reflected origin without credentials "
                                    "is lower risk but still allows data exfiltration for "
                                    "non-authenticated endpoints."
                                )
                            ),
                            remediation=(
                                "Maintain an explicit allowlist of permitted origins. Never "
                                "reflect the Origin header verbatim. Never combine "
                                "Access-Control-Allow-Origin: * with "
                                "Access-Control-Allow-Credentials: true — this combination is "
                                "invalid per the CORS spec and dangerous if implemented anyway."
                            ),
                            evidence=Evidence(
                                request_method=ep.method,
                                request_url=client._build_url(ep.path),
                                request_headers={"Origin": origin},
                                request_body=None,
                                response_status=cors_resp.status_code,
                                response_headers=dict(cors_resp.headers),
                                response_body_snippet=client.safe_body_snippet(cors_resp, 200),
                                notes=f"ACAO: {allow_origin}, ACAC: {allow_creds}",
                            ),
                            cvss_score=8.1 if sev == Severity.HIGH else 5.4,
                        )
                    )
                    break  # one CORS finding per endpoint is enough

            # --- Verbose error on malformed input ---
            if ep.method in ("POST", "PUT", "PATCH"):
                malformed_resp = client.request(
                    ep.method, ep.path,
                    data="{malformed json",
                    override_headers={"Content-Type": "application/json"},
                )
                if malformed_resp is not None and malformed_resp.status_code >= 500:
                    text = malformed_resp.text
                    for marker in _STACK_TRACE_MARKERS:
                        if marker in text:
                            findings.append(
                                Finding(
                                    title=f"Verbose Error / Stack Trace Exposure: {ep.path}",
                                    severity=Severity.MEDIUM,
                                    owasp_category=OWASPCategory.API8_MISCONFIG,
                                    endpoint=ep.path,
                                    method=ep.method,
                                    description=(
                                        f"Sending a malformed request body to {ep.path} "
                                        f"produced HTTP {malformed_resp.status_code} with a "
                                        f"stack trace or framework debug output in the response "
                                        f"(matched marker: '{marker}'). This discloses "
                                        f"implementation details — framework, file paths, "
                                        f"library versions — useful for further attacks."
                                    ),
                                    remediation=(
                                        "Disable debug mode in production (DEBUG=False in "
                                        "Django, NODE_ENV=production, ASPNETCORE_ENVIRONMENT="
                                        "Production). Implement a global exception handler that "
                                        "returns a generic error message and logs the full "
                                        "trace server-side only."
                                    ),
                                    evidence=Evidence(
                                        request_method=ep.method,
                                        request_url=client._build_url(ep.path),
                                        request_headers={"Content-Type": "application/json"},
                                        request_body="{malformed json",
                                        response_status=malformed_resp.status_code,
                                        response_headers=dict(malformed_resp.headers),
                                        response_body_snippet=client.safe_body_snippet(malformed_resp),
                                        notes=f"Stack trace marker found: {marker}",
                                    ),
                                    cvss_score=5.3,
                                )
                            )
                            break

            if len(findings) >= self.config.max_findings_per_check:
                return findings

        return findings
