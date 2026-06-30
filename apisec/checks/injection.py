"""SQL injection, reflected XSS, and OS command injection checks."""


import re

from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_SQLI_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d+|sqlite_|pg_query|"
    r"ODBC Driver|unclosed quotation|syntax error|you have an error in your sql)",
    re.IGNORECASE,
)

_CMDI_OUTPUT_PATTERNS = re.compile(
    r"(root:.*:0:0|uid=\d+\(|www-data|Volume in drive [A-Z]|Directory of [A-Z]:\\)",
    re.IGNORECASE,
)


def _is_string_param(value: object) -> bool:
    return isinstance(value, str) and not value.startswith("http")


class InjectionCheck(BaseCheck):
    name = "injection"
    description = "Injection — SQL injection, reflected XSS, OS command injection"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []

        sql_payloads = self.pe.sql_injection_payloads()
        xss_payloads = self.pe.xss_payloads()
        cmd_payloads = self.pe.command_injection_payloads()

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            params_to_test = [
                ("query", k) for k, v in ep.sample_params.items() if _is_string_param(v)
            ] + [
                ("body", k) for k, v in ep.sample_body.items() if _is_string_param(v)
            ]

            if not params_to_test:
                continue

            for location, actual_key in params_to_test:

                # SQLi
                for p in sql_payloads[:5]:  # top 5 per param to cap request volume
                    resp = self._inject(client, ep, location, actual_key, p.payload)
                    if resp is None:
                        continue

                    sqli_match = _SQLI_ERROR_PATTERNS.search(resp.text)
                    if sqli_match or resp.status_code == 500:
                        findings.append(
                            Finding(
                                title=f"SQL Injection: {ep.path} [{actual_key}]",
                                severity=Severity.CRITICAL,
                                owasp_category=OWASPCategory.API8_MISCONFIG,
                                endpoint=ep.path,
                                method=ep.method,
                                description=(
                                    f"SQL injection payload injected into {location} parameter "
                                    f"'{actual_key}' produced a database error in the response"
                                    + (
                                        f": '{sqli_match.group(0)[:80]}'"
                                        if sqli_match
                                        else " (HTTP 500)"
                                    )
                                    + ". This indicates the parameter is passed unsanitized to "
                                    "a SQL query."
                                ),
                                remediation=(
                                    "Use parameterised queries / prepared statements exclusively. "
                                    "Never concatenate user input into SQL strings. Use an ORM "
                                    "that handles parameterisation by default. Implement a WAF "
                                    "as a defence-in-depth layer. Disable detailed database "
                                    "error messages in production."
                                ),
                                evidence=Evidence(
                                    request_method=ep.method,
                                    request_url=client._build_url(ep.path),
                                    request_headers=dict(client.session.headers),
                                    request_body={actual_key: p.payload} if location == "body" else None,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_snippet=client.safe_body_snippet(resp),
                                    notes=f"Payload: {p.payload!r} | Match: {sqli_match.group(0) if sqli_match else 'HTTP 500'}",
                                ),
                                cvss_score=9.8,
                            )
                        )
                        break  # One confirmed SQLi per param is enough

                # Reflected XSS
                for p in xss_payloads[:4]:
                    resp = self._inject(client, ep, location, actual_key, p.payload)
                    if resp is None:
                        continue

                    if p.payload in (resp.text or ""):
                        findings.append(
                            Finding(
                                title=f"Reflected XSS: {ep.path} [{actual_key}]",
                                severity=Severity.MEDIUM,
                                owasp_category=OWASPCategory.API8_MISCONFIG,
                                endpoint=ep.path,
                                method=ep.method,
                                description=(
                                    f"The XSS payload injected into {location} parameter "
                                    f"'{actual_key}' was reflected verbatim in the response body "
                                    f"without HTML encoding. If this API response is rendered by "
                                    f"a browser without explicit encoding, it will execute."
                                ),
                                remediation=(
                                    "HTML-encode all output that originated from user input. "
                                    "Set Content-Type: application/json (not text/html) on API "
                                    "responses so browsers do not interpret them as HTML. Add "
                                    "Content-Security-Policy and X-Content-Type-Options: nosniff "
                                    "headers. If the API is consumed by a frontend framework, "
                                    "ensure the framework's template system is used correctly "
                                    "(no innerHTML / dangerouslySetInnerHTML)."
                                ),
                                evidence=Evidence(
                                    request_method=ep.method,
                                    request_url=client._build_url(ep.path),
                                    request_headers=dict(client.session.headers),
                                    request_body={actual_key: p.payload} if location == "body" else None,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_snippet=client.safe_body_snippet(resp),
                                    notes=f"Payload reflected verbatim: {p.payload!r}",
                                ),
                                cvss_score=6.1,
                            )
                        )
                        break

                # Command injection
                for p in cmd_payloads[:3]:
                    resp = self._inject(client, ep, location, actual_key, p.payload)
                    if resp is None:
                        continue

                    cmd_match = _CMDI_OUTPUT_PATTERNS.search(resp.text)
                    if cmd_match:
                        findings.append(
                            Finding(
                                title=f"OS Command Injection: {ep.path} [{actual_key}]",
                                severity=Severity.CRITICAL,
                                owasp_category=OWASPCategory.API8_MISCONFIG,
                                endpoint=ep.path,
                                method=ep.method,
                                description=(
                                    f"OS command injection payload in {location} parameter "
                                    f"'{actual_key}' produced shell output in the response: "
                                    f"'{cmd_match.group(0)[:80]}'. The server is executing "
                                    f"user-supplied input as a shell command."
                                ),
                                remediation=(
                                    "Never pass user input to shell commands. If OS calls are "
                                    "unavoidable, use language APIs that pass arguments as arrays "
                                    "(subprocess.run([...]) in Python, execv in C) rather than "
                                    "shell=True. Validate input against a strict allowlist. Run "
                                    "the application process with the minimum required OS "
                                    "privileges."
                                ),
                                evidence=Evidence(
                                    request_method=ep.method,
                                    request_url=client._build_url(ep.path),
                                    request_headers=dict(client.session.headers),
                                    request_body={actual_key: p.payload} if location == "body" else None,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_snippet=client.safe_body_snippet(resp),
                                    notes=f"Shell output found: {cmd_match.group(0)!r}",
                                ),
                                cvss_score=9.8,
                            )
                        )
                        break

                if len(findings) >= self.config.max_findings_per_check:
                    return findings

        return findings

    def _inject(self, client, ep, location, key, payload):
        if location == "query":
            injected_params = {**ep.sample_params, key: payload}
            return client.request(ep.method, ep.path, params=injected_params)
        else:
            injected_body = {**ep.sample_body, key: payload}
            return client.request(ep.method, ep.path, json=injected_body)
