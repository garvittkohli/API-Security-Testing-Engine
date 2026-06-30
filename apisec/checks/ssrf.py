"""API7:2023 — Server Side Request Forgery."""


import re

from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_URL_PARAM_PATTERN = re.compile(
    r"\b(url|uri|endpoint|host|redirect|callback|webhook|src|dest|target|"
    r"fetch|source|href|link|path|location|image_url|avatar_url|logo_url)\b",
    re.IGNORECASE,
)


def _is_url_param(key: str) -> bool:
    return bool(_URL_PARAM_PATTERN.search(key))


def _check_response_for_ssrf(text: str) -> list[str]:
    indicators = [
        "ami-id", "instance-id", "account-id", "iam/security-credentials",
        "computeMetadata", "gce-metadata", "IMDS",
        "redis_version", "redis_mode",
        "SSH-", "OpenSSH",
        "root:", "bin:", "/etc/passwd",
        "Connection refused",
        "127.0.0.1", "169.254.169.254",
    ]
    return [ind for ind in indicators if ind.lower() in text.lower()]


class SSRFCheck(BaseCheck):
    name = "ssrf"
    description = "Server Side Request Forgery — internal service and metadata endpoint access"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []
        payloads = self.pe.ssrf_payloads()

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            # Collect URL-like parameters from both body and query params
            url_params_body = [k for k in ep.sample_body if _is_url_param(k)]
            url_params_query = [k for k in ep.sample_params if _is_url_param(k)]

            if not url_params_body and not url_params_query:
                continue

            for ssrf_payload in payloads:
                # Inject into body parameters
                for param in url_params_body:
                    injected_body = {**ep.sample_body, param: ssrf_payload.payload}
                    resp = client.request(ep.method, ep.path, json=injected_body)

                    if resp is None:
                        continue

                    hit_indicators = _check_response_for_ssrf(resp.text)

                    if hit_indicators or resp.status_code == 200:
                        sev = Severity.CRITICAL if hit_indicators else Severity.MEDIUM
                        findings.append(
                            self._make_finding(
                                client, ep, param, ssrf_payload.payload,
                                resp, hit_indicators, "body", sev
                            )
                        )

                # Inject into query parameters
                for param in url_params_query:
                    injected_params = {**ep.sample_params, param: ssrf_payload.payload}
                    resp = client.request(ep.method, ep.path, params=injected_params)

                    if resp is None:
                        continue

                    hit_indicators = _check_response_for_ssrf(resp.text)

                    if hit_indicators or resp.status_code == 200:
                        sev = Severity.CRITICAL if hit_indicators else Severity.MEDIUM
                        findings.append(
                            self._make_finding(
                                client, ep, param, ssrf_payload.payload,
                                resp, hit_indicators, "query", sev
                            )
                        )

                if len(findings) >= self.config.max_findings_per_check:
                    return findings

        return findings

    def _make_finding(self, client, ep, param, payload_url, resp, indicators, location, sev):
        confirmed = bool(indicators)
        return Finding(
            title=f"SSRF {'Confirmed' if confirmed else 'Potential'}: {ep.path} [{param}]",
            severity=sev,
            owasp_category=OWASPCategory.API7_SSRF,
            endpoint=ep.path,
            method=ep.method,
            description=(
                f"The {location} parameter '{param}' was injected with the SSRF probe "
                f"{payload_url!r}. "
                + (
                    f"The response contained SSRF indicators: {indicators}. "
                    f"The server appears to have made an outbound request to the injected URL."
                    if confirmed
                    else "The server returned HTTP 200. Blind SSRF cannot be fully ruled out "
                    "without an out-of-band listener."
                )
            ),
            remediation=(
                "Validate and sanitize all URL-type inputs. Implement a strict allowlist of "
                "permitted URL schemes, hosts, and ports. Block requests to RFC-1918 address "
                "ranges (10.x, 172.16–31.x, 192.168.x) and cloud metadata endpoints "
                "(169.254.169.254, metadata.google.internal). On AWS, enforce IMDSv2 which "
                "requires a session token that SSRF cannot obtain."
            ),
            evidence=Evidence(
                request_method=ep.method,
                request_url=client._build_url(ep.path),
                request_headers=dict(client.session.headers),
                request_body={param: payload_url} if location == "body" else None,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body_snippet=client.safe_body_snippet(resp),
                notes=f"SSRF indicators found: {indicators}" if indicators else "No direct indicators",
            ),
            cvss_score=9.8 if confirmed else 5.0,
        )
