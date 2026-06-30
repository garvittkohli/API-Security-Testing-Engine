"""API3:2023 — Broken Object Property Level Authorization (mass assignment + excessive data exposure)."""


from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_SENSITIVE_FIELDS = {
    "password", "passwd", "secret", "token", "private_key", "api_key",
    "ssn", "credit_card", "card_number", "cvv", "internal_id",
    "stripe_customer_id", "paypal_id",
}


class MassAssignmentCheck(BaseCheck):
    name = "mass_assignment"
    description = "Broken Object Property Level Authorization — mass assignment and excessive exposure"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []
        payloads = self.pe.mass_assignment_payloads()

        writable_methods = {"POST", "PUT", "PATCH"}

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue
            if ep.method not in writable_methods:
                continue

            # --- Mass assignment probes ---
            for p in payloads:
                combined_body = {**ep.sample_body, **p.payload}
                resp = client.request(ep.method, ep.path, json=combined_body)

                if resp is None:
                    continue

                if resp.status_code not in (200, 201, 202):
                    continue

                injected_keys = set(p.payload.keys())
                body_text = resp.text.lower()

                confirmed_keys = [
                    k for k in injected_keys
                    if k.lower() in body_text
                ]

                if confirmed_keys:
                    findings.append(
                        Finding(
                            title=f"Mass Assignment: {ep.path} accepts {', '.join(confirmed_keys[:3])}",
                            severity=Severity.HIGH,
                            owasp_category=OWASPCategory.API3_BOPLA,
                            endpoint=ep.path,
                            method=ep.method,
                            description=(
                                f"The endpoint accepted and reflected privileged fields "
                                f"({', '.join(confirmed_keys)}) that were injected into the "
                                f"request body. If the server binds these fields directly to a "
                                f"database model, an attacker can escalate privileges, modify "
                                f"financial balances, or reassign resource ownership."
                            ),
                            remediation=(
                                "Use an allowlist (DTO / serializer whitelist) to define exactly "
                                "which fields are writable by clients. Never bind request bodies "
                                "directly to ORM models. Deny any fields not in the allowlist with "
                                "a 400 response. Mark sensitive model fields (role, is_admin, "
                                "balance) as read-only from the API layer."
                            ),
                            evidence=Evidence(
                                request_method=ep.method,
                                request_url=client._build_url(ep.path),
                                request_headers=dict(client.session.headers),
                                request_body=combined_body,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_snippet=client.safe_body_snippet(resp),
                                notes=f"Injected fields reflected: {confirmed_keys}",
                            ),
                            cvss_score=7.5,
                        )
                    )

            # --- Excessive data exposure probe ---
            # Fire the legitimate request and scan the response for sensitive fields
            if ep.sample_body:
                resp = client.request(ep.method, ep.path, json=ep.sample_body)
            else:
                resp = client.request("GET", ep.path)

            if resp and resp.status_code == 200:
                try:
                    response_data = resp.json()
                    response_keys = self._extract_keys(response_data)
                    exposed = _SENSITIVE_FIELDS & {k.lower() for k in response_keys}
                    if exposed:
                        findings.append(
                            Finding(
                                title=f"Excessive Data Exposure: {ep.path} leaks {', '.join(exposed)}",
                                severity=Severity.MEDIUM,
                                owasp_category=OWASPCategory.API3_BOPLA,
                                endpoint=ep.path,
                                method=ep.method,
                                description=(
                                    f"The response body contains fields that should not be "
                                    f"exposed to clients: {', '.join(exposed)}. Clients should "
                                    f"never receive passwords, secrets, or internal identifiers."
                                ),
                                remediation=(
                                    "Implement response filtering at the serialization layer. "
                                    "Never return fields from the data model that the client does "
                                    "not need. Use a dedicated response schema (e.g. Pydantic "
                                    "model, serializer) that explicitly lists allowed output fields."
                                ),
                                evidence=Evidence(
                                    request_method=ep.method,
                                    request_url=client._build_url(ep.path),
                                    request_headers=dict(client.session.headers),
                                    request_body=ep.sample_body or None,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_snippet=client.safe_body_snippet(resp),
                                    notes=f"Sensitive fields found: {sorted(exposed)}",
                                ),
                                cvss_score=5.3,
                            )
                        )
                except (ValueError, TypeError):
                    pass

            if len(findings) >= self.config.max_findings_per_check:
                return findings

        return findings

    def _extract_keys(self, data: object, depth: int = 0) -> list[str]:
        if depth > 5:
            return []
        keys: list[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                keys.append(str(k))
                keys.extend(self._extract_keys(v, depth + 1))
        elif isinstance(data, list):
            for item in data[:5]:
                keys.extend(self._extract_keys(item, depth + 1))
        return keys
