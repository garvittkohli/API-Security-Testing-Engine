"""API5:2023 — Broken Function Level Authorization."""


from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_ESCALATION_SUFFIXES = [
    "/admin",
    "/all",
    "/list",
    "/export",
    "/bulk",
    "/delete",
    "/purge",
    "/promote",
    "/internal",
]

_ALTERNATE_METHODS = {
    "GET": ["DELETE", "PUT", "PATCH"],
    "POST": ["PUT", "DELETE"],
    "PUT": ["DELETE"],
    "PATCH": ["DELETE"],
}


class BFLACheck(BaseCheck):
    name = "bfla"
    description = "Broken Function Level Authorization — privilege escalation via admin endpoints"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []

        tested_paths: set[str] = set()

        # --- Method-switching probes ---
        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            for alt_method in _ALTERNATE_METHODS.get(ep.method, []):
                resp = client.request(alt_method, ep.path)
                if resp is None:
                    continue

                if resp.status_code in (200, 201, 202, 204):
                    findings.append(
                        Finding(
                            title=f"BFLA: {alt_method} {ep.path} succeeds (documented as {ep.method})",
                            severity=Severity.HIGH,
                            owasp_category=OWASPCategory.API5_BFLA,
                            endpoint=ep.path,
                            method=alt_method,
                            description=(
                                f"The endpoint {ep.path} is documented as {ep.method} in the "
                                f"scan config but also accepted {alt_method} with HTTP "
                                f"{resp.status_code}. Undocumented methods on an endpoint may "
                                f"expose privileged operations (delete, replace) to callers who "
                                f"should only have read access."
                            ),
                            remediation=(
                                "Explicitly allowlist HTTP methods per endpoint. Return 405 "
                                "Method Not Allowed for any method not in the allowlist. "
                                "Ensure authorization logic is applied consistently regardless "
                                "of which HTTP method is used."
                            ),
                            evidence=Evidence(
                                request_method=alt_method,
                                request_url=client._build_url(ep.path),
                                request_headers=dict(client.session.headers),
                                request_body=None,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_snippet=client.safe_body_snippet(resp),
                                notes=f"Undocumented method {alt_method} returned {resp.status_code}",
                            ),
                            cvss_score=8.1,
                        )
                    )

            # --- Admin-path escalation probes ---
            base_path = ep.path.rstrip("/")
            for suffix in _ESCALATION_SUFFIXES:
                escalated = f"{base_path}{suffix}"
                if escalated in tested_paths or self._is_excluded(escalated):
                    continue
                tested_paths.add(escalated)

                resp = client.get(escalated)
                if resp is None:
                    continue

                if resp.status_code in (200, 201, 202):
                    body = client.safe_body_snippet(resp)
                    findings.append(
                        Finding(
                            title=f"BFLA: Admin path accessible — {escalated}",
                            severity=Severity.CRITICAL,
                            owasp_category=OWASPCategory.API5_BFLA,
                            endpoint=escalated,
                            method="GET",
                            description=(
                                f"The path {escalated} returned HTTP {resp.status_code} "
                                f"with the configured user-level token. This path appears to "
                                f"be a privileged or administrative function that should not be "
                                f"accessible to regular users."
                            ),
                            remediation=(
                                "Separate administrative API endpoints into a distinct namespace "
                                "protected by a separate, stronger authorization check (e.g. "
                                "require role=admin claim in JWT). Consider deploying admin APIs "
                                "on a separate, non-public network segment. Log all access "
                                "attempts to admin-tier paths."
                            ),
                            evidence=Evidence(
                                request_method="GET",
                                request_url=client._build_url(escalated),
                                request_headers=dict(client.session.headers),
                                request_body=None,
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                                response_body_snippet=body,
                                notes=f"Admin-suffix escalation from {ep.path}",
                            ),
                            cvss_score=9.8,
                        )
                    )

            if len(findings) >= self.config.max_findings_per_check:
                return findings

        return findings
