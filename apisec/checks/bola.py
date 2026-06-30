"""API1:2023 — Broken Object Level Authorization (BOLA/IDOR)."""

from __future__ import annotations

import re

from apisec.checks.base import BaseCheck
from apisec.config import EndpointDef
from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.http_client import APIClient

_ID_KEYS = re.compile(r"\bid\b|_id$|^id_|^uuid$", re.IGNORECASE)


def _looks_like_id(key: str, value: object) -> bool:
    if _ID_KEYS.search(key):
        return True
    if isinstance(value, int) and value > 0:
        return True
    if isinstance(value, str):
        if value.isdigit():
            return True
        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        if uuid_re.match(value):
            return True
    return False


class BOLACheck(BaseCheck):
    name = "bola"
    description = "Broken Object Level Authorization — IDOR via ID enumeration"

    def run(self, client: APIClient, endpoints: list[EndpointDef]) -> list[Finding]:
        findings: list[Finding] = []

        for ep in endpoints:
            if self._is_excluded(ep.path):
                continue

            id_params = {
                k: v
                for k, v in ep.sample_params.items()
                if _looks_like_id(k, v)
            }

            if not id_params:
                continue

            for param_key, base_value in id_params.items():
                variants = self.pe.bola_id_variants(base_value)

                for variant in variants[:6]:  # cap probes per endpoint
                    test_path = ep.path.replace(f"{{{param_key}}}", str(variant.payload))

                    if "{" in test_path:
                        # Fallback: append as query param if path template didn't substitute
                        test_path = ep.path.split("{")[0].rstrip("/")
                        params = {param_key: str(variant.payload)}
                    else:
                        params = {}

                    resp = client.request(ep.method, test_path, params=params or None)
                    if resp is None:
                        continue

                    if resp.status_code == 200 and len(resp.text.strip()) > 10:
                        body_snippet = client.safe_body_snippet(resp)

                        # Check the baseline to avoid false positives on public endpoints
                        baseline_path = ep.path.replace(f"{{{param_key}}}", str(base_value))
                        baseline = client.request(ep.method, baseline_path)
                        baseline_status = baseline.status_code if baseline else None

                        if baseline_status != 200:
                            # Baseline didn't return 200 but the probe did — strong signal
                            confidence = "HIGH"
                        else:
                            # Both return 200; compare body lengths as a heuristic
                            baseline_len = len(baseline.text) if baseline else 0
                            probe_len = len(resp.text)
                            if abs(probe_len - baseline_len) < 50:
                                # Bodies look identical — possibly a public endpoint
                                continue
                            confidence = "MEDIUM"

                        findings.append(
                            Finding(
                                title=f"BOLA: Unauthorized Access to {ep.path}",
                                severity=Severity.HIGH,
                                owasp_category=OWASPCategory.API1_BOLA,
                                endpoint=ep.path,
                                method=ep.method,
                                description=(
                                    f"The endpoint returned HTTP 200 with data when object ID "
                                    f"{variant.payload!r} was substituted for the configured "
                                    f"baseline ID {base_value!r}. The server is not verifying "
                                    f"that the requesting user owns the requested resource."
                                ),
                                remediation=(
                                    "Enforce object-level authorization on every endpoint that "
                                    "accepts an object identifier. Before returning data, verify "
                                    "that the authenticated principal owns or has been explicitly "
                                    "granted access to the requested object. Never rely solely on "
                                    "the ID being unguessable."
                                ),
                                evidence=Evidence(
                                    request_method=ep.method,
                                    request_url=client._build_url(test_path),
                                    request_headers=dict(client.session.headers),
                                    request_body=None,
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    response_body_snippet=body_snippet,
                                    notes=variant.description,
                                ),
                                confidence=confidence,
                                cvss_score=8.1,
                            )
                        )

                        if len(findings) >= self.config.max_findings_per_check:
                            return findings

        return findings
