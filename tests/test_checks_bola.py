"""
Tests for apisec.checks.bola — BOLA/IDOR detection logic.

Uses the `responses` library to mock HTTP without any network access.
"""

import responses

from apisec.checks.bola import BOLACheck
from apisec.config import EndpointDef, ScanConfig
from apisec.findings import Severity
from apisec.payload_engine import PayloadEngine


def _make_config(**overrides) -> ScanConfig:
    defaults = dict(
        base_url="https://api.test.com",
        rate_limit_delay=0,
        max_findings_per_check=20,
    )
    defaults.update(overrides)
    return ScanConfig(**defaults)


class TestBOLACheck:
    @responses.activate
    def test_detects_bola_when_baseline_is_forbidden_but_probe_succeeds(self):
        config = _make_config(
            endpoints=[
                EndpointDef(
                    method="GET",
                    path="/api/v1/users/{id}/profile",
                    sample_params={"id": 1042},
                )
            ]
        )

        # The "neighbour" ID returns 200 with real data
        responses.add(
            responses.GET,
            "https://api.test.com/api/v1/users/1041/profile",
            json={"id": 1041, "email": "victim@example.com", "name": "Other User"},
            status=200,
        )
        # The configured baseline ID (belonging to the authenticated user)
        # returns 403 — meaning the *probe* should NOT have succeeded
        responses.add(
            responses.GET,
            "https://api.test.com/api/v1/users/1042/profile",
            json={"error": "forbidden"},
            status=403,
        )

        # Catch-all for the other variant IDs probed (1037, 1040, 1043, 1044, 1047)
        for other_id in (1037, 1040, 1043, 1044, 1047):
            responses.add(
                responses.GET,
                f"https://api.test.com/api/v1/users/{other_id}/profile",
                json={"error": "not found"},
                status=404,
            )

        from apisec.http_client import APIClient
        client = APIClient(base_url=config.base_url, rate_limit_delay=0)

        check = BOLACheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        assert len(findings) >= 1
        bola_finding = findings[0]
        assert bola_finding.severity == Severity.HIGH
        assert "1041" in bola_finding.evidence.request_url
        assert bola_finding.confidence == "HIGH"

    @responses.activate
    def test_no_finding_when_endpoint_is_public_for_everyone(self):
        """If both the baseline and the probed ID return identical 200 bodies
        (a genuinely public endpoint), no BOLA finding should be raised."""
        config = _make_config(
            endpoints=[
                EndpointDef(
                    method="GET",
                    path="/api/v1/products/{id}",
                    sample_params={"id": 100},
                )
            ]
        )

        public_body = {"id": "PLACEHOLDER", "name": "Public Product", "price": 19.99, "in_stock": True}

        for pid in (95, 98, 99, 101, 102, 105, 100):
            body = dict(public_body, id=pid)
            responses.add(
                responses.GET,
                f"https://api.test.com/api/v1/products/{pid}",
                json=body,
                status=200,
            )

        from apisec.http_client import APIClient
        client = APIClient(base_url=config.base_url, rate_limit_delay=0)

        check = BOLACheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        assert findings == []

    @responses.activate
    def test_no_finding_when_probe_returns_404(self):
        config = _make_config(
            endpoints=[
                EndpointDef(
                    method="GET",
                    path="/api/v1/users/{id}/profile",
                    sample_params={"id": 5},
                )
            ]
        )

        responses.add(
            responses.GET,
            "https://api.test.com/api/v1/users/5/profile",
            json={"id": 5},
            status=200,
        )
        # All neighbour IDs return 404 — proper authorization in place
        for nid in (1, 3, 4, 6, 7, 10):
            responses.add(
                responses.GET,
                f"https://api.test.com/api/v1/users/{nid}/profile",
                json={"error": "not found"},
                status=404,
            )

        from apisec.http_client import APIClient
        client = APIClient(base_url=config.base_url, rate_limit_delay=0)

        check = BOLACheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        assert findings == []

    def test_skips_endpoints_without_id_like_params(self):
        config = _make_config(
            endpoints=[
                EndpointDef(method="GET", path="/api/v1/health", sample_params={}),
            ]
        )
        from apisec.http_client import APIClient
        client = APIClient(base_url=config.base_url, rate_limit_delay=0)

        check = BOLACheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        assert findings == []
