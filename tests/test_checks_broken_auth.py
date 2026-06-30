"""
Tests for apisec.checks.broken_auth — Broken Authentication detection.
"""

import responses

from apisec.checks.broken_auth import BrokenAuthCheck
from apisec.config import EndpointDef, ScanConfig
from apisec.findings import OWASPCategory, Severity
from apisec.http_client import APIClient
from apisec.payload_engine import PayloadEngine


def _make_config(**overrides) -> ScanConfig:
    defaults = dict(
        base_url="https://api.test.com",
        rate_limit_delay=0,
        auth_headers={"Authorization": "Bearer valid-token"},
        max_findings_per_check=20,
    )
    defaults.update(overrides)
    return ScanConfig(**defaults)


class TestBrokenAuthCheck:
    @responses.activate
    def test_flags_endpoint_accessible_without_authorization_header(self):
        config = _make_config(
            endpoints=[EndpointDef(method="GET", path="/api/v1/account/settings")]
        )

        # Any request to this path succeeds — server doesn't enforce auth at all
        responses.add(
            responses.GET,
            "https://api.test.com/api/v1/account/settings",
            json={"user_id": 1, "role": "admin"},
            status=200,
        )

        client = APIClient(base_url=config.base_url, auth_headers=config.auth_headers, rate_limit_delay=0)
        check = BrokenAuthCheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        no_auth_findings = [f for f in findings if "No Authorization header" in f.title]
        assert len(no_auth_findings) == 1
        assert no_auth_findings[0].severity == Severity.CRITICAL
        assert no_auth_findings[0].owasp_category == OWASPCategory.API2_BROKEN_AUTH

    @responses.activate
    def test_properly_secured_endpoint_produces_no_findings(self):
        config = _make_config(
            endpoints=[EndpointDef(method="GET", path="/api/v1/account/settings")]
        )

        # Every variant of the request returns 401 — auth properly enforced
        responses.add(
            responses.GET,
            "https://api.test.com/api/v1/account/settings",
            json={"error": "unauthorized"},
            status=401,
        )

        client = APIClient(base_url=config.base_url, auth_headers=config.auth_headers, rate_limit_delay=0)
        check = BrokenAuthCheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        assert findings == []

    @responses.activate
    def test_respects_max_findings_per_check_cap(self):
        config = _make_config(
            endpoints=[
                EndpointDef(method="GET", path=f"/api/v1/resource{i}")
                for i in range(10)
            ],
            max_findings_per_check=3,
        )

        for i in range(10):
            responses.add(
                responses.GET,
                f"https://api.test.com/api/v1/resource{i}",
                json={"ok": True},
                status=200,
            )

        client = APIClient(base_url=config.base_url, auth_headers=config.auth_headers, rate_limit_delay=0)
        check = BrokenAuthCheck(config, PayloadEngine())
        findings = check.run(client, config.endpoints)

        assert len(findings) <= 3

    def test_excluded_paths_are_skipped(self):
        config = _make_config(
            endpoints=[EndpointDef(method="GET", path="/api/v1/admin/wipe")],
            excluded_paths=["/api/v1/admin"],
        )
        client = APIClient(base_url=config.base_url, auth_headers=config.auth_headers, rate_limit_delay=0)
        check = BrokenAuthCheck(config, PayloadEngine())

        findings = check.run(client, config.endpoints)
        assert findings == []
