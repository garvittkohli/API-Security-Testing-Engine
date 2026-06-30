"""Tests for apisec.payload_engine — payload generation logic per vulnerability class."""

from apisec.payload_engine import PayloadEngine


class TestBOLAPayloads:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_numeric_id_generates_offset_variants(self):
        variants = self.pe.bola_id_variants(1042)
        offset_payloads = [v.payload for v in variants if v.name.startswith("BOLA numeric offset")]

        # Should include neighbours both above and below the base ID
        assert 1041 in offset_payloads
        assert 1043 in offset_payloads
        assert 1044 in offset_payloads
        assert all(v.vulnerability_class == "BOLA" for v in variants)
        assert all(v.inject_location == "path" for v in variants)

    def test_numeric_id_never_produces_non_positive_values(self):
        variants = self.pe.bola_id_variants(2)
        offset_payloads = [v.payload for v in variants if v.name.startswith("BOLA numeric offset")]
        assert all(p >= 1 for p in offset_payloads)

    def test_string_numeric_id_is_treated_as_numeric(self):
        variants = self.pe.bola_id_variants("500")
        offset_payloads = [v.payload for v in variants if v.name.startswith("BOLA numeric offset")]
        assert len(offset_payloads) == 8  # 8 offsets defined

    def test_non_numeric_id_skips_offset_variants_but_includes_reserved(self):
        variants = self.pe.bola_id_variants("not-an-id")
        offset_payloads = [v for v in variants if v.name.startswith("BOLA numeric offset")]
        reserved_payloads = [v for v in variants if "reserved" in v.name]

        assert offset_payloads == []
        assert len(reserved_payloads) == 4  # 1, 2, 0, -1

    def test_nil_uuid_variant_always_present(self):
        variants = self.pe.bola_id_variants(1)
        uuid_variants = [v for v in variants if "UUID" in v.name]
        assert len(uuid_variants) == 1
        assert uuid_variants[0].payload == "00000000-0000-0000-0000-000000000001"


class TestInjectionPayloads:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_sql_injection_payloads_cover_blind_and_error_based(self):
        payloads = self.pe.sql_injection_payloads()
        names = [p.name for p in payloads]

        assert any("Boolean blind" in n for n in names)
        assert any("Time-based blind" in n for n in names)
        assert any("UNION" in n for n in names)
        assert all(p.vulnerability_class == "SQLi" for p in payloads)
        assert all(isinstance(p.payload, str) for p in payloads)

    def test_xss_payloads_include_script_and_template_injection(self):
        payloads = self.pe.xss_payloads()
        raw_payloads = [p.payload for p in payloads]

        assert any("<script>" in p for p in raw_payloads)
        assert any("{{7*7}}" in p for p in raw_payloads)
        assert all(p.vulnerability_class == "XSS" for p in payloads)

    def test_command_injection_payloads_cover_unix_and_windows(self):
        payloads = self.pe.command_injection_payloads()
        raw_payloads = [p.payload for p in payloads]

        assert any(p.startswith(";") for p in raw_payloads)
        assert any("&" in p for p in raw_payloads)
        assert all(p.vulnerability_class == "CommandInjection" for p in payloads)


class TestSSRFPayloads:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_includes_cloud_metadata_endpoints(self):
        payloads = self.pe.ssrf_payloads()
        urls = [p.payload for p in payloads]

        assert any("169.254.169.254" in u for u in urls)
        assert any("metadata.google.internal" in u for u in urls)

    def test_includes_internal_service_probes(self):
        payloads = self.pe.ssrf_payloads()
        urls = [p.payload for p in payloads]

        assert any("127.0.0.1" in u for u in urls)
        assert all(p.vulnerability_class == "SSRF" for p in payloads)


class TestMassAssignmentPayloads:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_role_escalation_payload_present(self):
        payloads = self.pe.mass_assignment_payloads()
        role_payload = next(p for p in payloads if "Role escalation" in p.name)

        assert role_payload.payload["role"] == "admin"
        assert role_payload.payload["is_admin"] is True
        assert role_payload.vulnerability_class == "MassAssignment"

    def test_all_payloads_are_dicts_for_body_injection(self):
        payloads = self.pe.mass_assignment_payloads()
        assert all(isinstance(p.payload, dict) for p in payloads)
        assert all(p.inject_location == "body" for p in payloads)


class TestAuthBypassPayloads:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_includes_alg_none_jwt(self):
        payloads = self.pe.auth_bypass_payloads()
        alg_none = next(p for p in payloads if "Algorithm=none" in p.name)

        assert "alg" in alg_none.payload["Authorization"] or "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" in alg_none.payload["Authorization"]
        assert alg_none.vulnerability_class == "BrokenAuth"

    def test_includes_no_auth_header_case(self):
        payloads = self.pe.auth_bypass_payloads()
        no_auth = next(p for p in payloads if p.name == "No Authorization header")
        assert no_auth.payload is None
        assert no_auth.inject_location == "header"


class TestShadowEndpointPaths:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_includes_known_high_value_paths(self):
        paths = self.pe.shadow_endpoint_paths()

        assert "/actuator/env" in paths
        assert "/.env" in paths
        assert "/swagger-ui.html" in paths
        assert "/graphql" in paths

    def test_no_duplicate_paths(self):
        paths = self.pe.shadow_endpoint_paths()
        assert len(paths) == len(set(paths))


class TestMisconfigHelpers:
    def setup_method(self):
        self.pe = PayloadEngine()

    def test_cors_origins_include_attacker_domain(self):
        origins = self.pe.cors_origins_to_probe()
        assert "https://evil.com" in origins

    def test_sensitive_headers_include_csp_and_hsts(self):
        headers = self.pe.sensitive_headers_expected()
        assert "Content-Security-Policy" in headers
        assert "Strict-Transport-Security" in headers
