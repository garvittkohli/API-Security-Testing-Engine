"""Tests for apisec.config — YAML loading, env var interpolation, defaults."""

import pytest

from apisec.config import EndpointDef, load_config, minimal_config


SAMPLE_CONFIG = """
target:
  base_url: "https://api.example.com/"

auth:
  bearer_token: "${TEST_API_TOKEN}"
  extra_headers:
    X-Tenant-ID: "tenant-123"

headers:
  Accept: "application/json"

scan:
  checks:
    - bola
    - ssrf
  rate_limit_delay: 1.5
  timeout: 15
  max_findings_per_check: 5

excluded_paths:
  - "/api/v1/dangerous"

output:
  dir: "custom_reports"

endpoints:
  - method: get
    path: "/api/v1/users/{id}"
    sample_params:
      id: 42
  - method: POST
    path: "/api/v1/orders"
    sample_body:
      product_id: 7
"""


class TestLoadConfig:
    def test_base_url_trailing_slash_stripped(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(SAMPLE_CONFIG)

        config = load_config(config_file)
        assert config.base_url == "https://api.example.com"

    def test_env_var_interpolation_in_bearer_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(SAMPLE_CONFIG)

        config = load_config(config_file)
        assert config.auth_headers["Authorization"] == "Bearer secrettoken"

    def test_extra_headers_merged_into_auth_headers(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(SAMPLE_CONFIG)

        config = load_config(config_file)
        assert config.auth_headers["X-Tenant-ID"] == "tenant-123"

    def test_scan_section_values_applied(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(SAMPLE_CONFIG)

        config = load_config(config_file)
        assert config.scan_checks == ["bola", "ssrf"]
        assert config.rate_limit_delay == 1.5
        assert config.request_timeout == 15
        assert config.max_findings_per_check == 5

    def test_excluded_paths_and_output_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(SAMPLE_CONFIG)

        config = load_config(config_file)
        assert "/api/v1/dangerous" in config.excluded_paths
        assert config.output_dir == "custom_reports"

    def test_endpoints_parsed_with_method_uppercased(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(SAMPLE_CONFIG)

        config = load_config(config_file)
        assert len(config.endpoints) == 2

        users_ep = config.endpoints[0]
        assert users_ep.method == "GET"  # lowercase 'get' in YAML -> uppercased
        assert users_ep.path == "/api/v1/users/{id}"
        assert users_ep.sample_params == {"id": 42}

        orders_ep = config.endpoints[1]
        assert orders_ep.method == "POST"
        assert orders_ep.sample_body == {"product_id": 7}

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "does_not_exist.yaml")


class TestDefaultChecks:
    def test_default_checks_populated_when_omitted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_TOKEN", "secrettoken")
        minimal_yaml = """
target:
  base_url: "https://api.example.com"
auth:
  bearer_token: "${TEST_API_TOKEN}"
"""
        config_file = tmp_path / "minimal.yaml"
        config_file.write_text(minimal_yaml)

        config = load_config(config_file)
        assert "bola" in config.scan_checks
        assert "broken_auth" in config.scan_checks
        assert len(config.scan_checks) == 9


class TestEndpointDef:
    def test_method_normalized_to_uppercase(self):
        ep = EndpointDef(method="patch", path="/api/v1/thing")
        assert ep.method == "PATCH"


class TestMinimalConfig:
    def test_minimal_config_without_token(self):
        config = minimal_config("https://api.test.com")
        assert config.base_url == "https://api.test.com"
        assert config.auth_headers == {}
        assert config.endpoints == []

    def test_minimal_config_with_token_sets_bearer_header(self):
        config = minimal_config("https://api.test.com", token="abc123")
        assert config.auth_headers["Authorization"] == "Bearer abc123"
