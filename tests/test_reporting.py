"""Tests for apisec.reporting — HTML and JSON report generation."""

import json

from apisec.demo import generate_demo_result
from apisec.reporting import generate_html_report, generate_json_report


class TestJSONReport:
    def test_generates_valid_json_with_expected_top_level_keys(self, tmp_path):
        result = generate_demo_result()
        output = generate_json_report(result, tmp_path / "report.json")

        assert output.exists()
        data = json.loads(output.read_text())

        for key in ("target", "summary", "total_findings", "findings", "ecs_events"):
            assert key in data

        assert data["total_findings"] == len(result.findings)
        assert len(data["findings"]) == len(result.findings)

    def test_ecs_events_have_required_fields(self, tmp_path):
        result = generate_demo_result()
        output = generate_json_report(result, tmp_path / "report.json")
        data = json.loads(output.read_text())

        assert len(data["ecs_events"]) == len(result.findings)
        for event in data["ecs_events"]:
            assert "event.severity" in event
            assert "rule.name" in event
            assert "url.path" in event

    def test_findings_sorted_by_severity_critical_first(self, tmp_path):
        result = generate_demo_result()
        output = generate_json_report(result, tmp_path / "report.json")
        data = json.loads(output.read_text())

        severities = [f["severity"] for f in data["findings"]]
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [severity_order[s] for s in severities]
        assert ranks == sorted(ranks)

    def test_creates_parent_directories(self, tmp_path):
        result = generate_demo_result()
        nested_path = tmp_path / "nested" / "dir" / "report.json"
        output = generate_json_report(result, nested_path)
        assert output.exists()


class TestHTMLReport:
    def test_generates_html_file_containing_findings(self, tmp_path):
        result = generate_demo_result()
        output = generate_html_report(result, tmp_path / "report.html")

        assert output.exists()
        html = output.read_text()

        assert "<!DOCTYPE html>" in html
        assert "apisec" in html
        assert result.target in html

    def test_html_contains_severity_badges_for_each_finding(self, tmp_path):
        result = generate_demo_result()
        output = generate_html_report(result, tmp_path / "report.html")
        html = output.read_text()

        for f in result.findings:
            assert f.title in html

    def test_owasp_categories_present_in_coverage_table(self, tmp_path):
        result = generate_demo_result()
        output = generate_html_report(result, tmp_path / "report.html")
        html = output.read_text()

        categories = {f.owasp_category.value for f in result.findings}
        for category in categories:
            assert category in html
