"""Tests for apisec.demo — synthetic finding generation for `apisec demo`."""

from apisec.demo import generate_demo_result
from apisec.findings import severity_counts


class TestDemoResult:
    def test_finding_count_within_spec_range(self):
        result = generate_demo_result()
        assert 12 <= len(result.findings) <= 15

    def test_multiple_severity_levels_represented(self):
        result = generate_demo_result()
        counts = severity_counts(result.findings)

        non_zero_severities = [sev for sev, count in counts.items() if count > 0]
        assert len(non_zero_severities) >= 3
        assert counts["CRITICAL"] > 0
        assert counts["HIGH"] > 0

    def test_findings_cover_multiple_owasp_categories(self):
        result = generate_demo_result()
        categories = {f.owasp_category for f in result.findings}
        assert len(categories) >= 5

    def test_check_results_sum_matches_finding_count(self):
        result = generate_demo_result()
        total_from_checks = sum(c.finding_count for c in result.check_results)
        assert total_from_checks == len(result.findings)

    def test_no_network_calls_required(self):
        # generate_demo_result should be fully deterministic and synchronous —
        # calling it twice should yield the same finding count and target
        result1 = generate_demo_result()
        result2 = generate_demo_result()

        assert result1.target == result2.target
        assert len(result1.findings) == len(result2.findings)

    def test_every_finding_has_evidence(self):
        result = generate_demo_result()
        for f in result.findings:
            assert f.evidence.request_url.startswith("https://")
            assert f.evidence.response_status is not None
