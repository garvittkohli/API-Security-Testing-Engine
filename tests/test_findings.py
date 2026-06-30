"""Tests for apisec.findings — Finding, Severity, OWASPCategory, helpers."""

from apisec.findings import (
    Evidence,
    Finding,
    OWASPCategory,
    Severity,
    severity_counts,
    sort_by_severity,
)


def _make_finding(severity: Severity, title: str = "Test Finding") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        owasp_category=OWASPCategory.API1_BOLA,
        endpoint="/api/v1/test",
        method="GET",
        description="A test finding.",
        remediation="Fix it.",
        evidence=Evidence.synthetic("GET", "https://example.com/api/v1/test", 200, "{}"),
    )


class TestSeverity:
    def test_severity_ordering_critical_first(self):
        assert Severity.CRITICAL.order < Severity.HIGH.order
        assert Severity.HIGH.order < Severity.MEDIUM.order
        assert Severity.MEDIUM.order < Severity.LOW.order
        assert Severity.LOW.order < Severity.INFO.order

    def test_severity_color_is_hex(self):
        for sev in Severity:
            assert sev.color.startswith("#")
            assert len(sev.color) == 7


class TestFinding:
    def test_to_dict_contains_required_fields(self):
        finding = _make_finding(Severity.HIGH)
        data = finding.to_dict()

        required_keys = {
            "id", "title", "severity", "owasp_category", "endpoint",
            "method", "description", "remediation", "evidence",
            "timestamp", "cvss_score", "confidence",
        }
        assert required_keys.issubset(data.keys())
        assert data["severity"] == "HIGH"
        assert data["owasp_category"] == OWASPCategory.API1_BOLA.value

    def test_finding_id_is_generated_and_unique(self):
        f1 = _make_finding(Severity.LOW)
        f2 = _make_finding(Severity.LOW)
        assert f1.id != f2.id
        assert len(f1.id) == 8

    def test_evidence_to_dict_round_trip(self):
        ev = Evidence.synthetic("POST", "https://api.test/x", 201, "ok", notes="hello")
        d = ev.to_dict()
        assert d["request_method"] == "POST"
        assert d["response_status"] == 201
        assert d["notes"] == "hello"


class TestSeverityHelpers:
    def test_severity_counts_tallies_correctly(self):
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.LOW),
        ]
        counts = severity_counts(findings)

        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 0
        assert counts["LOW"] == 1
        assert counts["INFO"] == 0

    def test_severity_counts_empty_list(self):
        counts = severity_counts([])
        assert all(v == 0 for v in counts.values())
        assert set(counts.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_sort_by_severity_orders_critical_first(self):
        findings = [
            _make_finding(Severity.LOW, "low-1"),
            _make_finding(Severity.CRITICAL, "crit-1"),
            _make_finding(Severity.MEDIUM, "med-1"),
            _make_finding(Severity.HIGH, "high-1"),
        ]
        ordered = sort_by_severity(findings)
        ordered_severities = [f.severity for f in ordered]

        assert ordered_severities == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

    def test_sort_by_severity_does_not_mutate_input(self):
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.CRITICAL)]
        original_order = list(findings)
        sort_by_severity(findings)
        assert findings == original_order
