"""Serialize scan results to JSON with ECS-formatted events."""


import json
from pathlib import Path

from apisec.scanner import ScanResult


def generate_json_report(result: ScanResult, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = result.to_dict()

    # Add an ECS-friendly flattened view for direct SIEM ingestion
    data["ecs_events"] = [
        {
            "@timestamp": f["timestamp"],
            "event.kind": "alert",
            "event.category": "api_security",
            "event.severity": f["severity"],
            "rule.name": f["title"],
            "rule.reference": f["owasp_category"],
            "url.path": f["endpoint"],
            "http.request.method": f["method"],
            "http.response.status_code": f["evidence"]["response_status"],
            "finding.id": f["id"],
            "finding.confidence": f["confidence"],
        }
        for f in data["findings"]
    ]

    output_path.write_text(json.dumps(data, indent=2, default=str))
    return output_path
