"""Render scan results as a self-contained HTML report."""


from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from apisec.findings import OWASPCategory
from apisec.scanner import ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(result: ScanResult, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    data = result.to_dict()

    # Pre-aggregate OWASP category counts in canonical Top 10 order
    owasp_summary: "OrderedDict[str, int]" = OrderedDict(
        (cat.value, 0) for cat in OWASPCategory
    )
    for f in data["findings"]:
        owasp_summary[f["owasp_category"]] = owasp_summary.get(f["owasp_category"], 0) + 1
    # Drop categories with zero findings to keep the table tight
    owasp_summary = OrderedDict(
        (k, v) for k, v in owasp_summary.items() if v > 0
    ) or OrderedDict([("No category-mapped findings", 0)])

    html = template.render(
        target=data["target"],
        started_at=data["started_at"],
        duration_seconds=data["duration_seconds"],
        endpoints_scanned=data["endpoints_scanned"],
        summary=data["summary"],
        total_findings=data["total_findings"],
        findings=data["findings"],
        owasp_summary=owasp_summary,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path.write_text(html, encoding="utf-8")
    return output_path
