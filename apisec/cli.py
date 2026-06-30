"""CLI entry point — scan, quick-check, demo commands."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from apisec.config import load_config, minimal_config
from apisec.demo import generate_demo_result
from apisec.findings import severity_counts, sort_by_severity
from apisec.reporting import generate_html_report, generate_json_report
from apisec.scanner import Scanner, ScanResult


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_summary(result: ScanResult) -> None:
    counts = severity_counts(result.findings)
    print()
    print("=" * 60)
    print(f"  Scan complete: {result.target}")
    print(f"  Duration: {result.duration_seconds:.2f}s | Endpoints: {result.endpoints_scanned}")
    print("=" * 60)
    print(f"  CRITICAL: {counts['CRITICAL']:3d}   HIGH: {counts['HIGH']:3d}   "
          f"MEDIUM: {counts['MEDIUM']:3d}   LOW: {counts['LOW']:3d}   INFO: {counts['INFO']:3d}")
    print(f"  Total findings: {len(result.findings)}")
    print("=" * 60)

    for f in sort_by_severity(result.findings)[:10]:
        print(f"  [{f.severity.value:8s}] {f.title}")

    if len(result.findings) > 10:
        print(f"  ... and {len(result.findings) - 10} more — see full report")
    print()


def _write_reports(result: ScanResult, html_path: str | None, json_path: str | None, output_dir: str) -> None:
    if html_path is None and json_path is None:
        html_path = str(Path(output_dir) / "report.html")
        json_path = str(Path(output_dir) / "report.json")

    if html_path:
        path = generate_html_report(result, html_path)
        print(f"HTML report written to: {path}")

    if json_path:
        path = generate_json_report(result, json_path)
        print(f"JSON report written to: {path}")


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    if args.checks:
        config.scan_checks = [c.strip() for c in args.checks.split(",")]

    scanner = Scanner(config)
    result = scanner.run()

    _print_summary(result)
    _write_reports(result, args.html, args.json, config.output_dir)
    return _exit_code(result, args.fail_on)


def cmd_quick_check(args: argparse.Namespace) -> int:
    config = minimal_config(args.url, token=args.token)

    if args.checks:
        config.scan_checks = [c.strip() for c in args.checks.split(",")]
    else:
        # Quick check skips the noisiest/slowest checks by default
        config.scan_checks = ["broken_auth", "misconfig", "shadow_endpoints", "rate_limit"]

    from apisec.config import EndpointDef

    config.endpoints = [
        EndpointDef(method=ep["method"], path=ep["path"])
        for ep in [{"method": "GET", "path": "/api/v1/health"}]
    ]

    scanner = Scanner(config)
    result = scanner.run()

    _print_summary(result)
    _write_reports(result, args.html, args.json, config.output_dir)
    return _exit_code(result, args.fail_on)


def cmd_demo(args: argparse.Namespace) -> int:
    result = generate_demo_result()

    _print_summary(result)

    html_path = args.html or "reports/demo_report.html"
    json_path = args.json or "reports/demo_report.json"
    _write_reports(result, html_path, json_path, "reports")

    return 0


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return 0

    counts = severity_counts(result.findings)
    threshold_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    fail_on = fail_on.upper()

    if fail_on not in threshold_order:
        return 0

    threshold_index = threshold_order.index(fail_on)
    for severity in threshold_order[: threshold_index + 1]:
        if counts.get(severity, 0) > 0:
            print(f"\nExit code 1: at least one {severity} finding present (--fail-on {fail_on})")
            return 1

    return 0


# ----------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apisec",
        description="API Security Testing Engine — OWASP API Security Top 10 (2023) aligned",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    p_scan = subparsers.add_parser("scan", help="Run a full scan from a YAML config file")
    p_scan.add_argument("config", help="Path to YAML config file")
    p_scan.add_argument("--checks", help="Comma-separated list of checks to run (overrides config)")
    p_scan.add_argument("--html", help="Path to write the HTML report")
    p_scan.add_argument("--json", help="Path to write the JSON report")
    p_scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit with code 1 if any finding at or above this severity is found",
    )
    p_scan.set_defaults(func=cmd_scan)

    # --- quick-check ---
    p_quick = subparsers.add_parser("quick-check", help="Lightweight scan against a single base URL")
    p_quick.add_argument("--url", required=True, help="Base URL of the target API")
    p_quick.add_argument("--token", help="Bearer token for authenticated requests")
    p_quick.add_argument("--checks", help="Comma-separated list of checks to run")
    p_quick.add_argument("--html", help="Path to write the HTML report")
    p_quick.add_argument("--json", help="Path to write the JSON report")
    p_quick.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit with code 1 if any finding at or above this severity is found",
    )
    p_quick.set_defaults(func=cmd_quick_check)

    # --- demo ---
    p_demo = subparsers.add_parser("demo", help="Generate a report from synthetic findings (no live target)")
    p_demo.add_argument("--html", help="Path to write the HTML report (default: reports/demo_report.html)")
    p_demo.add_argument("--json", help="Path to write the JSON report (default: reports/demo_report.json)")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        if args.verbose:
            raise
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
