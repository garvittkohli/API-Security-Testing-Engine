# API Security Testing Engine

![CI](https://github.com/garvittkohli/api-security-engine/actions/workflows/ci.yml/badge.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![OWASP API Top 10 2023](https://img.shields.io/badge/OWASP%20API%20Top%2010-2023-red)

An automated, OWASP API Security Top 10 (2023) aligned testing engine for REST APIs.

Constructs and fires context-aware test payloads against API endpoints, then produces severity-graded findings — with the full HTTP request, response snippet, and remediation guidance — in a developer-ready HTML report and a SIEM-ingestible JSON output.

---

## Why this exists

Existing tools each have gaps that leave a real coverage hole for API-specific security testing:

| Tool | Gap |
|---|---|
| **Burp Suite / OWASP ZAP** | GUI-centric, not natively CI/CD-native without an Enterprise license. Designed for web application testing — OWASP *Web* Top 10 — not the API-specific Top 10 |
| **nuclei** | Template-based: only tests for patterns someone already wrote a template for. Can't construct context-aware payloads from your specific endpoint schema |
| **RESTler** | Requires a complete OpenAPI/Swagger specification. Authorization logic flaws (BOLA, BFLA) fall outside its testing model |
| **None of the above** | None produce a developer-ready report that maps each finding to OWASP category, includes the exact HTTP exchange as evidence, and gives concrete remediation steps |

**This tool fills that gap**: lightweight Python, no spec file required, CI/CD native, with BOLA multi-ID probing and JWT manipulation that none of the above do out of the box.

---

## Checks performed

| ID | OWASP API 2023 Category | What gets tested |
|---|---|---|
| API1 | Broken Object Level Authorization | Adjacent ID enumeration, UUID probing, cross-tenant object access |
| API2 | Broken Authentication | No-auth access, empty token, `null` token, `alg:none` JWT, weak-secret JWT |
| API3 | Broken Object Property Level Authorization | Mass assignment (role, balance, is_admin fields), excessive data exposure |
| API4 | Unrestricted Resource Consumption | Burst request detection, missing 429 response |
| API5 | Broken Function Level Authorization | Admin-suffix path escalation, undocumented HTTP method acceptance |
| API7 | Server Side Request Forgery | Cloud metadata probes (AWS IMDSv1/v2, GCP, Azure), internal service probes |
| API8 | Security Misconfiguration | Missing hardening headers, CORS origin reflection, stack trace exposure, Server banner |
| API8 | Injection (cross-category) | SQL injection (error-based, blind, UNION), reflected XSS, OS command injection |
| API9 | Improper Inventory Management | Shadow endpoint discovery (60+ paths), legacy API version detection |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLI  (apisec)                               │
│          scan │ quick-check │ demo                                  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                    ┌───────▼────────┐
                    │    Scanner     │  Orchestrates checks, collects findings
                    └──┬────────┬───┘
                       │        │
          ┌────────────▼──┐  ┌──▼────────────────────┐
          │ PayloadEngine │  │     Check Registry     │
          │               │  │  bola  broken_auth     │
          │ - bola IDs    │  │  mass_assignment       │
          │ - SQLi        │  │  rate_limit  bfla      │
          │ - XSS         │  │  ssrf  injection       │
          │ - CMDi        │  │  misconfig             │
          │ - SSRF URLs   │  │  shadow_endpoints      │
          │ - JWT bypass  │  │                        │
          └───────────────┘  └───────────┬────────────┘
                                         │
                                ┌────────▼────────┐
                                │   APIClient     │  Rate-limited, auth-aware
                                │   (requests)    │  HTTP engine
                                └────────┬────────┘
                                         │
                                  [Target API]
                                         │
                                ┌────────▼────────┐
                                │ Finding Model   │  Severity, OWASP, Evidence
                                └────────┬────────┘
                                         │
                           ┌─────────────┴─────────────┐
                           │                           │
                    ┌──────▼──────┐           ┌────────▼───────┐
                    │ HTML Report │           │  JSON Report   │
                    │ Dark theme  │           │  ECS-formatted │
                    │ Collapsible │           │  SIEM-ready    │
                    └─────────────┘           └────────────────┘
```

---

## Installation

```bash
git clone https://github.com/garvittkohli/api-security-engine.git
cd api-security-engine
pip install -e .
```

Dependencies: `requests`, `PyYAML`, `Jinja2` — nothing else.

---

## Usage

### Demo mode (no live target needed)

```bash
apisec demo
```

Generates 15 synthetic findings from across the full OWASP API Top 10, writes `reports/demo_report.html` and `reports/demo_report.json`. Works completely offline. The findings are modeled on real-world incidents — SSRF against AWS IMDS, alg:none JWT bypass, Spring Boot Actuator exposure, and so on.

---

### Full scan

```bash
# Copy the example config and fill in your target + token
cp config.example.yaml config.yaml
export API_TOKEN="eyJhbGc..."

apisec scan config.yaml
```

The YAML config lets you set the target, auth headers, endpoints to test (with sample params for context-aware BOLA/injection probing), and which checks to run:

```yaml
target:
  base_url: "https://staging.your-api.com"

auth:
  bearer_token: "${API_TOKEN}"          # Resolved from environment

scan:
  checks: [bola, broken_auth, ssrf, injection, misconfig, shadow_endpoints]
  rate_limit_delay: 0.5                 # Seconds between requests
  timeout: 10

endpoints:
  - method: GET
    path: "/api/v1/users/{id}/profile"
    sample_params:
      id: 1042                          # Your own user ID — BOLA probes neighbour IDs

  - method: POST
    path: "/api/v1/integrations/webhook-test"
    sample_body:
      callback_url: "https://hooks.your-app.com/notify"   # Triggers SSRF check
```

---

### Quick check (no config file)

```bash
apisec quick-check --url https://staging.your-api.com --token "Bearer eyJ..."
```

Runs a lightweight subset of checks (auth, misconfig, shadow endpoints, rate limiting) against default paths. Useful as a first pass before writing a full config.

---

### CI/CD pipeline integration

```bash
apisec scan config.yaml --fail-on high
```

Exit code 1 if any finding at HIGH or above is found. Pipe the JSON report into your SIEM or parse it in a pipeline step:

```yaml
# .github/workflows/security.yml
- name: API security scan
  run: |
    apisec scan config.yaml --json report.json --fail-on critical

- name: Upload security report
  uses: actions/upload-artifact@v4
  with:
    name: api-security-report
    path: report.json
```

The JSON report includes an `ecs_events` array formatted for direct Elasticsearch/Logstash ingestion, matching the field names from the Elastic Common Schema (`event.severity`, `rule.name`, `url.path`, `http.response.status_code`).

---

## Reports

### HTML (dark theme, developer-facing)

- Severity-graded finding cards (CRITICAL → INFO)
- Filter bar to isolate by severity
- Collapsible evidence blocks showing the exact request and response
- OWASP category tag on every finding
- Remediation guidance written at developer level

### JSON (SIEM / pipeline)

```json
{
  "target": "https://staging.api.com",
  "summary": { "CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "INFO": 0 },
  "findings": [...],
  "ecs_events": [
    {
      "@timestamp": "2026-06-15T08:30:01+00:00",
      "event.severity": "CRITICAL",
      "rule.name": "BOLA: Unauthorized Access to /api/v1/orders/{id}",
      "rule.reference": "API1:2023 – Broken Object Level Authorization",
      "url.path": "/api/v1/orders/{id}",
      "http.request.method": "GET",
      "http.response.status_code": 200
    }
  ]
}
```

---

## Adding a new check

One file, one registration:

```python
# apisec/checks/my_check.py
from apisec.checks.base import BaseCheck
from apisec.findings import Finding

class MyCheck(BaseCheck):
    name = "my_check"

    def run(self, client, endpoints):
        findings = []
        # ... your logic ...
        return findings
```

```python
# apisec/checks/__init__.py  — add one line:
from apisec.checks.my_check import MyCheck
CHECK_REGISTRY["my_check"] = MyCheck
```

That's it. The scanner discovers and runs it automatically when `my_check` is listed in the config.

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest --cov=apisec
```

59 tests covering the finding model, payload engine, config loading, BOLA and auth check logic (with mocked HTTP via `responses`), demo generation, and report rendering.

---

## Ethical and legal use

This tool fires real HTTP requests at real servers. Only use it against systems you own or have explicit written authorisation to test. The `--fail-on` exit code integration is designed for use in your own CI pipeline, not for testing third-party APIs.

The rate limiting built into `APIClient` (`rate_limit_delay`, default 0.5s) ensures the tool does not self-inflict DoS conditions during testing. The `excluded_paths` config key lets you permanently exclude destructive endpoints from the scan scope.

---

## Related work

This project is part of a portfolio of production-grade security tooling. See also:

- **GCP Misconfiguration Scanner** — IAM, Compute, VPC firewall, Cloud Storage, Cloud SQL, and Logging misconfiguration detection with Terraform HCL remediation generation and ELK Stack integration
- **"64 Milliseconds"** — Published article on Android OTP interception vulnerabilities ([Medium](https://medium.com/@garvittkohli))
