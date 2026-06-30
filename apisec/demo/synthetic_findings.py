"""Offline demo mode — synthetic findings with no live target."""


from datetime import datetime, timezone

from apisec.findings import Evidence, Finding, OWASPCategory, Severity
from apisec.scanner import CheckResult, ScanResult

_DEMO_TARGET = "https://demo.vulnerable-api.local"


def _f(**kwargs) -> Finding:
    return Finding(**kwargs)


def _build_findings() -> list[Finding]:
    return [
        # ------------------------------------------------------------
        # API1 — BOLA / IDOR
        # ------------------------------------------------------------
        _f(
            title="BOLA: Unauthorized Access to /api/v1/users/{id}/profile",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API1_BOLA,
            endpoint="/api/v1/users/{id}/profile",
            method="GET",
            description=(
                "GET /api/v1/users/1043/profile returned HTTP 200 with full profile data "
                "when accessed using a token authenticating as user 1042. The server performs "
                "no ownership check — sequential ID enumeration exposes every user's PII."
            ),
            remediation=(
                "Enforce object-level authorization on every endpoint that accepts an "
                "object identifier. Before returning data, verify that the authenticated "
                "principal owns or has been explicitly granted access to the requested "
                "object. Never rely solely on the ID being unguessable."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/users/1043/profile", 200,
                '{"id": 1043, "email": "j.patel@corp-mail.com", "phone": "+91-98XXXXXX12", '
                '"address": {"city": "Pune", "zip": "411001"}, "subscription_tier": "enterprise"}',
                notes="Authenticated as user 1042; baseline request to /users/1042/profile also returned 200. "
                      "Response bodies differ — confirmed cross-tenant data leak.",
            ),
            confidence="HIGH",
            cvss_score=8.1,
        ),
        _f(
            title="BOLA: Order Details Accessible Across Tenants — /api/v1/orders/{id}",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API1_BOLA,
            endpoint="/api/v1/orders/{id}",
            method="GET",
            description=(
                "Sequential order IDs 8801–8806 all returned HTTP 200 with full order data "
                "(address, line items, card last-4) regardless of which account the token "
                "belongs to. 6/6 probed IDs exposed third-party order records."
            ),
            remediation=(
                "Add an ownership check (`order.user_id == request.user.id`) before "
                "returning order data. Consider switching from sequential integer IDs to "
                "UUIDs as a secondary defence-in-depth measure (not a substitute for "
                "authorization checks)."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/orders/8802", 200,
                '{"order_id": 8802, "user_id": 559, "items": [{"sku": "SKU-2291", "qty": 1}], '
                '"shipping_address": "12 MG Road, Bengaluru", "payment_method": "card_**** 4471", "total": 4299.00}',
                notes="Authenticated token belongs to user_id 230. 6/6 sequential IDs probed returned full order data.",
            ),
            confidence="HIGH",
            cvss_score=9.1,
        ),

        # ------------------------------------------------------------
        # API2 — Broken Authentication
        # ------------------------------------------------------------
        _f(
            title="Broken Auth (Algorithm=none JWT): /api/v1/account/settings",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API2_BROKEN_AUTH,
            endpoint="/api/v1/account/settings",
            method="GET",
            description=(
                "The endpoint returned HTTP 200 when accessed using a JWT with "
                "alg=none and an empty signature, containing the claim "
                '\'{"sub": "1", "role": "admin"}\'. The server is not validating the '
                "JWT algorithm field before trusting the claims — an attacker can craft "
                "a token asserting any user ID or role with zero cryptographic effort."
            ),
            remediation=(
                "Require a valid, unexpired token on every protected endpoint. Validate "
                "the JWT algorithm server-side and explicitly reject alg=none and any "
                "algorithm not on an allowlist (e.g. RS256). Use a JWT library that "
                "enforces algorithm allowlisting by default (PyJWT >= 2.x with "
                "algorithms=['RS256'])."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/account/settings", 200,
                '{"user_id": 1, "role": "admin", "email": "admin@vulnerable-api.local", '
                '"mfa_enabled": false, "api_keys": ["sk_live_4eC39HqLyjWDarjtT1zdp7dc"]}',
                notes="Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
            ),
            confidence="HIGH",
            cvss_score=9.8,
        ),
        _f(
            title="Broken Auth (Empty Bearer token): /api/v1/notifications",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API2_BROKEN_AUTH,
            endpoint="/api/v1/notifications",
            method="GET",
            description=(
                "Endpoint returned HTTP 200 with Authorization: Bearer <empty>. "
                "The middleware checks header presence but not token validity."
            ),
            remediation=(
                "Return HTTP 401 for any request where the bearer token is missing, "
                "empty, or fails signature verification — before any business logic "
                "executes. Add a unit test asserting this for every protected route."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/notifications", 200,
                '[{"id": 991, "type": "password_reset", "to": "ceo@partner-corp.com", '
                '"reset_link": "https://app.vulnerable-api.local/reset?token=8f2a..."}]',
                notes="Header sent: Authorization: Bearer  (empty value)",
            ),
            confidence="HIGH",
            cvss_score=9.1,
        ),
        _f(
            title="No Rate Limiting on Authentication Endpoint: /api/v1/auth/login",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API4_RESOURCE_CONSUMPTION,
            endpoint="/api/v1/auth/login",
            method="POST",
            description=(
                "40 rapid requests to the login endpoint produced no HTTP 429. "
                "39/40 returned 401 without any throttling, delay, or lockout — "
                "credential stuffing at full dictionary speed is unimpeded."
            ),
            remediation=(
                "Implement rate limiting per IP and per account on authentication "
                "endpoints — typically 5-10 attempts per minute. Return HTTP 429 with a "
                "Retry-After header once exceeded. Add progressive delays and CAPTCHA "
                "after repeated failures, and alert on anomalous login attempt volume "
                "via the SIEM."
            ),
            evidence=Evidence.synthetic(
                "POST", f"{_DEMO_TARGET}/api/v1/auth/login", 401,
                '{"error": "invalid_credentials"}',
                notes="Status codes from 40 requests: [401] x39, [200] x1 (account exists, password #37 happened to be correct test data)",
            ),
            confidence="HIGH",
            cvss_score=7.5,
        ),

        # ------------------------------------------------------------
        # API3 — BOPLA / Mass Assignment
        # ------------------------------------------------------------
        _f(
            title="Mass Assignment: /api/v1/users/{id} accepts role, is_admin",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API3_BOPLA,
            endpoint="/api/v1/users/{id}",
            method="PATCH",
            description=(
                "PATCH /api/v1/users/2207 accepted role=admin and is_admin=true in the "
                "request body and reflected both fields in the response. Privilege escalation "
                "confirmed — fields persisted to the database."
            ),
            remediation=(
                "Use an allowlist (DTO / serializer) to define exactly which fields are "
                "writable by clients on this endpoint. Never bind request bodies directly "
                "to ORM models. Mark 'role' and 'is_admin' as server-managed fields that "
                "can only be changed via a separate admin-only endpoint."
            ),
            evidence=Evidence.synthetic(
                "PATCH", f"{_DEMO_TARGET}/api/v1/users/2207", 200,
                '{"id": 2207, "name": "test_user", "role": "admin", "is_admin": true, "updated_at": "2026-06-15T09:14:02Z"}',
                notes="Request body included: {\"name\": \"test_user\", \"role\": \"admin\", \"is_admin\": true}. Both fields reflected and persisted.",
            ),
            confidence="HIGH",
            cvss_score=8.5,
        ),
        _f(
            title="Excessive Data Exposure: /api/v1/users/{id} leaks password, internal_id",
            severity=Severity.MEDIUM,
            owasp_category=OWASPCategory.API3_BOPLA,
            endpoint="/api/v1/users/{id}",
            method="GET",
            description=(
                "GET /api/v1/users/2207 returns password (bcrypt hash) and internal_id "
                "in the response body. Neither field should leave the server layer."
            ),
            remediation=(
                "Implement response filtering at the serialization layer using a "
                "dedicated output schema. Audit all `SELECT *` style queries that are "
                "passed directly to a JSON serializer — this is the most common root "
                "cause of excessive data exposure."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/users/2207", 200,
                '{"id": 2207, "internal_id": 88341, "name": "test_user", '
                '"password": "$2b$12$KIXQ1z9j8X9Z0Y3vQe7p9.uH8N1c2W3xR4sT5uV6wX7yZ8aB9cD0E", '
                '"email": "test_user@vulnerable-api.local"}',
                notes="Sensitive fields found: ['password', 'internal_id']",
            ),
            confidence="HIGH",
            cvss_score=5.3,
        ),

        # ------------------------------------------------------------
        # API5 — BFLA
        # ------------------------------------------------------------
        _f(
            title="BFLA: Admin path accessible — /api/v1/users/admin",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API5_BFLA,
            endpoint="/api/v1/users/admin",
            method="GET",
            description=(
                "/api/v1/users/admin returned HTTP 200 with a full user dump (4,812 records "
                "including emails and registration IPs) using a standard user-tier token. "
                "No role check on an admin bulk-export function."
            ),
            remediation=(
                "Separate administrative API endpoints into a distinct namespace "
                "protected by a dedicated authorization check that validates the role "
                "claim server-side on every request — not just at login. Add automated "
                "tests that assert non-admin tokens receive 403 on every /admin/* route."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/users/admin", 200,
                '{"total": 4812, "users": [{"id": 1, "email": "admin@vulnerable-api.local", '
                '"created_ip": "10.0.4.12"}, {"id": 2, "email": "ops@vulnerable-api.local", "created_ip": "10.0.4.18"}, "..."]}',
                notes="Authenticated as standard user role='customer'. Admin-suffix escalation from /api/v1/users.",
            ),
            confidence="HIGH",
            cvss_score=9.8,
        ),
        _f(
            title="BFLA: DELETE /api/v1/products/{id} succeeds (documented as GET)",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API5_BFLA,
            endpoint="/api/v1/products/{id}",
            method="DELETE",
            description=(
                "DELETE /api/v1/products/5510 returned 204 using a standard catalog token. "
                "The endpoint is documented as GET-only. Confirmed deletion on follow-up GET (404)."
            ),
            remediation=(
                "Explicitly allowlist HTTP methods per route at the framework routing "
                "layer. Return 405 Method Not Allowed for any method not in the "
                "allowlist. Ensure destructive operations (DELETE) always require an "
                "elevated role regardless of which route exposes them."
            ),
            evidence=Evidence.synthetic(
                "DELETE", f"{_DEMO_TARGET}/api/v1/products/5510", 204, "",
                notes="Undocumented method DELETE returned 204 No Content. Product 5510 confirmed removed on subsequent GET (404).",
            ),
            confidence="HIGH",
            cvss_score=8.1,
        ),

        # ------------------------------------------------------------
        # API7 — SSRF
        # ------------------------------------------------------------
        _f(
            title="SSRF Confirmed: /api/v1/integrations/webhook-test [callback_url]",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API7_SSRF,
            endpoint="/api/v1/integrations/webhook-test",
            method="POST",
            description=(
                "Injecting http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                "into callback_url caused the server to fetch and return AWS IMDS content — "
                "including temporary AccessKeyId, SecretAccessKey, and session Token for the "
                "instance's attached IAM role."
            ),
            remediation=(
                "Validate and sanitize all URL-type inputs. Implement a strict allowlist "
                "of permitted destination hosts for webhook/callback features. Block "
                "requests to RFC-1918 ranges and 169.254.169.254 at the application "
                "layer. On AWS, enforce IMDSv2 (token-required) so SSRF cannot retrieve "
                "credentials even if the request reaches the metadata service."
            ),
            evidence=Evidence.synthetic(
                "POST", f"{_DEMO_TARGET}/api/v1/integrations/webhook-test", 200,
                '{"fetched_status": 200, "fetched_body": "{\\"Code\\":\\"Success\\",\\"AccessKeyId\\":\\"ASIAW7XYZQ3EXAMPLE\\",'
                '\\"SecretAccessKey\\":\\"REDACTED\\",\\"Token\\":\\"REDACTED\\",\\"role\\":\\"prod-api-instance-role\\"}"}',
                notes="Injected body: {\"callback_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-api-instance-role\"}",
            ),
            confidence="HIGH",
            cvss_score=9.8,
        ),

        # ------------------------------------------------------------
        # API8 — Security Misconfiguration / Injection
        # ------------------------------------------------------------
        _f(
            title="SQL Injection: /api/v1/products/search [q]",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API8_MISCONFIG,
            endpoint="/api/v1/products/search",
            method="GET",
            description=(
                "Error-based SQLi in ?q= via extractvalue() returned MySQL version "
                "through an XPATH syntax error: 'XPATH syntax error: ~8.0.35-MySQL'."
            ),
            remediation=(
                "Use parameterised queries / prepared statements exclusively for the "
                "search endpoint. Never concatenate user input into SQL strings. "
                "Disable detailed database error messages in production responses; log "
                "them server-side only."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/products/search?q=%27%20AND%20extractvalue(1%2Cconcat(0x7e%2C(SELECT%20version())))--", 500,
                '{"error": "Internal Server Error", "detail": "XPATH syntax error: \'~8.0.35-MySQL\'"}',
                notes="Payload: \"' AND extractvalue(1,concat(0x7e,(SELECT version())))--\" | Match: XPATH syntax error",
            ),
            confidence="HIGH",
            cvss_score=9.8,
        ),
        _f(
            title="CORS Misconfiguration: /api/v1/account reflects Origin 'https://evil.com'",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.API8_MISCONFIG,
            endpoint="/api/v1/account",
            method="GET",
            description=(
                "Origin: https://evil.com was reflected in ACAO with ACAC: true. "
                "Any cross-origin page can make credentialed requests and read responses — "
                "full authenticated data exfiltration from a third-party origin."
            ),
            remediation=(
                "Maintain an explicit allowlist of permitted origins server-side. Never "
                "reflect the Origin header verbatim. Never combine "
                "Access-Control-Allow-Origin: * (or a reflected origin) with "
                "Access-Control-Allow-Credentials: true."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/account", 200,
                '{"id": 2207, "email": "test_user@vulnerable-api.local", "balance": 1250.00}',
                notes="ACAO: https://evil.com, ACAC: true",
            ),
            confidence="HIGH",
            cvss_score=8.1,
        ),
        _f(
            title="Missing Security Headers",
            severity=Severity.LOW,
            owasp_category=OWASPCategory.API8_MISCONFIG,
            endpoint="/api/v1/health",
            method="GET",
            description=(
                "Missing: Strict-Transport-Security, X-Content-Type-Options, "
                "X-Frame-Options, Content-Security-Policy across all responses."
            ),
            remediation=(
                "Add the missing headers at the API gateway or application middleware "
                "level: Strict-Transport-Security (max-age=31536000; "
                "includeSubDomains), X-Content-Type-Options: nosniff, X-Frame-Options: "
                "DENY, Content-Security-Policy: default-src 'none'."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/health", 200,
                '{"status": "ok"}',
                notes="Missing: ['X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security', 'Content-Security-Policy']",
            ),
            confidence="HIGH",
            cvss_score=3.1,
        ),

        # ------------------------------------------------------------
        # API9 — Improper Inventory Management
        # ------------------------------------------------------------
        _f(
            title="Shadow Endpoint Exposed: /actuator/env",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.API9_INVENTORY,
            endpoint="/actuator/env",
            method="GET",
            description=(
                "/actuator/env returned HTTP 200, exposing spring.datasource.password "
                "and jwt.signing.secret in plaintext. Endpoint not in API inventory, "
                "left enabled in the production build."
            ),
            remediation=(
                "Remove or restrict Spring Boot Actuator endpoints in production "
                "(management.endpoints.web.exposure.include should not include 'env' "
                "or 'dump'). If actuator endpoints are required for monitoring, expose "
                "them on a separate internal-only port protected by network policy and "
                "authentication."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/actuator/env", 200,
                '{"propertySources": [{"name": "applicationConfig", "properties": '
                '{"spring.datasource.password": {"value": "Pr0d_DB_2024!"}, '
                '"jwt.signing.secret": {"value": "s3cr3t-do-not-share"}}}]}',
                notes="Discovered via shadow-endpoint wordlist probe",
            ),
            confidence="HIGH",
            cvss_score=9.1,
        ),
        _f(
            title="Legacy API Version Still Active: /api/v1/payments",
            severity=Severity.MEDIUM,
            owasp_category=OWASPCategory.API9_INVENTORY,
            endpoint="/api/v1/payments",
            method="GET",
            description=(
                "/api/v1/payments still returns full card PANs (v2 returns masked card_last4). "
                "The legacy version was never decommissioned and bypasses the v2 data minimization fix."
            ),
            remediation=(
                "Decommission old API versions on a published deprecation timeline. "
                "If a legacy version must remain available for backward compatibility, "
                "ensure all security patches and data-minimization fixes are backported."
            ),
            evidence=Evidence.synthetic(
                "GET", f"{_DEMO_TARGET}/api/v1/payments", 200,
                '[{"id": 771, "card_number": "4111111111111111", "amount": 2599.00}]',
                notes="Current version path: /api/v2/payments (returns masked card_last4 only)",
            ),
            confidence="HIGH",
            cvss_score=5.3,
        ),
    ]


def generate_demo_result() -> ScanResult:
    """Build a complete ScanResult with synthetic findings and check timings."""
    findings = _build_findings()

    started = datetime(2026, 6, 15, 8, 30, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 6, 15, 8, 32, 47, tzinfo=timezone.utc)

    check_results = [
        CheckResult(name="bola", duration_seconds=24.1, finding_count=2),
        CheckResult(name="broken_auth", duration_seconds=18.7, finding_count=2),
        CheckResult(name="mass_assignment", duration_seconds=12.4, finding_count=2),
        CheckResult(name="rate_limit", duration_seconds=31.2, finding_count=1),
        CheckResult(name="bfla", duration_seconds=21.6, finding_count=2),
        CheckResult(name="ssrf", duration_seconds=15.9, finding_count=1),
        CheckResult(name="injection", duration_seconds=28.3, finding_count=1),
        CheckResult(name="misconfig", duration_seconds=9.8, finding_count=2),
        CheckResult(name="shadow_endpoints", duration_seconds=4.96, finding_count=2),
    ]

    return ScanResult(
        target=_DEMO_TARGET,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=(finished - started).total_seconds(),
        findings=findings,
        check_results=check_results,
        endpoints_scanned=14,
    )
