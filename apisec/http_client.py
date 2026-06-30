"""Rate-limited, auth-aware HTTP client for the scan engine."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import requests
from requests.exceptions import ConnectionError, RequestException, Timeout

logger = logging.getLogger(__name__)


class APIClient:
    def __init__(
        self,
        base_url: str,
        auth_headers: dict[str, str] | None = None,
        custom_headers: dict[str, str] | None = None,
        rate_limit_delay: float = 0.5,
        timeout: int = 10,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_headers = auth_headers or {}
        self.custom_headers = custom_headers or {}
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self._last_request_ts: float = 0.0

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "APISecurityEngine/1.0 (Authorized Security Testing)",
                "Accept": "application/json, text/plain, */*",
            }
        )
        self.session.headers.update(self.auth_headers)
        self.session.headers.update(self.custom_headers)

    # ------------------------------------------------------------------
    # Core request machinery
    # ------------------------------------------------------------------

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_ts = time.monotonic()

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        separator = "" if path.startswith("/") else "/"
        return f"{self.base_url}{separator}{path}"

    def request(
        self,
        method: str,
        path: str,
        override_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        self._throttle()
        url = self._build_url(path)

        merged_headers = dict(self.session.headers)
        if override_headers:
            merged_headers.update(override_headers)

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=merged_headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
                **kwargs,
            )
            logger.debug("%s %s -> %d", method.upper(), url, response.status_code)
            return response
        except Timeout:
            logger.warning("Timeout: %s %s", method.upper(), url)
            return None
        except ConnectionError:
            logger.warning("Connection error: %s %s", method.upper(), url)
            return None
        except RequestException as exc:
            logger.warning("Request failed: %s %s — %s", method.upper(), url, exc)
            return None

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def get(self, path: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("DELETE", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("PATCH", path, **kwargs)

    # ------------------------------------------------------------------
    # Auth-stripped variant used by authentication checks
    # ------------------------------------------------------------------

    def unauthenticated_request(
        self, method: str, path: str, **kwargs: Any
    ) -> Optional[requests.Response]:
        """Issue the same request without any auth headers."""
        self._throttle()
        url = self._build_url(path)

        bare_headers = {
            "User-Agent": "APISecurityEngine/1.0 (Authorized Security Testing)",
            "Accept": "application/json, text/plain, */*",
        }
        bare_headers.update(self.custom_headers)

        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=bare_headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
                **kwargs,
            )
            logger.debug("(unauthenticated) %s %s -> %d", method.upper(), url, response.status_code)
            return response
        except (Timeout, ConnectionError, RequestException) as exc:
            logger.warning("Unauthenticated request failed: %s — %s", url, exc)
            return None

    # ------------------------------------------------------------------
    # Burst helper used by rate limit check
    # ------------------------------------------------------------------

    def burst_requests(
        self, method: str, path: str, count: int = 20, delay: float = 0.0
    ) -> list[Optional[requests.Response]]:
        """Send <count> rapid requests without the normal rate limit delay."""
        url = self._build_url(path)
        results: list[Optional[requests.Response]] = []
        for _ in range(count):
            try:
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    verify=self.verify_ssl,
                )
                results.append(resp)
            except (Timeout, ConnectionError, RequestException):
                results.append(None)
            if delay:
                time.sleep(delay)
        return results

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def safe_body_snippet(self, response: requests.Response, max_len: int = 500) -> str:
        try:
            text = response.text
            return text[:max_len] + ("..." if len(text) > max_len else "")
        except Exception:
            return "<unreadable>"

    def response_headers_dict(self, response: requests.Response) -> dict[str, str]:
        return dict(response.headers)
