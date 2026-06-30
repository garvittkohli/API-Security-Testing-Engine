"""Abstract base class for all security checks."""


import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apisec.config import EndpointDef, ScanConfig
    from apisec.findings import Finding
    from apisec.http_client import APIClient
    from apisec.payload_engine import PayloadEngine

logger = logging.getLogger(__name__)


class BaseCheck(ABC):
    """Abstract base for all OWASP API security checks."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: "ScanConfig", payload_engine: "PayloadEngine") -> None:
        self.config = config
        self.pe = payload_engine
        self.logger = logging.getLogger(f"apisec.checks.{self.name}")

    @abstractmethod
    def run(self, client: "APIClient", endpoints: list["EndpointDef"]) -> list["Finding"]:
        """Execute the check and return a list of findings."""
        ...

    def _is_excluded(self, path: str) -> bool:
        return any(path.startswith(ex) for ex in self.config.excluded_paths)

    def _truncate(self, text: str, max_len: int = 500) -> str:
        return text[:max_len] + "..." if len(text) > max_len else text
