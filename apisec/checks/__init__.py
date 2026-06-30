"""Check registry — add new checks here."""

from apisec.checks.base import BaseCheck
from apisec.checks.bfla import BFLACheck
from apisec.checks.bola import BOLACheck
from apisec.checks.broken_auth import BrokenAuthCheck
from apisec.checks.injection import InjectionCheck
from apisec.checks.mass_assignment import MassAssignmentCheck
from apisec.checks.misconfig import MisconfigCheck
from apisec.checks.rate_limit import RateLimitCheck
from apisec.checks.shadow_endpoints import ShadowEndpointCheck
from apisec.checks.ssrf import SSRFCheck

CHECK_REGISTRY: dict[str, type[BaseCheck]] = {
    "bola": BOLACheck,
    "broken_auth": BrokenAuthCheck,
    "mass_assignment": MassAssignmentCheck,
    "rate_limit": RateLimitCheck,
    "bfla": BFLACheck,
    "ssrf": SSRFCheck,
    "injection": InjectionCheck,
    "misconfig": MisconfigCheck,
    "shadow_endpoints": ShadowEndpointCheck,
}

__all__ = ["BaseCheck", "CHECK_REGISTRY"]
