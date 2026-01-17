from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class ResourceConfig:
    """
    Appendix X input contract:
    Provider-agnostic normalized storage configuration.
    Missing/unknown values are represented explicitly as None.
    """
    resource_id: str
    provider: str
    resource_type: str

    public_access: Optional[bool] = None
    encryption_enabled: Optional[bool] = None
    logging_enabled: Optional[bool] = None

    # Simplified policy data required for permission analysis.
    # Keep it minimal and non-sensitive.
    policy_summary: Dict[str, Any] = field(default_factory=dict)

    # Non-sensitive context like region/account alias
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """
    Appendix X output contract.
    """
    finding_type: str  # fixed "misconfiguration"
    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_id: str
    evidence: Dict[str, Any]
    remediation: str
    timestamp_utc: Optional[str] = None

