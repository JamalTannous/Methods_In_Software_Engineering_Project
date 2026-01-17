from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Any, Dict

from .domain import ResourceConfig, Finding, Severity


class Rule(ABC):
    """
    Appendix X Rule interface.
    Must be stateless, deterministic, and return <= 1 Finding.
    """

    @abstractmethod
    def getRuleId(self) -> str: ...

    @abstractmethod
    def getDescription(self) -> str: ...

    @abstractmethod
    def getDefaultSeverity(self) -> Severity: ...

    @abstractmethod
    def evaluate(self, resource: ResourceConfig) -> Optional[Finding]: ...


def _mk_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    resource_id: str,
    evidence: Dict[str, Any],
    remediation: str,
) -> Finding:
    return Finding(
        finding_type="misconfiguration",
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        resource_id=resource_id,
        evidence=evidence,
        remediation=remediation,
    )


class PublicAccessRule(Rule):
    def getRuleId(self) -> str:
        return "RULE_PUBLIC_ACCESS"

    def getDescription(self) -> str:
        return "Detects publicly accessible storage resources."

    def getDefaultSeverity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, resource: ResourceConfig) -> Optional[Finding]:
        # Conservative: if unknown => no finding
        if resource.public_access is None:
            return None
        if resource.public_access is True:
            return _mk_finding(
                rule_id=self.getRuleId(),
                title="Public access enabled",
                description=(
                    "The storage resource appears to be publicly accessible, "
                    "which may expose data to unauthorised parties."
                ),
                severity=self.getDefaultSeverity(),
                resource_id=resource.resource_id,
                evidence={"public_access": True},
                remediation=(
                    "Disable public access and restrict permissions to trusted principals only."
                ),
            )
        return None


class EncryptionRule(Rule):
    def getRuleId(self) -> str:
        return "RULE_ENCRYPTION_MISSING"

    def getDescription(self) -> str:
        return "Detects missing or incorrectly configured encryption at rest."

    def getDefaultSeverity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, resource: ResourceConfig) -> Optional[Finding]:
        if resource.encryption_enabled is None:
            return None
        if resource.encryption_enabled is False:
            return _mk_finding(
                rule_id=self.getRuleId(),
                title="Encryption at rest disabled or missing",
                description=(
                    "The storage resource does not appear to have encryption at rest enabled."
                ),
                severity=self.getDefaultSeverity(),
                resource_id=resource.resource_id,
                evidence={"encryption_enabled": False},
                remediation=(
                    "Enable encryption at rest (e.g., SSE/KMS) and enforce it via bucket/container policies."
                ),
            )
        return None


class LoggingRule(Rule):
    def getRuleId(self) -> str:
        return "RULE_LOGGING_DISABLED"

    def getDescription(self) -> str:
        return "Detects disabled or missing access logging configuration."

    def getDefaultSeverity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(self, resource: ResourceConfig) -> Optional[Finding]:
        if resource.logging_enabled is None:
            return None
        if resource.logging_enabled is False:
            return _mk_finding(
                rule_id=self.getRuleId(),
                title="Access logging disabled",
                description=(
                    "Access logging appears to be disabled, reducing visibility for investigations and audits."
                ),
                severity=self.getDefaultSeverity(),
                resource_id=resource.resource_id,
                evidence={"logging_enabled": False},
                remediation=(
                    "Enable access logging and ensure logs are retained and protected from tampering."
                ),
            )
        return None


class ExcessivePermissionsRule(Rule):
    """
    Minimal, provider-agnostic policy heuristic based on policy_summary.

    Expected policy_summary keys (examples):
      - "public_principals": bool        (True if '*' / anonymous principals exist)
      - "wildcard_actions": bool         (True if actions include '*', 's3:*', etc.)
      - "wildcard_resources": bool       (True if resources include '*')
      - "allow_statements": int          (count of allow statements)
    """

    def getRuleId(self) -> str:
        return "RULE_EXCESSIVE_PERMISSIONS"

    def getDescription(self) -> str:
        return "Detects overly permissive IAM/bucket/container policies."

    def getDefaultSeverity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, resource: ResourceConfig) -> Optional[Finding]:
        ps = resource.policy_summary or {}

        # Conservative: if nothing to evaluate => no finding
        if not isinstance(ps, dict) or len(ps) == 0:
            return None

        public_principals = ps.get("public_principals")
        wildcard_actions = ps.get("wildcard_actions")
        wildcard_resources = ps.get("wildcard_resources")

        # If any required signal is unknown => do not flag (avoid false positives)
        # (You can relax this later if you explicitly want "fail closed".)
        required = [public_principals, wildcard_actions, wildcard_resources]
        if any(v is None for v in required):
            return None

        is_excessive = bool(public_principals) or (bool(wildcard_actions) and bool(wildcard_resources))
        if not is_excessive:
            return None

        evidence = {
            "public_principals": bool(public_principals),
            "wildcard_actions": bool(wildcard_actions),
            "wildcard_resources": bool(wildcard_resources),
        }

        return _mk_finding(
            rule_id=self.getRuleId(),
            title="Overly permissive access policy",
            description=(
                "The access policy appears to grant overly broad permissions (e.g., public principals "
                "or wildcard actions/resources), increasing the risk of unauthorised access."
            ),
            severity=self.getDefaultSeverity(),
            resource_id=resource.resource_id,
            evidence=evidence,
            remediation=(
                "Restrict principals to known identities, avoid wildcard actions/resources, "
                "and apply least-privilege permissions."
            ),
        )

