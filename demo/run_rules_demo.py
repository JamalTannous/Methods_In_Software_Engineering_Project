from misconfig_detector.engine import RuleEngine
from misconfig_detector.rules import (
    PublicAccessRule,
    EncryptionRule,
    LoggingRule,
    ExcessivePermissionsRule,
)
from misconfig_detector.domain import ResourceConfig


def main():
    # Initialize rule engine
    engine = RuleEngine()

    # Register rules in deterministic order
    engine.registerRule(PublicAccessRule())
    engine.registerRule(EncryptionRule())
    engine.registerRule(LoggingRule())
    engine.registerRule(ExcessivePermissionsRule())

    # Synthetic normalized resources (as per Appendix X testability section)
    resources = [
        ResourceConfig(
            resource_id="acc1:bucket-public",
            provider="AWS",
            resource_type="bucket",
            public_access=True,
            encryption_enabled=False,
            logging_enabled=False,
            policy_summary={
                "public_principals": True,
                "wildcard_actions": False,
                "wildcard_resources": False,
            },
        ),
        ResourceConfig(
            resource_id="acc1:bucket-private",
            provider="AWS",
            resource_type="bucket",
            public_access=False,
            encryption_enabled=True,
            logging_enabled=True,
            policy_summary={
                "public_principals": False,
                "wildcard_actions": False,
                "wildcard_resources": False,
            },
        ),
    ]

    # Run evaluation
    findings = engine.evaluateAll(resources)

    # Print results
    print("=== Misconfiguration Findings ===")
    if not findings:
        print("No misconfigurations detected.")
        return

    for f in findings:
        print(f"- Resource: {f.resource_id}")
        print(f"  Rule ID: {f.rule_id}")
        print(f"  Severity: {f.severity}")
        print(f"  Description: {f.description}")
        print(f"  Remediation: {f.remediation}")
        print(f"  Evidence: {f.evidence}")
        print("")


if __name__ == "__main__":
    main()

