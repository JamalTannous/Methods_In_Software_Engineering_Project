import pytest

from misconfig_detector.domain import ResourceConfig, Severity
from misconfig_detector.rules import (
    PublicAccessRule,
    EncryptionRule,
    ExcessivePermissionsRule,
    LoggingRule,
)


def test_public_access_detected():
    r = ResourceConfig(
        resource_id="acc1:bucketA",
        provider="AWS",
        resource_type="bucket",
        public_access=True,
    )
    f = PublicAccessRule().evaluate(r)
    assert f is not None
    assert f.rule_id == "RULE_PUBLIC_ACCESS"
    assert f.severity == Severity.HIGH


def test_public_access_unknown_no_finding():
    r = ResourceConfig(
        resource_id="acc1:bucketA",
        provider="AWS",
        resource_type="bucket",
        public_access=None,
    )
    assert PublicAccessRule().evaluate(r) is None


def test_encryption_missing_detected():
    r = ResourceConfig(
        resource_id="acc1:bucketB",
        provider="AWS",
        resource_type="bucket",
        encryption_enabled=False,
    )
    f = EncryptionRule().evaluate(r)
    assert f is not None
    assert f.rule_id == "RULE_ENCRYPTION_MISSING"
    assert f.severity == Severity.HIGH


def test_excessive_permissions_detected_public_principal():
    r = ResourceConfig(
        resource_id="acc1:bucketC",
        provider="AWS",
        resource_type="bucket",
        policy_summary={
            "public_principals": True,
            "wildcard_actions": False,
            "wildcard_resources": False,
        },
    )
    f = ExcessivePermissionsRule().evaluate(r)
    assert f is not None
    assert f.rule_id == "RULE_EXCESSIVE_PERMISSIONS"
    assert f.severity == Severity.HIGH


def test_logging_disabled_detected():
    r = ResourceConfig(
        resource_id="acc1:bucketD",
        provider="AWS",
        resource_type="bucket",
        logging_enabled=False,
    )
    f = LoggingRule().evaluate(r)
    assert f is not None
    assert f.rule_id == "RULE_LOGGING_DISABLED"
    assert f.severity == Severity.MEDIUM


def test_missing_fields_conservative_no_finding():
    # Missing policy_summary signals => should not flag
    r = ResourceConfig(
        resource_id="acc1:bucketE",
        provider="AWS",
        resource_type="bucket",
        policy_summary={"public_principals": None},
    )
    assert ExcessivePermissionsRule().evaluate(r) is None

