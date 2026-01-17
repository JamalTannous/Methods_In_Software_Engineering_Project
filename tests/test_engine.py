from misconfig_detector.domain import ResourceConfig
from misconfig_detector.engine import RuleEngine
from misconfig_detector.rules import PublicAccessRule, EncryptionRule, LoggingRule


class ExplodingRule:
    def getRuleId(self): return "RULE_EXPLODE"
    def getDescription(self): return "Always throws."
    def getDefaultSeverity(self): return None
    def evaluate(self, resource):  # noqa
        raise RuntimeError("boom")


def test_engine_isolates_rule_failures():
    eng = RuleEngine()
    eng.registerRule(ExplodingRule())      # should be isolated
    eng.registerRule(PublicAccessRule())   # should still run

    r = ResourceConfig(
        resource_id="acc1:bucketA",
        provider="AWS",
        resource_type="bucket",
        public_access=True,
    )
    findings = eng.evaluateResource(r)
    assert any(f.rule_id == "RULE_PUBLIC_ACCESS" for f in findings)


def test_engine_empty_inputs():
    eng = RuleEngine()
    assert eng.evaluateAll([]) == []


def test_engine_deterministic_order_registration():
    eng = RuleEngine()
    eng.registerRule(LoggingRule())
    eng.registerRule(EncryptionRule())

    r = ResourceConfig(
        resource_id="acc1:bucketX",
        provider="AWS",
        resource_type="bucket",
        logging_enabled=False,
        encryption_enabled=False,
    )
    findings = eng.evaluateResource(r)
    assert [f.rule_id for f in findings] == [
        "RULE_LOGGING_DISABLED",
        "RULE_ENCRYPTION_MISSING",
    ]

